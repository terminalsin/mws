//! Virtual MFA devices: real TOTP (RFC 6238) seeds and QR codes, codes
//! checked on EnableMFADevice/ResyncMFADevice, and by STS for MFA-protected
//! calls.

use aws_lc_rs::hmac;
use chrono::Utc;
use mws_core::{RequestContext, ServiceError};
use rand::RngCore;

use crate::common::*;
use crate::generated::{errors, types};
use crate::ops::users::Subject;
use crate::state::{MfaDevice, State};
use crate::{wire, Iam};

const STEP_SECONDS: i64 = 30;
/// How many 30-second steps either side of now a code may come from.
const ENABLE_WINDOW: i64 = 10;
const RESYNC_WINDOW: i64 = 120;
const MAX_DEVICES_PER_USER: usize = 8;

/// RFC 4648 base32 without padding, as AWS returns the seed.
fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    for chunk in bytes.chunks(5) {
        let mut buf = [0u8; 5];
        buf[..chunk.len()].copy_from_slice(chunk);
        let n = u64::from_be_bytes([0, 0, 0, buf[0], buf[1], buf[2], buf[3], buf[4]]);
        let chars = (chunk.len() * 8).div_ceil(5);
        for i in 0..chars {
            out.push(ALPHABET[((n >> (35 - i * 5)) & 31) as usize] as char);
        }
    }
    out
}

/// The 6-digit TOTP code for a 30-second time step.
pub(crate) fn totp(seed: &[u8], step: i64) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, seed);
    let tag = hmac::sign(&key, &step.to_be_bytes());
    let h = tag.as_ref();
    let off = (h[h.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    format!("{:06}", bin % 1_000_000)
}

fn now_step() -> i64 {
    Utc::now().timestamp() / STEP_SECONDS
}

/// The time step at which `code1` then `code2` were generated, if any
/// within `window` steps of now.
fn consecutive(seed: &[u8], code1: &str, code2: &str, window: i64) -> Option<i64> {
    let now = now_step();
    (now - window..=now + 1).find(|t| totp(seed, *t) == code1 && totp(seed, t + 1) == code2)
}

fn invalid_code(serial: &str) -> ServiceError {
    errors::invalid_authentication_code(format!("Authentication code for device {serial} is not valid."))
}

fn no_such_device(serial: &str) -> ServiceError {
    errors::no_such_entity(format!("MFA Device with serial number {serial} does not exist."))
}

/// A minimal PNG (8-bit greyscale, stored deflate blocks) of a QR code.
fn qr_png(text: &str) -> Vec<u8> {
    let Ok(code) = qrcode::QrCode::new(text.as_bytes()) else { return Vec::new() };
    let width = code.width();
    let colors = code.to_colors();
    const SCALE: usize = 4;
    const BORDER: usize = 4;
    let size = (width + 2 * BORDER) * SCALE;
    let mut raw = Vec::with_capacity((size + 1) * size);
    for y in 0..size {
        raw.push(0); // filter: none
        for x in 0..size {
            let (mx, my) = (x / SCALE, y / SCALE);
            let dark = mx >= BORDER
                && my >= BORDER
                && mx < width + BORDER
                && my < width + BORDER
                && colors[(my - BORDER) * width + (mx - BORDER)] == qrcode::Color::Dark;
            raw.push(if dark { 0 } else { 255 });
        }
    }
    // zlib stream of stored blocks.
    let mut z = vec![0x78, 0x01];
    let blocks: Vec<&[u8]> = raw.chunks(65535).collect();
    for (i, b) in blocks.iter().enumerate() {
        z.push(u8::from(i == blocks.len() - 1));
        let len = b.len() as u16;
        z.extend(len.to_le_bytes());
        z.extend((!len).to_le_bytes());
        z.extend_from_slice(b);
    }
    let (mut a, mut b) = (1u32, 0u32);
    for byte in &raw {
        a = (a + *byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    z.extend(((b << 16) | a).to_be_bytes());

    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xffff_ffffu32;
        for byte in data {
            crc ^= *byte as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
            }
        }
        !crc
    }
    let chunk = |out: &mut Vec<u8>, ty: &[u8], data: &[u8]| {
        out.extend((data.len() as u32).to_be_bytes());
        let mut body = ty.to_vec();
        body.extend_from_slice(data);
        out.extend_from_slice(&body);
        out.extend(crc32(&body).to_be_bytes());
    };
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut ihdr = (size as u32).to_be_bytes().to_vec();
    ihdr.extend((size as u32).to_be_bytes());
    ihdr.extend([8, 0, 0, 0, 0]); // 8-bit greyscale
    chunk(&mut png, b"IHDR", &ihdr);
    chunk(&mut png, b"IDAT", &z);
    chunk(&mut png, b"IEND", &[]);
    png
}

impl State {
    fn device(&self, serial: &str) -> Result<&MfaDevice, ServiceError> {
        self.mfa_devices.get(serial).ok_or_else(|| no_such_device(serial))
    }
    fn device_mut(&mut self, serial: &str) -> Result<&mut MfaDevice, ServiceError> {
        self.mfa_devices.get_mut(serial).ok_or_else(|| no_such_device(serial))
    }
}

impl Iam {
    /// Check a one-time code from an enabled MFA device (STS calls this for
    /// `SerialNumber`/`TokenCode`). A code is accepted once.
    pub fn verify_mfa_code(&self, serial: &str, code: &str) -> bool {
        let mut state = self.write_for_arn(serial);
        let Some(device) = state.mfa_devices.get_mut(serial).filter(|d| d.enabled.is_some()) else { return false };
        let now = now_step();
        let hit = (now - 1..=now + 1).find(|t| totp(&device.seed, *t) == code && device.last_step < Some(*t));
        match hit {
            Some(t) => {
                device.last_step = Some(t);
                true
            }
            None => false,
        }
    }

    fn device_wire(&self, state: &State, d: &MfaDevice, with_seed: bool) -> types::VirtualMFADevice {
        let label = state.account_aliases.first().cloned().unwrap_or_else(|| self.account_id().to_string());
        let seed = base32(&d.seed);
        let uri = format!(
            "otpauth://totp/Amazon%20Web%20Services:{}@{label}?secret={seed}&issuer=Amazon%20Web%20Services",
            d.name
        );
        types::VirtualMFADevice {
            serial_number: d.serial.clone(),
            base32_string_seed: with_seed.then(|| seed.clone().into_bytes()),
            qr_code_png: with_seed.then(|| qr_png(&uri)),
            user: d.user.as_deref().and_then(|u| state.user(u)).map(wire::user_summary),
            enable_date: d.enabled,
            tags: tags_to_wire(&d.tags),
        }
    }

    pub fn create_virtual_mfa_device(
        &self,
        ctx: &RequestContext,
        input: types::CreateVirtualMFADeviceRequest,
    ) -> Result<types::CreateVirtualMFADeviceResponse, ServiceError> {
        let path = input.path.unwrap_or_else(|| "/".into());
        let serial = self.arn(&format!("mfa{path}{}", input.virtual_mfa_device_name));
        let tags = tags_from_wire(input.tags)?;
        self.authorize_with(ctx, "CreateVirtualMFADevice", &serial, request_tag_context(&tags))?;
        self.authorize_tagging(ctx, "TagMFADevice", &serial, &tags)?;
        let mut state = self.write();
        if state.mfa_devices.values().any(|d| d.name.eq_ignore_ascii_case(&input.virtual_mfa_device_name)) {
            return Err(errors::entity_already_exists("MFADevice entity at the same path and name already exists."));
        }
        let mut seed = vec![0u8; 40];
        rand::thread_rng().fill_bytes(&mut seed);
        let device = MfaDevice {
            serial: serial.clone(),
            path,
            name: input.virtual_mfa_device_name,
            seed,
            user: None,
            enabled: None,
            tags,
            last_step: None,
        };
        let out = self.device_wire(&state, &device, true);
        state.mfa_devices.insert(serial, device);
        Ok(types::CreateVirtualMFADeviceResponse { virtual_mfa_device: out })
    }

    pub fn list_virtual_mfa_devices(
        &self,
        ctx: &RequestContext,
        input: types::ListVirtualMFADevicesRequest,
    ) -> Result<types::ListVirtualMFADevicesResponse, ServiceError> {
        self.authorize(ctx, "ListVirtualMFADevices", "*")?;
        let state = self.read();
        let wanted = input.assignment_status.as_deref().unwrap_or("Any");
        let all: Vec<types::VirtualMFADevice> = state
            .mfa_devices
            .values()
            .filter(|d| match wanted {
                "Assigned" => d.user.is_some(),
                "Unassigned" => d.user.is_none(),
                _ => true,
            })
            .map(|d| self.device_wire(&state, d, false))
            .collect();
        let (page, truncated, marker) =
            paginate(&all, |d| d.serial_number.clone(), input.marker.as_deref(), input.max_items)?;
        Ok(types::ListVirtualMFADevicesResponse { virtual_mfa_devices: page, is_truncated: truncated, marker })
    }

    pub fn delete_virtual_mfa_device(
        &self,
        ctx: &RequestContext,
        input: types::DeleteVirtualMFADeviceRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "DeleteVirtualMFADevice", &input.serial_number)?;
        let mut state = self.write();
        if state.device(&input.serial_number)?.user.is_some() {
            return Err(errors::delete_conflict("MFA VirtualDevice in use. Must deactivate first."));
        }
        state.mfa_devices.remove(&input.serial_number);
        Ok(())
    }

    pub fn enable_mfa_device(
        &self,
        ctx: &RequestContext,
        input: types::EnableMFADeviceRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "EnableMFADevice", &self.user_arn_or_default(&input.user_name))?;
        let mut state = self.write();
        let user_key = state.user(&input.user_name).ok_or_else(|| no_such_user(&input.user_name))?.name.to_lowercase();
        let in_use = state.mfa_devices.values().filter(|d| d.user.as_deref() == Some(user_key.as_str())).count();
        let device = state.device_mut(&input.serial_number)?;
        if device.user.is_some() {
            return Err(errors::entity_already_exists("MFA Device is already in use."));
        }
        if in_use >= MAX_DEVICES_PER_USER {
            return Err(errors::limit_exceeded("Cannot exceed quota for MFADevicesPerUser: 8"));
        }
        let step = consecutive(&device.seed, &input.authentication_code1, &input.authentication_code2, ENABLE_WINDOW)
            .ok_or_else(|| invalid_code(&input.serial_number))?;
        device.user = Some(user_key);
        device.enabled = Some(ctx.received_at);
        device.last_step = Some(step + 1);
        Ok(())
    }

    pub fn resync_mfa_device(
        &self,
        ctx: &RequestContext,
        input: types::ResyncMFADeviceRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "ResyncMFADevice", &self.user_arn_or_default(&input.user_name))?;
        let mut state = self.write();
        let user_key = state.user(&input.user_name).ok_or_else(|| no_such_user(&input.user_name))?.name.to_lowercase();
        let device = state.device_mut(&input.serial_number)?;
        if device.user.as_deref() != Some(user_key.as_str()) {
            return Err(no_such_device(&input.serial_number));
        }
        let step = consecutive(&device.seed, &input.authentication_code1, &input.authentication_code2, RESYNC_WINDOW)
            .ok_or_else(|| invalid_code(&input.serial_number))?;
        device.last_step = Some(step + 1);
        Ok(())
    }

    pub fn deactivate_mfa_device(
        &self,
        ctx: &RequestContext,
        input: types::DeactivateMFADeviceRequest,
    ) -> Result<(), ServiceError> {
        let Subject::User(name) = self.subject(ctx, input.user_name)? else {
            return Err(no_such_device(&input.serial_number));
        };
        self.authorize(ctx, "DeactivateMFADevice", &self.user_arn_or_default(&name))?;
        let mut state = self.write();
        state.user(&name).ok_or_else(|| no_such_user(&name))?;
        let device = state.device_mut(&input.serial_number)?;
        if device.user.as_deref() != Some(name.to_lowercase().as_str()) {
            return Err(no_such_device(&input.serial_number));
        }
        device.user = None;
        device.enabled = None;
        device.last_step = None;
        Ok(())
    }

    pub fn list_mfa_devices(
        &self,
        ctx: &RequestContext,
        input: types::ListMFADevicesRequest,
    ) -> Result<types::ListMFADevicesResponse, ServiceError> {
        let subject = self.subject(ctx, input.user_name)?;
        let user_key = match &subject {
            Subject::User(n) => {
                self.authorize(ctx, "ListMFADevices", &self.user_arn_or_default(n))?;
                Some(n.to_lowercase())
            }
            Subject::Root => {
                self.authorize(ctx, "ListMFADevices", &ctx.caller.arn)?;
                None
            }
        };
        let state = self.read();
        if let Some(u) = &user_key {
            state.user(u).ok_or_else(|| no_such_user(u))?;
        }
        let all: Vec<types::MFADevice> = state
            .mfa_devices
            .values()
            .filter(|d| user_key.is_some() && d.user == user_key)
            .map(|d| types::MFADevice {
                user_name: state
                    .user(d.user.as_deref().unwrap_or_default())
                    .map(|u| u.name.clone())
                    .unwrap_or_default(),
                serial_number: d.serial.clone(),
                enable_date: d.enabled.unwrap_or_default(),
            })
            .collect();
        let (page, truncated, marker) =
            paginate(&all, |d| d.serial_number.clone(), input.marker.as_deref(), input.max_items)?;
        Ok(types::ListMFADevicesResponse { mfa_devices: page, is_truncated: truncated, marker })
    }

    pub fn get_mfa_device(
        &self,
        ctx: &RequestContext,
        input: types::GetMFADeviceRequest,
    ) -> Result<types::GetMFADeviceResponse, ServiceError> {
        self.authorize(ctx, "GetMFADevice", &input.serial_number)?;
        let state = self.read();
        let d = state.device(&input.serial_number)?;
        let owner = d.user.as_deref().and_then(|u| state.user(u)).map(|u| u.name.clone());
        if let Some(want) = &input.user_name {
            if owner.as_deref().map(str::to_lowercase) != Some(want.to_lowercase()) {
                return Err(no_such_device(&input.serial_number));
            }
        }
        Ok(types::GetMFADeviceResponse {
            user_name: owner,
            serial_number: d.serial.clone(),
            enable_date: d.enabled,
            certifications: None,
        })
    }

    pub fn tag_mfa_device(&self, ctx: &RequestContext, input: types::TagMFADeviceRequest) -> Result<(), ServiceError> {
        let tags = tags_from_wire(Some(input.tags))?;
        self.authorize_with(ctx, "TagMFADevice", &input.serial_number, request_tag_context(&tags))?;
        let mut state = self.write();
        merge_tags(&mut state.device_mut(&input.serial_number)?.tags, tags, "TagsPerMFADevice")
    }

    pub fn untag_mfa_device(
        &self,
        ctx: &RequestContext,
        input: types::UntagMFADeviceRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "UntagMFADevice", &input.serial_number)?;
        let mut state = self.write();
        remove_tags(&mut state.device_mut(&input.serial_number)?.tags, &input.tag_keys);
        Ok(())
    }

    pub fn list_mfa_device_tags(
        &self,
        ctx: &RequestContext,
        input: types::ListMFADeviceTagsRequest,
    ) -> Result<types::ListMFADeviceTagsResponse, ServiceError> {
        self.authorize(ctx, "ListMFADeviceTags", &input.serial_number)?;
        let state = self.read();
        let tags = tags_list(&state.device(&input.serial_number)?.tags);
        let (page, truncated, marker) = paginate(&tags, |t| t.key.clone(), input.marker.as_deref(), input.max_items)?;
        Ok(types::ListMFADeviceTagsResponse { tags: page, is_truncated: truncated, marker })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_matches_rfc6238_vectors() {
        // RFC 6238 Appendix B, SHA-1 seed "12345678901234567890", last 6 digits.
        let seed = b"12345678901234567890";
        assert_eq!(totp(seed, 59 / 30), "287082");
        assert_eq!(totp(seed, 1111111109 / 30), "081804");
        assert_eq!(totp(seed, 2000000000 / 30), "279037");
    }

    #[test]
    fn base32_matches_rfc4648() {
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32(b"fooba"), "MZXW6YTB");
    }

    #[test]
    fn qr_png_has_a_png_signature() {
        assert!(qr_png("otpauth://totp/x?secret=ABC").starts_with(b"\x89PNG"));
    }
}
