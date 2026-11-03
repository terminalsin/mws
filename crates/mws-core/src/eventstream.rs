//! The `application/vnd.amazon.eventstream` framing used by event stream
//! responses: each message is a prelude (total length, headers length,
//! prelude CRC32), string headers, the payload and a message CRC32.

fn crc32(data: &[u8], mut crc: u32) -> u32 {
    crc = !crc;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// One message with string-valued headers.
pub fn event_message(headers: &[(&str, &str)], payload: &[u8]) -> Vec<u8> {
    let mut h = Vec::new();
    for (name, value) in headers {
        h.push(name.len() as u8);
        h.extend_from_slice(name.as_bytes());
        h.push(7); // string
        h.extend_from_slice(&(value.len() as u16).to_be_bytes());
        h.extend_from_slice(value.as_bytes());
    }
    let total = 12 + h.len() + payload.len() + 4;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(total as u32).to_be_bytes());
    out.extend_from_slice(&(h.len() as u32).to_be_bytes());
    let prelude_crc = crc32(&out, 0);
    out.extend_from_slice(&prelude_crc.to_be_bytes());
    out.extend_from_slice(&h);
    out.extend_from_slice(payload);
    let message_crc = crc32(&out, 0);
    out.extend_from_slice(&message_crc.to_be_bytes());
    out
}

/// An `event` message of type `event_type`.
pub fn event(event_type: &str, content_type: Option<&str>, payload: &[u8]) -> Vec<u8> {
    let mut headers = vec![(":message-type", "event"), (":event-type", event_type)];
    if let Some(ct) = content_type {
        headers.push((":content-type", ct));
    }
    event_message(&headers, payload)
}

/// An `exception` message: a modeled error carried inside the stream.
pub fn exception(exception_type: &str, content_type: &str, payload: &[u8]) -> Vec<u8> {
    event_message(
        &[(":message-type", "exception"), (":exception-type", exception_type), (":content-type", content_type)],
        payload,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_check_value() {
        assert_eq!(crc32(b"123456789", 0), 0xCBF4_3926);
    }

    #[test]
    fn framing() {
        let m = event("End", None, b"");
        let total = u32::from_be_bytes(m[0..4].try_into().unwrap()) as usize;
        assert_eq!(total, m.len());
        let headers_len = u32::from_be_bytes(m[4..8].try_into().unwrap()) as usize;
        assert_eq!(12 + headers_len + 4, m.len());
        assert_eq!(u32::from_be_bytes(m[8..12].try_into().unwrap()), crc32(&m[0..8], 0));
        let n = m.len();
        assert_eq!(u32::from_be_bytes(m[n - 4..].try_into().unwrap()), crc32(&m[..n - 4], 0));
    }
}
