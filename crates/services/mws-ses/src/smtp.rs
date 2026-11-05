//! A local SMTP listener. Mail from a client that authenticates with SES
//! SMTP credentials (an IAM access key id and the password SES derives from
//! its secret) is a submission, sent as `SendRawEmail`; mail from a client
//! that does not authenticate is inbound mail, delivered to the receipt
//! rules of the account hosting each recipient.

use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use crate::receive::{Inbound, MAX_MESSAGE};
use crate::send::hosted_in;
use crate::Ses;

/// Regions an SMTP password may have been derived for.
const REGIONS: &[&str] = &[
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "af-south-1",
    "ap-south-1",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-northeast-3",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-southeast-3",
    "ca-central-1",
    "eu-central-1",
    "eu-central-2",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-north-1",
    "eu-south-1",
    "il-central-1",
    "me-south-1",
    "sa-east-1",
    "us-gov-west-1",
];

/// The SES SMTP password for an IAM secret access key in `region`.
pub fn smtp_password(secret_access_key: &str, region: &str) -> String {
    fn sign(key: &[u8], msg: &str) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key");
        mac.update(msg.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }
    let mut sig = sign(format!("AWS4{secret_access_key}").as_bytes(), "11111111");
    for part in [region, "ses", "aws4_request", "SendRawEmail"] {
        sig = sign(&sig, part);
    }
    let mut out = vec![0x04];
    out.extend(sig);
    base64::engine::general_purpose::STANDARD.encode(out)
}

/// Serve SMTP on `listener` until the task is dropped.
pub async fn serve_smtp(ses: Ses, listener: TcpListener) {
    loop {
        let Ok((stream, peer)) = listener.accept().await else { continue };
        let ses = ses.clone();
        tokio::spawn(async move {
            if let Err(e) = session(ses, stream, peer.ip().to_string()).await {
                tracing::debug!("SES SMTP session ended: {e}");
            }
        });
    }
}

struct Login {
    ctx: mws_core::RequestContext,
}

fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

/// The address inside `MAIL FROM:<a>` / `RCPT TO:<a>`.
fn path_arg(rest: &str) -> String {
    let rest = rest.trim();
    let inner = match (rest.find('<'), rest.find('>')) {
        (Some(a), Some(b)) if b > a => &rest[a + 1..b],
        _ => rest.split_whitespace().next().unwrap_or_default(),
    };
    inner.to_string()
}

impl Ses {
    /// Check SES SMTP credentials; the context to send as on success.
    fn smtp_login(&self, user: &str, password: &str) -> Option<Login> {
        let stores = self.inner.credentials.get()?;
        let now = chrono::Utc::now();
        let cred = stores.iter().find_map(|s| s.resolve(user, None, now).ok().flatten())?;
        let preferred = self.inner.template.lock().ok()?.as_ref().map(|(c, _)| c.region.clone());
        let region = preferred
            .iter()
            .map(String::as_str)
            .chain(REGIONS.iter().copied())
            .find(|r| smtp_password(&cred.secret_access_key, r) == password)?
            .to_string();
        let mut ctx = self.background_context(&cred.caller.account_id, &region);
        ctx.caller = cred.caller;
        Some(Login { ctx })
    }
}

async fn ask<R, W>(read: &mut R, write: &mut W, prompt: &str) -> std::io::Result<String>
where
    R: tokio::io::AsyncBufRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    write.write_all(format!("334 {prompt}\r\n").as_bytes()).await?;
    let mut l = Vec::new();
    read.read_until(b'\n', &mut l).await?;
    Ok(String::from_utf8_lossy(&l).trim().to_string())
}

async fn session(ses: Ses, stream: TcpStream, peer: String) -> std::io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    let host = "email-smtp.amazonaws.com";
    write.write_all(format!("220 {host} ESMTP SimpleEmailService-mws\r\n").as_bytes()).await?;
    let mut login: Option<Login> = None;
    let mut mail_from: Option<String> = None;
    let mut recipients: Vec<String> = Vec::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        if read.read_until(b'\n', &mut line).await? == 0 {
            return Ok(());
        }
        let text = String::from_utf8_lossy(&line).trim_end().to_string();
        let (verb, rest) = text.split_once(' ').unwrap_or((&text, ""));
        let reply: String = match verb.to_ascii_uppercase().as_str() {
            "EHLO" => format!("250-{host}\r\n250-8BITMIME\r\n250-SIZE {MAX_MESSAGE}\r\n250-AUTH PLAIN LOGIN\r\n250 Ok"),
            "HELO" => format!("250 {host}"),
            "NOOP" => "250 Ok".into(),
            "RSET" => {
                mail_from = None;
                recipients.clear();
                "250 Ok".into()
            }
            "QUIT" => {
                write.write_all(b"221 Bye\r\n").await?;
                return Ok(());
            }
            "VRFY" => "252 Cannot VRFY user".into(),
            "STARTTLS" => "454 4.7.0 TLS not available".into(),
            "AUTH" => {
                let mut parts = rest.split_whitespace();
                let mech = parts.next().unwrap_or_default().to_ascii_uppercase();
                let initial = parts.next().map(str::to_string);
                let creds = match mech.as_str() {
                    "PLAIN" => {
                        let data = match initial {
                            Some(d) => d,
                            None => ask(&mut read, &mut write, "").await?,
                        };
                        let decoded = b64(&data);
                        let mut fields = decoded.split('\0').skip(1);
                        Some((
                            fields.next().unwrap_or_default().to_string(),
                            fields.next().unwrap_or_default().to_string(),
                        ))
                    }
                    "LOGIN" => {
                        let user = match initial {
                            Some(u) => b64(&u),
                            None => b64(&ask(&mut read, &mut write, "VXNlcm5hbWU6").await?),
                        };
                        let pass = b64(&ask(&mut read, &mut write, "UGFzc3dvcmQ6").await?);
                        Some((user, pass))
                    }
                    _ => None,
                };
                match creds {
                    None => "504 5.5.4 Unrecognized authentication type".into(),
                    Some((user, pass)) => match ses.smtp_login(&user, &pass) {
                        Some(l) => {
                            login = Some(l);
                            "235 Authentication successful.".into()
                        }
                        None => "535 Authentication Credentials Invalid".into(),
                    },
                }
            }
            "MAIL" => {
                let arg = rest.trim_start();
                if !arg.to_ascii_uppercase().starts_with("FROM:") {
                    "501 5.5.4 Syntax: MAIL FROM:<address>".into()
                } else {
                    mail_from = Some(path_arg(&arg[5..]));
                    recipients.clear();
                    "250 Ok".into()
                }
            }
            "RCPT" => {
                let arg = rest.trim_start();
                if mail_from.is_none() {
                    "503 5.5.1 Error: need MAIL command".into()
                } else if !arg.to_ascii_uppercase().starts_with("TO:") {
                    "501 5.5.4 Syntax: RCPT TO:<address>".into()
                } else {
                    let to = path_arg(&arg[3..]);
                    if login.is_some() {
                        if recipients.len() >= 50 {
                            "452 4.5.3 Too many recipients".into()
                        } else {
                            recipients.push(to);
                            "250 Ok".into()
                        }
                    } else if hosted_in(&ses.lock(), &to).is_some() {
                        recipients.push(to);
                        "250 Ok".into()
                    } else {
                        format!("550 5.1.1 <{to}>: Recipient address rejected: mailbox unavailable")
                    }
                }
            }
            "DATA" => {
                if recipients.is_empty() {
                    "503 5.5.1 Error: need RCPT command".into()
                } else {
                    write.write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n").await?;
                    let mut data = Vec::new();
                    let mut l = Vec::new();
                    let mut too_big = false;
                    loop {
                        l.clear();
                        if read.read_until(b'\n', &mut l).await? == 0 {
                            return Ok(());
                        }
                        if l == b".\r\n" || l == b".\n" {
                            break;
                        }
                        let content = if l.starts_with(b"..") { &l[1..] } else { &l[..] };
                        if data.len() + content.len() > MAX_MESSAGE {
                            too_big = true;
                        } else {
                            data.extend_from_slice(content);
                        }
                    }
                    let from = mail_from.take().unwrap_or_default();
                    let to = std::mem::take(&mut recipients);
                    if too_big {
                        "552 5.3.4 Message size exceeds fixed limit".into()
                    } else if let Some(l) = &login {
                        let mut ctx = l.ctx.clone();
                        ctx.received_at = ses.background_context(&ctx.caller.account_id, &ctx.region).received_at;
                        ctx.source_ip = Some(peer.clone());
                        ctx.request_id = uuid::Uuid::new_v4().to_string();
                        match ses.send_smtp(&ctx, &from, to, data) {
                            Ok(id) => format!("250 Ok {id}"),
                            Err(e) => format!("554 Transaction failed: {}", e.message()),
                        }
                    } else {
                        let ctx = ses.background_context(&ses.default_account(), "us-east-1");
                        let inbound = Inbound {
                            raw: data,
                            mail_from: from,
                            recipients: to,
                            source_ip: peer.clone(),
                            tls: false,
                            origin: None,
                        };
                        match ses.receive(&ctx, inbound).await {
                            Ok(r) => format!("250 Ok {}", r.message_id),
                            Err((code, m)) => format!("{code} {m}"),
                        }
                    }
                }
            }
            "" => continue,
            _ => "502 5.5.2 Error: command not recognized".into(),
        };
        write.write_all(format!("{reply}\r\n").as_bytes()).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_shape() {
        let p = smtp_password("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-1");
        let raw = base64::engine::general_purpose::STANDARD.decode(&p).unwrap();
        assert_eq!(raw.len(), 33);
        assert_eq!(raw[0], 4);
        assert_ne!(p, smtp_password("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "eu-west-1"));
    }

    #[test]
    fn paths() {
        assert_eq!(path_arg("<a@b.com> SIZE=10"), "a@b.com");
        assert_eq!(path_arg(" a@b.com"), "a@b.com");
    }
}
