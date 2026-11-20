use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, anyhow};
use serde::de::DeserializeOwned;
use serde_json::json;
use towonel_common::auth::sign_auth_header;
use towonel_common::hub_error;
use towonel_common::time::now_ms;

use crate::api::{Cred, DeviceCode, Enrolled, Netmap};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub enum Poll {
    Pending,
    Enrolled(Box<Enrolled>),
}

pub enum StreamEvent {
    Netmap(Box<Netmap>),
    Revoked,
    KeyExpired,
}

pub struct MeshClient {
    hub_url: String,
    key: iroh::SecretKey,
    http: reqwest::Client,
    last_ts: AtomicU64,
}

impl MeshClient {
    pub fn new(hub_url: &str, key: iroh::SecretKey) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            hub_url: hub_url.trim_end_matches('/').to_string(),
            key,
            http,
            last_ts: AtomicU64::new(0),
        })
    }

    pub async fn enroll(&self, auth_key: &str, name: &str, os: &str) -> anyhow::Result<Enrolled> {
        let body = json!({"auth_key": auth_key, "name": name, "os": os});
        let (_, bytes) = self
            .post("/v1/mesh/enroll", "towonel/mesh-enroll/v1", &body)
            .await?;
        decode(&bytes)
    }

    pub async fn request_device_code(&self, name: &str, os: &str) -> anyhow::Result<DeviceCode> {
        let body = json!({"name": name, "os": os});
        let (_, bytes) = self
            .post("/v1/mesh/device-code", "towonel/mesh-device-code/v1", &body)
            .await?;
        decode(&bytes)
    }

    pub async fn poll_device_code(&self) -> anyhow::Result<Poll> {
        let (status, bytes) = self
            .post_raw(
                "/v1/mesh/device-code/poll",
                "towonel/mesh-device-poll/v1",
                Vec::new(),
            )
            .await?;
        if status == reqwest::StatusCode::ACCEPTED {
            return Ok(Poll::Pending);
        }
        decode(&bytes).map(|e| Poll::Enrolled(Box::new(e)))
    }

    pub async fn cred(&self) -> anyhow::Result<Cred> {
        #[derive(serde::Deserialize)]
        struct Resp {
            cred: Cred,
        }
        let (_, bytes) = self
            .post_raw("/v1/mesh/cred", "towonel/mesh-cred/v1", Vec::new())
            .await?;
        decode::<Resp>(&bytes).map(|r| r.cred)
    }

    pub async fn report_endpoint(&self, addr: &iroh::EndpointAddr) -> anyhow::Result<()> {
        let body = serde_json::to_vec(addr)?;
        self.post_raw("/v1/mesh/endpoint", "towonel/mesh-endpoint/v1", body)
            .await
            .map(drop)
    }

    pub async fn report_services(&self, ports: &[u16]) -> anyhow::Result<()> {
        let body = serde_json::to_vec(&json!({"ports": ports}))?;
        self.post_raw("/v1/mesh/services", "towonel/mesh-services/v1", body)
            .await
            .map(drop)
    }

    pub async fn advertise_exit_node(&self, advertise: bool) -> anyhow::Result<()> {
        let body = serde_json::to_vec(&json!({"advertise": advertise}))?;
        self.post_raw("/v1/mesh/exit-node", "towonel/mesh-exit-node/v1", body)
            .await
            .map(drop)
    }

    pub async fn netmap(&self) -> anyhow::Result<Netmap> {
        let resp = self
            .get("/v1/mesh/netmap", "towonel/mesh-netmap/v1")
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await?;
        let (_, bytes) = check(resp).await?;
        decode(&bytes)
    }

    pub async fn netmap_stream(&self) -> anyhow::Result<NetmapStream> {
        let resp = self
            .get("/v1/mesh/netmap/stream", "towonel/mesh-netmap-stream/v1")
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.bytes().await?;
            return Err(hub_err(status, &body));
        }
        Ok(NetmapStream {
            resp,
            buf: Vec::new(),
        })
    }

    fn get(&self, path: &str, domain: &str) -> reqwest::RequestBuilder {
        self.http
            .get(format!("{}{path}", self.hub_url))
            .header(reqwest::header::AUTHORIZATION, self.sign(domain, &[]))
    }

    async fn post(
        &self,
        path: &str,
        domain: &str,
        body: &serde_json::Value,
    ) -> anyhow::Result<(reqwest::StatusCode, Vec<u8>)> {
        self.post_raw(path, domain, serde_json::to_vec(body)?).await
    }

    async fn post_raw(
        &self,
        path: &str,
        domain: &str,
        body: Vec<u8>,
    ) -> anyhow::Result<(reqwest::StatusCode, Vec<u8>)> {
        let url = format!("{}{path}", self.hub_url);
        let resp = self
            .http
            .post(&url)
            .header(reqwest::header::AUTHORIZATION, self.sign(domain, &body))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .timeout(REQUEST_TIMEOUT)
            .body(body)
            .send()
            .await
            .with_context(|| format!("failed to reach {url}"))?;
        check(resp).await
    }

    /// Timestamps strictly increase so two requests in the same millisecond
    /// don't collide in the hub's replay cache.
    fn sign(&self, domain: &str, body: &[u8]) -> String {
        let now = now_ms();
        let prev = self
            .last_ts
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |last| {
                Some(now.max(last + 1))
            })
            .unwrap_or_else(|last| last);
        sign_auth_header(&self.key, domain, now.max(prev + 1), body)
    }
}

/// Server-sent events from `GET /v1/mesh/netmap/stream`.
pub struct NetmapStream {
    resp: reqwest::Response,
    buf: Vec<u8>,
}

impl NetmapStream {
    /// `Ok(None)` when the hub closes the stream.
    pub async fn next(&mut self) -> anyhow::Result<Option<StreamEvent>> {
        loop {
            while let Some(frame) = take_frame(&mut self.buf) {
                if let Some(event) = parse_event(&frame)? {
                    return Ok(Some(event));
                }
            }
            match self.resp.chunk().await? {
                Some(chunk) => self.buf.extend_from_slice(&chunk),
                None => return Ok(None),
            }
        }
    }
}

fn take_frame(buf: &mut Vec<u8>) -> Option<String> {
    let end = buf.windows(2).position(|w| w == b"\n\n")?;
    let frame: Vec<u8> = buf.drain(..end + 2).collect();
    Some(String::from_utf8_lossy(&frame).into_owned())
}

/// `None` for keep-alives and events this client doesn't know.
fn parse_event(frame: &str) -> anyhow::Result<Option<StreamEvent>> {
    let mut name = None;
    let mut data = String::new();
    for line in frame.lines() {
        if let Some(v) = line.strip_prefix("event:") {
            name = Some(v.trim());
        } else if let Some(v) = line.strip_prefix("data:") {
            data.push_str(v.trim_start());
        }
    }
    Ok(match name {
        Some("netmap") => Some(StreamEvent::Netmap(Box::new(serde_json::from_str(&data)?))),
        Some("revoked") => Some(StreamEvent::Revoked),
        Some("key_expired") => Some(StreamEvent::KeyExpired),
        _ => None,
    })
}

async fn check(resp: reqwest::Response) -> anyhow::Result<(reqwest::StatusCode, Vec<u8>)> {
    let status = resp.status();
    let body = resp.bytes().await?.to_vec();
    if status.is_success() {
        Ok((status, body))
    } else {
        Err(hub_err(status, &body))
    }
}

/// Worth retrying: the hub was unreachable or failed on its side, as opposed
/// to answering with a 4xx.
#[must_use]
pub fn is_transient(e: &anyhow::Error) -> bool {
    e.downcast_ref::<hub_error::HubApiError>()
        .is_none_or(|h| h.status >= 500)
}

fn hub_err(status: reqwest::StatusCode, body: &[u8]) -> anyhow::Error {
    hub_error::parse(status.as_u16(), body).map_or_else(
        || anyhow!("hub returned {status}: {}", String::from_utf8_lossy(body)),
        Into::into,
    )
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> anyhow::Result<T> {
    serde_json::from_slice(bytes).context("unexpected hub response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_split_across_chunks() {
        let mut buf = b"event: revoked\nda".to_vec();
        assert!(take_frame(&mut buf).is_none());
        buf.extend_from_slice(b"ta: {}\n\n: keep-alive\n\n");
        let frame = take_frame(&mut buf).unwrap();
        assert!(matches!(
            parse_event(&frame).unwrap(),
            Some(StreamEvent::Revoked)
        ));
        let keepalive = take_frame(&mut buf).unwrap();
        assert!(parse_event(&keepalive).unwrap().is_none());
        assert!(buf.is_empty());
    }

    #[test]
    fn only_unreachable_or_5xx_is_transient() {
        let api = |status| {
            anyhow::Error::from(hub_error::HubApiError {
                status,
                code: "x".into(),
                message: "x".into(),
            })
        };
        assert!(is_transient(&anyhow!("connection refused")));
        assert!(is_transient(&api(502)));
        assert!(!is_transient(&api(410)));
        assert!(!is_transient(&api(401)));
    }

    #[test]
    fn timestamps_strictly_increase() {
        let client = MeshClient::new("https://hub.test", iroh::SecretKey::generate()).unwrap();
        let ts = |h: String| h.split('.').nth(1).unwrap().parse::<u64>().unwrap();
        let a = ts(client.sign("d", &[]));
        let b = ts(client.sign("d", &[]));
        assert!(b > a);
    }
}
