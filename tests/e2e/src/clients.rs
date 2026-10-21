//! DNS test clients built on `dnsy-proto`: UDP, TCP, `DoT` (framed streams) and `DoH`.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use dnsy_proto::{Class, Edns, Header, Message, Name, Opcode, Question, Rcode, RecordType};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::pki::{ClientIdentity, Pki};

/// How long a negative assertion (no reply expected) waits.
pub const SILENCE: Duration = Duration::from_millis(500);

static NEXT_ID: AtomicU16 = AtomicU16::new(0x1000);

/// A recursion-desired query for `name` and `rtype` without EDNS.
pub fn query(name: &str, rtype: RecordType) -> Message {
    Message {
        header: Header {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            qr: false,
            opcode: Opcode::Query,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            ad: false,
            cd: false,
            rcode: Rcode::NoError,
        },
        questions: vec![Question {
            name: Name::from_ascii(name).expect("query name"),
            qtype: rtype,
            qclass: Class::In,
        }],
        answers: Vec::new(),
        authority: Vec::new(),
        additional: Vec::new(),
        edns: None,
    }
}

/// `query` with an EDNS OPT advertising `payload` octets.
pub fn query_edns(name: &str, rtype: RecordType, payload: u16) -> Message {
    let mut m = query(name, rtype);
    m.edns = Some(Edns {
        udp_payload: payload,
        ..Edns::default()
    });
    m
}

/// Encodes with a generous limit (clients never truncate their own queries).
pub fn wire(m: &Message) -> Vec<u8> {
    m.encode(65_535).expect("encode query")
}

/// Sends raw bytes over UDP; `None` when nothing came back within `wait`. Only a datagram from
/// `addr` that echoes the query id is a reply: the client socket is unconnected on a shared
/// loopback, so a late answer meant for an earlier owner of the same ephemeral port (another
/// test, another process) must not be mistaken for ours.
pub async fn udp_raw(addr: SocketAddr, bytes: &[u8], wait: Duration) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
    socket.send_to(bytes, addr).await.expect("send");
    let mut buf = vec![0u8; 65_535];
    let id = bytes.get(..2);
    let reply = async {
        loop {
            let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                return None;
            };
            if from == addr && buf.get(..2) == id {
                return Some(buf[..n].to_vec());
            }
        }
    };
    tokio::time::timeout(wait, reply).await.ok().flatten()
}

/// One UDP exchange; panics when there is no reply within the default deadline.
pub async fn udp_exchange(addr: SocketAddr, q: &Message) -> Message {
    let bytes = udp_raw(addr, &wire(q), crate::DEADLINE)
        .await
        .expect("no UDP reply");
    Message::decode(&bytes).expect("decodable reply")
}

/// One UDP exchange that expects silence.
pub async fn udp_silent(addr: SocketAddr, q: &Message) -> bool {
    udp_raw(addr, &wire(q), SILENCE).await.is_none()
}

/// A length-prefixed DNS stream (TCP framing, also used inside TLS).
pub struct Framed<S> {
    pub stream: S,
}

pub type TcpClient = Framed<TcpStream>;
pub type DotClient = Framed<TlsStream<TcpStream>>;

impl Framed<TcpStream> {
    pub async fn connect_tcp(addr: SocketAddr) -> TcpClient {
        Framed {
            stream: TcpStream::connect(addr).await.expect("tcp connect"),
        }
    }
}

impl Framed<TlsStream<TcpStream>> {
    /// Connects over TLS (ALPN `dot`); the handshake error is returned (with TLS 1.3 a rejected
    /// client certificate only shows on the first read).
    pub async fn connect_dot(
        addr: SocketAddr,
        pki: &Pki,
        identity: Option<&ClientIdentity>,
    ) -> io::Result<DotClient> {
        let tcp = TcpStream::connect(addr).await?;
        let stream = TlsConnector::from(pki.client_config(identity, &[b"dot"]))
            .connect(Pki::server_name(), tcp)
            .await?;
        Ok(Framed { stream })
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Framed<S> {
    pub async fn send(&mut self, q: &Message) -> io::Result<()> {
        self.send_raw(&wire(q)).await
    }

    /// Writes `bytes` behind a two-octet length prefix.
    pub async fn send_raw(&mut self, bytes: &[u8]) -> io::Result<()> {
        let len = u16::try_from(bytes.len()).expect("frame fits");
        let mut frame = len.to_be_bytes().to_vec();
        frame.extend_from_slice(bytes);
        self.write_all(&frame).await
    }

    /// Writes bytes as they are, with no framing.
    pub async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.stream.write_all(bytes).await?;
        self.stream.flush().await
    }

    pub async fn recv_raw(&mut self) -> io::Result<Vec<u8>> {
        let mut len = [0u8; 2];
        self.stream.read_exact(&mut len).await?;
        let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
        self.stream.read_exact(&mut buf).await?;
        Ok(buf)
    }

    pub async fn recv(&mut self) -> io::Result<Message> {
        let bytes = tokio::time::timeout(crate::DEADLINE, self.recv_raw())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no reply"))??;
        Message::decode(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    pub async fn ask(&mut self, q: &Message) -> io::Result<Message> {
        self.send(q).await?;
        self.recv().await
    }

    /// Whether the peer closes the connection (EOF or reset) within `wait`; data it still sends
    /// on the way out (a TLS alert, say) is discarded.
    pub async fn closed_within(&mut self, wait: Duration) -> bool {
        let drain = async {
            let mut buf = [0u8; 512];
            loop {
                match self.stream.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
            }
        };
        tokio::time::timeout(wait, drain).await.is_ok()
    }
}

/// How a `DoH` request carries its token.
#[derive(Clone, Debug)]
pub enum Token {
    None,
    /// `Authorization: Bearer <secret>`.
    Bearer(String),
    /// `/dns-query/<secret>`.
    Path(String),
}

/// A `DoH` response.
pub struct DohResponse {
    pub status: u16,
    pub headers: reqwest::header::HeaderMap,
    pub body: Vec<u8>,
}

impl DohResponse {
    pub fn message(&self) -> Message {
        Message::decode(&self.body).expect("DNS message body")
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

/// A `DoH` client over HTTP/2 or HTTP/1.1.
pub struct DohClient {
    client: reqwest::Client,
    base: String,
    pub path: String,
}

impl DohClient {
    pub fn new(pki: &Pki, addr: SocketAddr, http2: bool) -> DohClient {
        crate::pki::install_provider();
        let alpn: &[&[u8]] = if http2 {
            &[b"h2", b"http/1.1"]
        } else {
            &[b"http/1.1"]
        };
        let mut builder = reqwest::Client::builder()
            .tls_backend_preconfigured((*pki.client_config(None, alpn)).clone())
            .timeout(crate::DEADLINE);
        if !http2 {
            builder = builder.http1_only();
        }
        DohClient {
            client: builder.build().expect("reqwest client"),
            base: format!("https://{addr}"),
            path: "/dns-query".to_owned(),
        }
    }

    fn url(&self, token: &Token) -> String {
        match token {
            Token::Path(t) => format!("{}{}/{t}", self.base, self.path),
            _ => format!("{}{}", self.base, self.path),
        }
    }

    fn authorize(builder: reqwest::RequestBuilder, token: &Token) -> reqwest::RequestBuilder {
        match token {
            Token::Bearer(t) => builder.bearer_auth(t),
            _ => builder,
        }
    }

    pub async fn post(&self, q: &Message, token: &Token) -> DohResponse {
        let b = self
            .client
            .post(self.url(token))
            .header("content-type", "application/dns-message")
            .body(wire(q));
        finish(Self::authorize(b, token)).await
    }

    pub async fn get(&self, q: &Message, token: &Token) -> DohResponse {
        let url = format!(
            "{}?dns={}",
            self.url(token),
            URL_SAFE_NO_PAD.encode(wire(q))
        );
        finish(Self::authorize(self.client.get(url), token)).await
    }

    /// An arbitrary request to `path_and_query` (starting with `/`).
    pub async fn raw(
        &self,
        method: reqwest::Method,
        path_and_query: &str,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> DohResponse {
        let mut b = self
            .client
            .request(method, format!("{}{path_and_query}", self.base))
            .body(body);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        finish(b).await
    }
}

async fn finish(b: reqwest::RequestBuilder) -> DohResponse {
    let resp = b.send().await.expect("DoH request");
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = resp.bytes().await.expect("DoH body").to_vec();
    DohResponse {
        status,
        headers,
        body,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn udp_raw_ignores_datagrams_that_are_not_the_servers_reply() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let answering = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, client) = server.recv_from(&mut buf).await.unwrap();
            // A foreign datagram first (someone else's late answer to a recycled port), the
            // server echoing a different id second, then the real reply.
            stranger.send_to(&buf[..n], client).await.unwrap();
            let mut wrong_id = buf[..n].to_vec();
            wrong_id[0] ^= 0xff;
            server.send_to(&wrong_id, client).await.unwrap();
            server.send_to(b"\x12\x34reply", client).await.unwrap();
        });
        let got = udp_raw(addr, b"\x12\x34query", Duration::from_secs(5)).await;
        answering.await.unwrap();
        assert_eq!(got.as_deref(), Some(&b"\x12\x34reply"[..]));
    }
}
