//! HTTP/2 (DoH) client stream and connection helpers for hickory-net.
//!
//! Provides [`HttpsClientStream`], [`HttpsClientStreamBuilder`], and the
//! lower-level [`connect`] and [`message_from`] free functions used by the
//! DoH transport layer.

use core::fmt::Debug;
use core::future::Future;
use core::net::SocketAddr;
use core::pin::Pin;
use core::str::FromStr;
use core::task::{Context, Poll};
use std::cell::Cell;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use futures_util::stream::{Stream, StreamExt};
use h2::client::SendRequest;
use http::header::{
    self, HeaderValue, ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, CACHE_CONTROL, CONTENT_LENGTH,
    USER_AGENT,
};
use http::{Method, Request};
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

use crate::error::NetError;
use crate::http::{RequestContext, SetHeaders, Version};
use crate::proto::op::{DnsRequest, DnsResponse};
use crate::runtime::iocompat::AsyncIoStdAsTokio;
use crate::runtime::{DnsTcpStream, RuntimeProvider, Spawn};
use crate::xfer::{DnsExchange, DnsRequestSender, DnsResponseStream, CONNECT_TIMEOUT};

// ---------------------------------------------------------------------------
// Obfuscation helpers — always active, no opt-in required
// ---------------------------------------------------------------------------

/// Block size for request body padding. Every outbound POST body is rounded
/// up to the next multiple of this value by appending zero bytes, masking the
/// real DNS message length from passive observers.
const OBFS_PAD_BLOCK: usize = 128;

/// Browser User-Agent strings rotated per-request to blend DoH traffic with
/// ordinary HTTPS browser sessions.
const OBFS_USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
];

thread_local! {
    static OBFS_RNG_STATE: Cell<u64> = Cell::new(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64 ^ d.as_secs())
            .unwrap_or(0xDEAD_BEEF)
    );
}

/// Cheap non-crypto pseudorandom u64.
/// Statistical quality is irrelevant — used only for UA rotation and nonces.
/// Uses thread-local state to avoid OS clock syscall overhead per request.
#[inline]
fn obfs_rand() -> u64 {
    OBFS_RNG_STATE.with(|state| {
        let mut x = state.get();
        if x == 0 {
            x = 0xDEAD_BEEF;
        }
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        state.set(x);
        x
    })
}

/// Pad `buf` in-place to the next multiple of `OBFS_PAD_BLOCK` bytes.
/// Padding bytes are zeroed. Reallocation is minimized via exact reservation.
fn obfs_pad(buf: &mut Vec<u8>) {
    let rem = buf.len() % OBFS_PAD_BLOCK;
    if rem != 0 {
        let pad_len = OBFS_PAD_BLOCK - rem;
        buf.reserve_exact(pad_len);
        buf.resize(buf.len() + pad_len, 0u8);
    }
}

/// Append a random nonce query-param so every request URL is unique, e.g.
/// `/dns-query?_=83741`. Defeats URL-pattern classifiers.
fn obfs_path(path: &str) -> String {
    let nonce = obfs_rand() % 100_000;
    if path.contains('?') {
        format!("{path}&_={nonce}")
    } else {
        format!("{path}?_={nonce}")
    }
}

/// Inject browser-mimicry headers into a built `http::Request`.
/// Uses HeaderValue::from_static to avoid runtime parsing overhead.
fn obfs_inject_headers<B>(req: &mut Request<B>) {
    let ua = OBFS_USER_AGENTS[(obfs_rand() as usize) % OBFS_USER_AGENTS.len()];
    let headers = req.headers_mut();
    headers.insert(USER_AGENT, HeaderValue::from_static(ua));
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("application/dns-message, */*;q=0.9"),
    );
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    // "identity" avoids double-compression issues with h2 DATA frames.
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
}

// ---------------------------------------------------------------------------
// HTTP/2 Buffer Constants
// ---------------------------------------------------------------------------
const MAX_DOH_BODY: usize = 64 * 1024;
const MIN_DOH_BODY_ALLOC: usize = 512;
const DEFAULT_DOH_BODY_ALLOC: usize = 4096;

/// An established HTTPS/2 connection to a DNS-over-HTTPS name server.
///
/// Implements [`DnsRequestSender`] for sending DNS queries over HTTP/2,
/// and [`Stream`] for connection health monitoring.
#[derive(Clone)]
#[must_use = "futures do nothing unless polled"]
pub struct HttpsClientStream {
    context: Arc<RequestContext>,
    h2: SendRequest<Bytes>,
    is_shutdown: bool,
}

impl HttpsClientStream {
    /// Creates a new [`HttpsClientStreamBuilder`] for constructing an HTTPS/2 connection.
    pub fn builder<P: RuntimeProvider>(
        client_config: Arc<ClientConfig>,
        provider: P,
    ) -> HttpsClientStreamBuilder<P> {
        HttpsClientStreamBuilder {
            provider,
            client_config,
            bind_addr: None,
            set_headers: None,
            connect_timeout: CONNECT_TIMEOUT,
        }
    }
}

impl DnsRequestSender for HttpsClientStream {
    fn send_message(&mut self, mut request: DnsRequest) -> DnsResponseStream {
        if self.is_shutdown {
            let err = NetError::from(io::Error::new(
                io::ErrorKind::NotConnected,
                "cannot send messages after stream is shutdown",
            ));
            return err.into();
        }

        request.metadata.id = 0;
        let bytes = match request.to_vec() {
            Ok(bytes) => bytes,
            Err(err) => return NetError::from(err).into(),
        };

        // Pad the serialised DNS message to the next OBFS_PAD_BLOCK boundary
        // before handing it off, masking payload length from passive observers.
        let mut payload = bytes;
        obfs_pad(&mut payload);

        Box::pin(send(
            self.h2.clone(),
            Bytes::from(payload),
            self.context.clone(),
        ))
        .into()
    }

    fn shutdown(&mut self) {
        self.is_shutdown = true;
    }

    fn is_shutdown(&self) -> bool {
        self.is_shutdown
    }
}

impl Stream for HttpsClientStream {
    type Item = Result<(), NetError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.is_shutdown {
            return Poll::Ready(None);
        }

        match self.h2.poll_ready(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Some(Ok(()))),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(NetError::from(format!(
                "h2 stream errored: {e}",
            ))))),
        }
    }
}

/// Builder for [`HttpsClientStream`].
///
/// Obtained via [`HttpsClientStream::builder`]. Configure the connection
/// parameters, then call [`exchange`][Self::exchange] or [`build`][Self::build]
/// to establish the HTTP/2 connection.
#[derive(Clone)]
pub struct HttpsClientStreamBuilder<P> {
    provider: P,
    client_config: Arc<ClientConfig>,
    bind_addr: Option<SocketAddr>,
    set_headers: Option<Arc<dyn SetHeaders>>,
    connect_timeout: Duration,
}

impl<P: RuntimeProvider> HttpsClientStreamBuilder<P> {
    /// Sets the local socket address to bind to before connecting.
    pub fn bind_addr(&mut self, bind_addr: SocketAddr) {
        self.bind_addr = Some(bind_addr);
    }

    /// Installs a custom [`SetHeaders`] hook that is called on every outbound request.
    pub fn set_headers(&mut self, headers: Arc<dyn SetHeaders>) {
        self.set_headers.replace(headers);
    }

    /// Overrides the TCP+TLS connection timeout (default: [`CONNECT_TIMEOUT`]).
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Connects to `name_server`, performs the HTTP/2 handshake, and returns a
    /// [`DnsExchange`] with the background driver already spawned.
    pub async fn exchange(
        self,
        name_server: SocketAddr,
        server_name: Arc<str>,
        path: Arc<str>,
    ) -> Result<DnsExchange<P>, NetError> {
        let mut handle = self.provider.create_handle();
        let stream = self.build(name_server, server_name, path).await?;
        let (exchange, bg) = DnsExchange::from_stream(stream);
        handle.spawn_bg(bg);
        Ok(exchange)
    }

    /// Returns a future that resolves to an [`HttpsClientStream`] once the
    /// TCP connection, TLS handshake, and HTTP/2 preface exchange complete.
    ///
    /// The caller is responsible for spawning the returned background driver.
    /// Prefer [`exchange`][Self::exchange] to have that done automatically.
    pub fn build(
        self,
        name_server: SocketAddr,
        server_name: Arc<str>,
        path: Arc<str>,
    ) -> impl Future<Output = Result<HttpsClientStream, NetError>> + Send + 'static {
        connect(
            self.provider.connect_tcp(name_server, self.bind_addr, None),
            self.client_config,
            name_server,
            server_name,
            path,
            self.set_headers,
            self.connect_timeout,
        )
    }
}

/// Low-level connection helper that drives a TCP future through TLS and the
/// HTTP/2 handshake to produce an [`HttpsClientStream`].
///
/// Prefer [`HttpsClientStreamBuilder::build`] or [`HttpsClientStreamBuilder::exchange`]
/// unless you need to supply a custom TCP future.
pub fn connect(
    tcp: impl Future<Output = Result<impl DnsTcpStream, io::Error>> + Send + 'static,
    mut client_config: Arc<ClientConfig>,
    name_server: SocketAddr,
    server_name: Arc<str>,
    query_path: Arc<str>,
    set_headers: Option<Arc<dyn SetHeaders>>,
    connect_timeout: Duration,
) -> impl Future<Output = Result<HttpsClientStream, NetError>> + Send + 'static {
    if client_config.alpn_protocols.is_empty() {
        Arc::make_mut(&mut client_config).alpn_protocols = vec![ALPN_H2.to_vec()];
    }

    let context = Arc::new(RequestContext {
        version: Version::Http2,
        server_name,
        query_path,
        set_headers,
    });

    async move {
        let tls_server_name = match ServerName::try_from(&*context.server_name) {
            Ok(dns_name) => dns_name.to_owned(),
            Err(err) => {
                return Err(NetError::from(format!(
                    "bad server name {:?}: {err}",
                    context.server_name
                )));
            }
        };

        let (h2, driver) = timeout(connect_timeout, async {
            let tcp = tcp.await?;
            let tls = TlsConnector::from(client_config)
                .connect(tls_server_name, AsyncIoStdAsTokio(tcp))
                .await
                .map_err(NetError::from)?;

            let mut handshake = h2::client::Builder::new();
            handshake.enable_push(false);
            handshake.handshake(tls).await.map_err(NetError::from)
        })
        .await
        .map_err(|_| NetError::Timeout)??;

        debug!("h2 connection established to: {name_server}");
        tokio::spawn(async move {
            if let Err(e) = driver.await {
                warn!("h2 connection failed: {e}");
            }
        });

        Ok(HttpsClientStream {
            h2,
            context,
            is_shutdown: false,
        })
    }
}

async fn send(
    h2: SendRequest<Bytes>,
    message: Bytes,
    cx: Arc<RequestContext>,
) -> Result<DnsResponse, NetError> {
    let mut h2 = match h2.ready().await {
        Ok(h2) => h2,
        Err(err) => {
            return Err(NetError::from(format!("h2 send_request error: {err}")));
        }
    };

    let mut request = cx
        .build(message.remaining())
        .map_err(|err| NetError::from(format!("bad http request: {err}")))?;

    // Append random nonce query-param to the request URI to defeat URL classifiers.
    // Doing this in-place avoids allocating a new Arc<str> and Arc<RequestContext>.
    let old_uri = request.uri().clone();
    let mut parts = old_uri.into_parts();
    if let Some(pq) = parts.path_and_query {
        let new_pq = obfs_path(pq.as_str());
        parts.path_and_query = Some(new_pq.parse().unwrap());
    }
    *request.uri_mut() = http::Uri::from_parts(parts).unwrap();

    // Inject browser-mimicry headers unconditionally.
    obfs_inject_headers(&mut request);

    debug!("request: {:#?}", request);

    let (response_future, mut send_stream) = h2
        .send_request(request, false)
        .map_err(|err| NetError::from(format!("h2 send_request error: {err}")))?;

    send_stream
        .send_data(message, true)
        .map_err(|e| NetError::from(format!("h2 send_data error: {e}")))?;

    let mut response_stream = response_future
        .await
        .map_err(|err| NetError::from(format!("received a stream error: {err}")))?;

    debug!("got response: {:#?}", response_stream);

    let content_length = response_stream
        .headers()
        .get(CONTENT_LENGTH)
        .map(|v| v.to_str())
        .transpose()
        .map_err(|e| NetError::from(format!("bad headers received: {e}")))?
        .map(usize::from_str)
        .transpose()
        .map_err(|e| NetError::from(format!("bad headers received: {e}")))?;

    let initial_capacity = content_length
        .unwrap_or(DEFAULT_DOH_BODY_ALLOC)
        .min(MAX_DOH_BODY)
        .max(MIN_DOH_BODY_ALLOC);

    let mut response_bytes = BytesMut::with_capacity(initial_capacity);

    while let Some(partial_bytes) = response_stream.body_mut().data().await {
        let partial_bytes =
            partial_bytes.map_err(|e| NetError::from(format!("bad http request: {e}")))?;

        debug!("got bytes: {}", partial_bytes.len());
        response_bytes.extend_from_slice(&partial_bytes);

        if response_bytes.len() > MAX_DOH_BODY {
            return Err(NetError::from(format!(
                "response too large: {} bytes (max {})",
                response_bytes.len(),
                MAX_DOH_BODY
            )));
        }

        if let Some(content_length) = content_length {
            if response_bytes.len() >= content_length {
                break;
            }
        }
    }

    if let Some(content_length) = content_length {
        if response_bytes.len() != content_length {
            return Err(NetError::from(format!(
                "expected byte length: {}, got: {}",
                content_length,
                response_bytes.len()
            )));
        }
    }

    if !response_stream.status().is_success() {
        let error_string = String::from_utf8_lossy(response_bytes.as_ref());
        return Err(NetError::from(format!(
            "http unsuccessful code: {}, message: {}",
            response_stream.status(),
            error_string
        )));
    } else {
        if let Some(content_type) = response_stream.headers().get(header::CONTENT_TYPE) {
            if content_type.as_bytes() != crate::http::MIME_APPLICATION_DNS.as_bytes() {
                return Err(NetError::from(format!(
                    "ContentType unsupported (must be '{}'): {:?}",
                    crate::http::MIME_APPLICATION_DNS,
                    content_type
                )));
            }
        }
    };

    DnsResponse::from_buffer(response_bytes.to_vec()).map_err(NetError::from)
}

/// Validates and decodes an inbound HTTP/2 DNS request into raw message bytes.
///
/// Verifies the request against `this_server_name` and `this_server_endpoint`,
/// then dispatches to the appropriate method handler. Currently only POST is
/// supported; GET returns an error.
pub async fn message_from<R>(
    this_server_name: Option<Arc<str>>,
    this_server_endpoint: Arc<str>,
    request: Request<R>,
) -> Result<BytesMut, NetError>
where
    R: Stream<Item = Result<Bytes, h2::Error>> + 'static + Send + Debug + Unpin,
{
    debug!("Received request: {:#?}", request);

    let this_server_name = this_server_name.as_deref();
    match crate::http::verify(
        Version::Http2,
        this_server_name,
        &this_server_endpoint,
        &request,
    ) {
        Ok(_) => (),
        Err(err) => return Err(err),
    }

    let mut content_length = None;
    if let Some(length) = request.headers().get(CONTENT_LENGTH) {
        let length = usize::from_str(length.to_str()?)?;
        debug!("got message length: {}", length);
        content_length = Some(length);
    }

    match *request.method() {
        Method::GET => Err(format!("GET unimplemented: {}", request.method()).into()),
        Method::POST => message_from_post(request.into_body(), content_length).await,
        _ => Err(format!("bad method: {}", request.method()).into()),
    }
}

pub(crate) async fn message_from_post<R>(
    mut request_stream: R,
    length: Option<usize>,
) -> Result<BytesMut, NetError>
where
    R: Stream<Item = Result<Bytes, h2::Error>> + 'static + Send + Debug + Unpin,
{
    let initial_capacity = length
        .unwrap_or(DEFAULT_DOH_BODY_ALLOC)
        .min(MAX_DOH_BODY)
        .max(MIN_DOH_BODY_ALLOC);

    let mut bytes = BytesMut::with_capacity(initial_capacity);

    loop {
        match request_stream.next().await {
            Some(Ok(frame)) => {
                bytes.extend_from_slice(&frame);
                if bytes.len() > MAX_DOH_BODY {
                    return Err(NetError::from(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "request too large",
                    )));
                }
            }
            Some(Err(err)) => return Err(err.into()),
            None => {
                return if let Some(length) = length {
                    // A padded sender may deliver more bytes than the declared
                    // DNS content length (trailing zero padding). Accept as
                    // long as the real content fits inside the received body.
                    if bytes.len() >= length {
                        Ok(bytes.split_to(length))
                    } else {
                        Err(NetError::from(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "not all bytes received",
                        )))
                    }
                } else {
                    Ok(bytes)
                };
            }
        };

        if let Some(length) = length {
            if bytes.len() >= length {
                return Ok(bytes.split_to(length));
            }
        }
    }
}

const ALPN_H2: &[u8] = b"h2";

#[cfg(test)]
mod tests {
    use core::net::SocketAddr;

    use rustls::KeyLogFile;
    use test_support::subscribe;

    use super::*;
    use crate::proto::op::{DnsRequestOptions, Edns, Message, Query};
    use crate::proto::rr::{Name, RData, RecordType};
    use crate::runtime::TokioRuntimeProvider;
    use crate::tls::client_config;
    use crate::xfer::FirstAnswer;

    // --- obfuscation unit tests -------------------------------------------

    #[test]
    fn test_obfs_pad_aligns_to_block() {
        let mut buf = vec![0xAAu8; 10];
        obfs_pad(&mut buf);
        assert_eq!(buf.len(), OBFS_PAD_BLOCK);
        assert!(buf[..10].iter().all(|&b| b == 0xAA));
        assert!(buf[10..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_obfs_pad_already_aligned() {
        let mut buf = vec![0x55u8; OBFS_PAD_BLOCK];
        obfs_pad(&mut buf);
        assert_eq!(buf.len(), OBFS_PAD_BLOCK);
    }

    #[test]
    fn test_obfs_path_appends_nonce() {
        let p = obfs_path("/dns-query");
        assert!(p.starts_with("/dns-query?_="), "got: {p}");
    }

    #[test]
    fn test_obfs_path_existing_params() {
        let p = obfs_path("/dns-query?type=A");
        assert!(p.contains("&_="), "got: {p}");
    }

    // --- original tests (unchanged) ---------------------------------------

    #[cfg(any(feature = "webpki-roots", feature = "rustls-platform-verifier"))]
    #[tokio::test]
    async fn test_https_google() {
        subscribe();
        let google = SocketAddr::from(([8, 8, 8, 8], 443));
        let mut request = Message::query();
        let query = Query::new(Name::from_str("www.example.com.").unwrap(), RecordType::A);
        request.add_query(query);
        request.metadata.recursion_desired = true;
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        request.edns = Some(edns);

        let request = DnsRequest::new(request, DnsRequestOptions::default());
        let mut client_config = client_config_h2();
        client_config.key_log = Arc::new(KeyLogFile::new());

        let provider = TokioRuntimeProvider::new();
        let https_builder = HttpsClientStream::builder(Arc::new(client_config), provider);
        let connect =
            https_builder.build(google, Arc::from("dns.google"), Arc::from("/dns-query"));
        let mut https = connect.await.expect("https connect failed");

        let response = https
            .send_message(request)
            .first_answer()
            .await
            .expect("send_message failed");
        assert!(
            response
                .answers
                .iter()
                .any(|record| matches!(record.data, RData::A(_)))
        );
        let mut request = Message::query();
        let query = Query::new(
            Name::from_str("www.example.com.").unwrap(),
            RecordType::AAAA,
        );
        request.add_query(query);
        request.metadata.recursion_desired = true;
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        request.edns = Some(edns);

        let request = DnsRequest::new(request, DnsRequestOptions::default());
        let response = https
            .send_message(request.clone())
            .first_answer()
            .await
            .expect("send_message failed");
        assert!(
            response
                .answers
                .iter()
                .any(|record| matches!(record.data, RData::AAAA(_)))
        );
    }

    #[cfg(any(feature = "webpki-roots", feature = "rustls-platform-verifier"))]
    #[tokio::test]
    async fn test_https_google_with_pure_ip_address_server() {
        subscribe();
        let google = SocketAddr::from(([8, 8, 8, 8], 443));
        let mut request = Message::query();
        let query = Query::new(Name::from_str("www.example.com.").unwrap(), RecordType::A);
        request.add_query(query);
        request.metadata.recursion_desired = true;
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        request.edns = Some(edns);

        let request = DnsRequest::new(request, DnsRequestOptions::default());
        let mut client_config = client_config_h2();
        client_config.key_log = Arc::new(KeyLogFile::new());

        let provider = TokioRuntimeProvider::new();
        let https_builder = HttpsClientStream::builder(Arc::new(client_config), provider);
        let connect = https_builder.build(
            google,
            Arc::from(google.ip().to_string()),
            Arc::from("/dns-query"),
        );
        let mut https = connect.await.expect("https connect failed");

        let response = https
            .send_message(request)
            .first_answer()
            .await
            .expect("send_message failed");
        assert!(
            response
                .answers
                .iter()
                .any(|record| matches!(record.data, RData::A(_)))
        );
        let mut request = Message::query();
        let query = Query::new(
            Name::from_str("www.example.com.").unwrap(),
            RecordType::AAAA,
        );
        request.add_query(query);
        request.metadata.recursion_desired = true;
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        request.edns = Some(edns);

        let request = DnsRequest::new(request, DnsRequestOptions::default());
        let response = https
            .send_message(request.clone())
            .first_answer()
            .await
            .expect("send_message failed");
        assert!(
            response
                .answers
                .iter()
                .any(|record| matches!(record.data, RData::AAAA(_)))
        );
    }

    #[cfg(any(feature = "webpki-roots", feature = "rustls-platform-verifier"))]
    #[tokio::test]
    #[ignore = "cloudflare has been unreliable as a public test service"]
    async fn test_https_cloudflare() {
        subscribe();
        let cloudflare = SocketAddr::from(([1, 1, 1, 1], 443));
        let mut request = Message::query();
        let query = Query::new(Name::from_str("www.example.com.").unwrap(), RecordType::A);
        request.add_query(query);
        request.metadata.recursion_desired = true;
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        request.edns = Some(edns);

        let request = DnsRequest::new(request, DnsRequestOptions::default());
        let client_config = client_config_h2();
        let provider = TokioRuntimeProvider::new();
        let https_builder = HttpsClientStream::builder(Arc::new(client_config), provider);
        let connect = https_builder.build(
            cloudflare,
            Arc::from("cloudflare-dns.com"),
            Arc::from("/dns-query"),
        );
        let mut https = connect.await.expect("https connect failed");

        let response = https
            .send_message(request)
            .first_answer()
            .await
            .expect("send_message failed");
        assert!(
            response
                .answers
                .iter()
                .any(|record| matches!(record.data, RData::A(_)))
        );
        let mut request = Message::query();
        let query = Query::new(
            Name::from_str("www.example.com.").unwrap(),
            RecordType::AAAA,
        );
        request.add_query(query);
        request.metadata.recursion_desired = true;
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        request.edns = Some(edns);

        let request = DnsRequest::new(request, DnsRequestOptions::default());
        let response = https
            .send_message(request)
            .first_answer()
            .await
            .expect("send_message failed");
        assert!(
            response
                .answers
                .iter()
                .any(|record| matches!(record.data, RData::AAAA(_)))
        );
    }

    fn client_config_h2() -> ClientConfig {
        let mut config = client_config().unwrap();
        config.alpn_protocols = vec![ALPN_H2.to_vec()];
        config
    }

    #[tokio::test]
    async fn test_from_post() {
        subscribe();
        let message = Message::query();
        let msg_bytes = message.to_vec().unwrap();
        let len = msg_bytes.len();
        let stream = TestBytesStream(vec![Ok(Bytes::from(msg_bytes))]);
        let cx = RequestContext {
            version: Version::Http2,
            server_name: Arc::from("ns.example.com"),
            query_path: Arc::from("/dns-query"),
            set_headers: None,
        };
        let request = cx.build(len).unwrap();
        let request = request.map(|()| stream);

        let bytes = message_from(
            Some(Arc::from("ns.example.com")),
            "/dns-query".into(),
            request,
        )
        .await
        .unwrap();
        let msg_from_post = Message::from_vec(bytes.as_ref()).expect("bytes failed");
        assert_eq!(message, msg_from_post);
    }

    #[derive(Debug)]
    struct TestBytesStream(Vec<Result<Bytes, h2::Error>>);

    impl Stream for TestBytesStream {
        type Item = Result<Bytes, h2::Error>;
        
        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            match self.0.pop() {
                Some(Ok(bytes)) => Poll::Ready(Some(Ok(bytes))),
                Some(Err(err)) => Poll::Ready(Some(Err(err))),
                None => Poll::Ready(None),
            }
        }
    }
}
