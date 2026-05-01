use core::fmt::Debug;
use core::future::Future;
use core::net::SocketAddr;
use core::pin::Pin;
use core::str::FromStr;
use core::task::{Context, Poll};
use std::io;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use futures_util::stream::{Stream, StreamExt};
use h2::client::SendRequest;
use http::header::{self, CONTENT_LENGTH};
use http::{Method, Request};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

use crate::error::NetError;
use crate::http::{RequestContext, SetHeaders, Version};
use crate::proto::op::{DnsRequest, DnsResponse};
use crate::runtime::iocompat::AsyncIoStdAsTokio;
use crate::runtime::{DnsTcpStream, RuntimeProvider, Spawn};
use crate::xfer::{CONNECT_TIMEOUT, DnsExchange, DnsRequestSender, DnsResponseStream};

#[derive(Clone)]
#[must_use = "futures do nothing unless polled"]
pub struct HttpsClientStream {
    context: Arc<RequestContext>,
    h2: SendRequest<Bytes>,
    is_shutdown: bool,
}

impl HttpsClientStream {
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
            panic!("can not send messages after stream is shutdown")
        }

        request.metadata.id = 0;

        let bytes = match request.to_vec() {
            Ok(bytes) => bytes,
            Err(err) => return NetError::from(err).into(),
        };

        Box::pin(send(
            self.h2.clone(),
            Bytes::from(bytes),
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

#[derive(Clone)]
pub struct HttpsClientStreamBuilder<P> {
    provider: P,
    client_config: Arc<ClientConfig>,
    bind_addr: Option<SocketAddr>,
    set_headers: Option<Arc<dyn SetHeaders>>,
    connect_timeout: Duration,
}

impl<P: RuntimeProvider> HttpsClientStreamBuilder<P> {
    pub fn bind_addr(&mut self, bind_addr: SocketAddr) {
        self.bind_addr = Some(bind_addr);
    }

    pub fn set_headers(&mut self, headers: Arc<dyn SetHeaders>) {
        self.set_headers.replace(headers);
    }

    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

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
        let mut client_cfg = (*client_config).clone();
        client_cfg.alpn_protocols = vec![ALPN_H2.to_vec()];

        client_config = Arc::new(client_cfg);
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

    let request = cx
        .build(message.remaining())
        .map_err(|err| NetError::from(format!("bad http request: {err}")))?;

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

    const MAX_DOH_BODY: usize = 64 * 1024;
    let initial_capacity = content_length
        .unwrap_or(4096)
        .min(MAX_DOH_BODY)
        .max(512);
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
        let content_type = response_stream
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|h| {
                h.to_str().map_err(|err| {
                    NetError::from(format!("ContentType header not a string: {err}"))
                })
            })
            .unwrap_or(Ok(crate::http::MIME_APPLICATION_DNS))?;

        if content_type != crate::http::MIME_APPLICATION_DNS {
            return Err(NetError::from(format!(
                "ContentType unsupported (must be '{}'): '{}'",
                crate::http::MIME_APPLICATION_DNS,
                content_type
            )));
        }
    };

    DnsResponse::from_buffer(response_bytes.to_vec()).map_err(NetError::from)
}

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
    const MAX_DOH_BODY: usize = 64 * 1024;
    let initial_capacity = length.unwrap_or(4096).min(MAX_DOH_BODY).max(512);
    let mut bytes = BytesMut::with_capacity(initial_capacity);

    loop {
        match request_stream.next().await {
            Some(Ok(frame)) => {
                bytes.extend_from_slice(&frame);
                if bytes.len() > MAX_DOH_BODY {
                    return Err("request too large".into());
                }
            }
            Some(Err(err)) => return Err(err.into()),
            None => {
                return if let Some(length) = length {
                    if bytes.len() == length {
                        Ok(bytes)
                    } else {
                        Err("not all bytes received".into())
                    }
                } else {
                    Ok(bytes)
                };
            }
        };

        if let Some(length) = length {
            if bytes.len() == length {
                return Ok(bytes);
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
