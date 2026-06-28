// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option.
// This file may not be copied, modified, or distributed except according to those terms.

//! HTTP protocol related components for DNS over HTTP/2 (DoH) and HTTP/3 (DoH3)

use core::str::FromStr;
use std::sync::Arc;

use http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri, header, uri};
use tracing::debug;

use crate::error::NetError;

pub(crate) struct RequestContext {
    pub(crate) version: Version,
    // Pre-computed URI components avoid per-request string parsing
    pub(crate) authority: uri::Authority,
    pub(crate) path_and_query: uri::PathAndQuery,
    pub(crate) set_headers: Option<Arc<dyn SetHeaders>>,
}

impl RequestContext {
    /// Initializes a new RequestContext, pre-parsing the URI components
    pub(crate) fn new(
        version: Version,
        server_name: &str,
        query_path: &str,
        set_headers: Option<Arc<dyn SetHeaders>>,
    ) -> Result<Self, NetError> {
        Ok(Self {
            version,
            authority: uri::Authority::from_str(server_name)
                .map_err(|e| NetError::from(format!("invalid authority: {e}")))?,
            path_and_query: uri::PathAndQuery::try_from(query_path)
                .map_err(|e| NetError::from(format!("invalid DoH path: {e}")))?,
            set_headers,
        })
    }

    /// Create a new Request for an http dns-message request
    ///
    /// ```text
    /// RFC 8484              DNS Queries over HTTPS (DoH)          October 2018
    ///
    /// The URI Template defined in this document is processed without any
    /// variables when the HTTP method is POST. When the HTTP method is GET,
    /// the single variable "dns" is defined as the content of the DNS
    /// request (as described in Section 6), encoded with base64url
    /// [RFC4648].
    /// ```
    pub(crate) fn build(&self, message_len: usize) -> Result<Request<()>, NetError> {
        let mut parts = uri::Parts::default();
        parts.scheme = Some(uri::Scheme::HTTPS);
        // Cheap clones of pre-parsed components
        parts.authority = Some(self.authority.clone());
        parts.path_and_query = Some(self.path_and_query.clone());

        let url = Uri::from_parts(parts)
            .map_err(|e| NetError::from(format!("uri parse error: {e}")))?;

        // TODO: add user agent to TypedHeaders
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(url)
            .version(self.version.to_http())
            .header(CONTENT_TYPE, MIME_APPLICATION_DNS)
            .header(ACCEPT, MIME_APPLICATION_DNS)
            .header(CONTENT_LENGTH, message_len);

        if let Some(headers) = &self.set_headers {
            if let Some(map) = request.headers_mut() {
                headers.set_headers(map)?;
            }
        }

        request
            .body(())
            .map_err(|e| NetError::from(format!("http stream errored: {e}")))
    }
}

/// Verifies the request is well-formed for the name-server and supported protocols
pub fn verify<T>(
    version: Version,
    name_server: Option<&str>,
    query_path: &str,
    request: &Request<T>,
) -> Result<(), NetError> {
    let uri = request.uri();

    // 1. Validate Path
    if uri.path() != query_path {
        return Err(format!("bad path: {}, expected: {}", uri.path(), query_path).into());
    }

    // 2. Validate Scheme
    if Some(&uri::Scheme::HTTPS) != uri.scheme() {
        return Err("must be HTTPS scheme".into());
    }

    // 3. Validate Authority
    if let Some(name_server) = name_server {
        let host = uri.authority().map(|a| a.host()).ok_or("no authority in HTTPS request")?;
        if host != name_server {
            return Err("incorrect authority".into());
        }
    }

    // 4. Validate Content-Type
    // TODO: switch to mime::APPLICATION_DNS when that stabilizes
    let ctype = request.headers().get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .ok_or("unsupported content type")?;
        
    if ctype != MIME_APPLICATION_DNS {
        return Err("unsupported content type".into());
    }

    // 5. Validate Accept Header (Iterator optimized)
    // TODO: switch to mime::APPLICATION_DNS when that stabilizes
    let accept_header = request.headers().get(ACCEPT)
        .ok_or("Accept is unspecified")?
        .to_str()
        .map_err(|e| NetError::from(e.to_string()))?;

    let is_accepted = accept_header.split(',').any(|mime_and_quality| {
        let mime = mime_and_quality.splitn(2, ';').next().unwrap_or("").trim();
        mime == MIME_APPLICATION_DNS || mime == "application/*"
    });

    if !is_accepted {
        return Err("does not accept content type".into());
    }

    // 6. Validate Protocol Version
    if request.version() != version.to_http() {
        let message = match version {
            #[cfg(feature = "__https")]
            Version::Http2 => "only HTTP/2 supported",
            #[cfg(feature = "__h3")]
            Version::Http3 => "only HTTP/3 supported",
        };
        return Err(message.into());
    }

    debug!(
        "verified request from: {}",
        request
            .headers()
            .get(header::USER_AGENT)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown or bad user agent")
    );

    Ok(())
}

/// Create a new Response for an http dns-message request
///
/// ```text
/// RFC 8484              DNS Queries over HTTPS (DoH)          October 2018
///
///  4.2.1. Handling DNS and HTTP Errors
///
/// DNS response codes indicate either success or failure for the DNS
/// query. A successful HTTP response with a 2xx status code (see
/// Section 6.3 of [RFC7231]) is used for any valid DNS response,
/// regardless of the DNS response code. For example, a successful 2xx
/// HTTP status code is used even with a DNS message whose DNS response
/// code indicates failure, such as SERVFAIL or NXDOMAIN.
///
/// HTTP responses with non-successful HTTP status codes do not contain
/// replies to the original DNS question in the HTTP request. DoH
/// clients need to use the same semantic processing of non-successful
/// HTTP status codes as other HTTP clients. This might mean that the
/// DoH client retries the query with the same DoH server, such as if
/// there are authorization failures (HTTP status code 401; see
/// Section 3.1 of [RFC7235]). It could also mean that the DoH client
/// retries with a different DoH server, such as for unsupported media
/// types (HTTP status code 415; see Section 6.5.13 of [RFC7231]), or
/// where the server cannot generate a representation suitable for the
/// client (HTTP status code 406; see Section 6.5.6 of [RFC7231]), and so
/// on.
/// ```
pub fn response(version: Version, message_len: usize) -> Result<Response<()>, NetError> {
    Response::builder()
        .status(StatusCode::OK)
        .version(version.to_http())
        .header(CONTENT_TYPE, MIME_APPLICATION_DNS)
        .header(CONTENT_LENGTH, message_len)
        .body(())
        .map_err(|e| NetError::from(format!("invalid response: {e}")))
}

/// Represents a version of the HTTP spec.
#[derive(Clone, Copy, Debug)]
pub enum Version {
    /// HTTP/2 for DoH.
    #[cfg(feature = "__https")]
    Http2,
    /// HTTP/3 for DoH3.
    #[cfg(feature = "__h3")]
    Http3,
}

impl Version {
    fn to_http(self) -> http::Version {
        match self {
            #[cfg(feature = "__https")]
            Self::Http2 => http::Version::HTTP_2,
            #[cfg(feature = "__h3")]
            Self::Http3 => http::Version::HTTP_3,
        }
    }
}

/// Helper trait to update HTTP headers on requests
///
/// For instance a DoH server may require authentication based
/// on per-request HTTP headers and this trait allows their addition.
pub trait SetHeaders: Send + Sync + 'static {
    /// Get a set of headers to add to the query
    fn set_headers(&self, headers: &mut HeaderMap<HeaderValue>) -> Result<(), NetError>;
}

pub(crate) const MIME_APPLICATION_DNS: &str = "application/dns-message";

/// The default query path for DNS-over-HTTPS if none was given.
pub const DEFAULT_DNS_QUERY_PATH: &str = "/dns-query";

#[cfg(test)]
mod tests {
    use http::{
        HeaderMap,
        header::{HeaderName, HeaderValue},
    };
    use super::*;

    #[test]
    #[cfg(feature = "__https")]
    fn test_new_verify_h2() {
        let cx = RequestContext::new(
            Version::Http2,
            "ns.example.com",
            "/dns-query",
            None,
        ).expect("Failed to create context");
        
        let request = cx.build(512).expect("error converting to http");
        assert!(
            verify(
                Version::Http2,
                Some("ns.example.com"),
                "/dns-query",
                &request
            )
            .is_ok()
        );
    }

    #[test]
    #[cfg(feature = "__https")]
    fn test_additional_headers() {
        let cx = RequestContext::new(
            Version::Http2,
            "ns.example.com",
            "/dns-query",
            Some(Arc::new(vec![(
                HeaderName::from_static("test-header"),
                HeaderValue::from_static("test-header-value"),
            )]) as Arc<dyn SetHeaders>),
        ).expect("Failed to create context");
        
        let request = cx.build(512).expect("error converting to http");
        assert!(
            verify(
                Version::Http2,
                Some("ns.example.com"),
                "/dns-query",
                &request
            )
            .is_ok()
        );
        assert_eq!(
            request
                .headers()
                .get(HeaderName::from_static("test-header"))
                .expect("header to be set"),
            HeaderValue::from_static("test-header-value")
        )
    }

    #[test]
    #[cfg(feature = "__h3")]
    fn test_new_verify_h3() {
        let cx = RequestContext::new(
            Version::Http3,
            "ns.example.com",
            "/dns-query",
            None,
        ).expect("Failed to create context");
        
        let request = cx.build(512).expect("error converting to http");
        assert!(
            verify(
                Version::Http3,
                Some("ns.example.com"),
                "/dns-query",
                &request
            )
            .is_ok()
        );
    }

    impl SetHeaders for Vec<(HeaderName, HeaderValue)> {
        fn set_headers(&self, map: &mut HeaderMap<HeaderValue>) -> Result<(), NetError> {
            for (name, value) in self.iter() {
                map.insert(name.clone(), value.clone());
            }
            Ok(())
        }
    }
}
