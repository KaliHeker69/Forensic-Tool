/// Timesketch reverse proxy – forwards /tools/timesketch/{*path} to
/// the locally-running Timesketch container at http://127.0.0.1:80.
///
/// Because the container is bound to 127.0.0.1 it is unreachable from
/// any client that is not on the same host.  This proxy makes it
/// accessible through the portal from any machine on the network while
/// keeping authentication enforced at the portal level.
///
/// Path rewriting strategy
/// ──────────────────────
/// Timesketch generates root-relative asset/API URLs (e.g. `/dist/…`,
/// `/api/v1/…`).  Without rewriting, those are fetched from the portal
/// origin at the wrong path.  We handle this in two ways:
///
///   1. HTML responses  – regex-rewrite every root-relative URL found in
///      HTML attributes (src=, href=, action=, …) and inject a tiny
///      fetch/XHR interceptor so that JavaScript API calls are also
///      redirected through the proxy prefix at runtime.
///
///   2. CSS responses   – rewrite url(/…) references.
///
///   3. Redirect headers – rewrite Location: headers (both 3xx redirects
///      and the Refresh header) so the browser stays within the proxy
///      mount point.
use axum::{
    extract::Request,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use regex::Regex;
use reqwest::Client;
use std::sync::{Arc, OnceLock};

use crate::auth::middleware::{AppState, AuthUser};

const TIMESKETCH_UPSTREAM: &str = "http://127.0.0.1:80";
const PROXY_PREFIX: &str = "/tools/timesketch";

// ── Shared HTTP client ───────────────────────────────────────────────────────
// Redirects are disabled so we can rewrite Location before the browser follows.
static CLIENT: OnceLock<Client> = OnceLock::new();

fn client() -> &'static Client {
    CLIENT.get_or_init(|| {
        Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .expect("Failed to build Timesketch proxy client")
    })
}

// ── Compiled regexes (initialised once) ─────────────────────────────────────

/// Matches root-relative URLs in HTML attribute values:
///   src="/…"   href="/…"   action="/…"   data-url="/…"   content="/…"
/// Group 1 = attribute + opening quote, group 2 = the path starting with /
static HTML_ATTR_RE: OnceLock<Regex> = OnceLock::new();

/// Matches CSS url(/…) references.
static CSS_URL_RE: OnceLock<Regex> = OnceLock::new();

fn html_attr_re() -> &'static Regex {
    HTML_ATTR_RE.get_or_init(|| {
        Regex::new(r#"((?:src|href|action|data-url|content)=")(\/[^/"'][^"]*)"#).unwrap()
    })
}

fn css_url_re() -> &'static Regex {
    CSS_URL_RE.get_or_init(|| {
        Regex::new(r"url\((\/[^/)'][^)]*)\)").unwrap()
    })
}

// ── Router ───────────────────────────────────────────────────────────────────

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // Bare path – redirect to trailing slash so relative assets resolve.
        .route(
            "/tools/timesketch",
            any(|| async { axum::response::Redirect::to("/tools/timesketch/") }),
        )
        .route("/tools/timesketch/", any(proxy_handler))
        .route("/tools/timesketch/{*path}", any(proxy_handler))
}

// ── Proxy handler ────────────────────────────────────────────────────────────

async fn proxy_handler(
    // Require the user to be authenticated before proxying.
    _auth: AuthUser,
    req: Request,
) -> Response {
    let req_path = req.uri().path().to_owned();
    let req_query = req.uri().query().map(|q| q.to_owned());

    // Strip the portal prefix so the upstream receives a clean path.
    let upstream_path = req_path
        .strip_prefix(PROXY_PREFIX)
        .filter(|p| !p.is_empty())
        .unwrap_or("/");

    let upstream_url = match &req_query {
        Some(q) => format!("{TIMESKETCH_UPSTREAM}{upstream_path}?{q}"),
        None => format!("{TIMESKETCH_UPSTREAM}{upstream_path}"),
    };

    // Convert axum Method → reqwest Method.
    let method = match reqwest::Method::from_bytes(req.method().as_str().as_bytes()) {
        Ok(m) => m,
        Err(_) => reqwest::Method::GET,
    };

    let (parts, body) = req.into_parts();

    // Read request body – cap at 32 MB to avoid memory exhaustion.
    let body_bytes = axum::body::to_bytes(body, 32 * 1024 * 1024)
        .await
        .unwrap_or_default();

    // Build forwarded headers – drop hop-by-hop headers (RFC 7230 §6.1).
    let mut fwd_headers = reqwest::header::HeaderMap::new();
    for (name, value) in &parts.headers {
        match name.as_str().to_lowercase().as_str() {
            "host"
            | "connection"
            | "transfer-encoding"
            | "upgrade"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "te"
            | "trailers"
            | "keep-alive" => continue,
            _ => {}
        }
        if let Ok(rname) = reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()) {
            if let Ok(rval) = reqwest::header::HeaderValue::from_bytes(value.as_bytes()) {
                fwd_headers.append(rname, rval);
            }
        }
    }
    // Tell Timesketch the canonical host so its cookies/CSP are set correctly.
    fwd_headers.insert(
        reqwest::header::HOST,
        reqwest::header::HeaderValue::from_static("127.0.0.1"),
    );

    // ── Send upstream ────────────────────────────────────────────────────────
    let upstream_resp = match client()
        .request(method, &upstream_url)
        .headers(fwd_headers)
        .body(body_bytes.to_vec())
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Timesketch proxy error: {e}");
            return (
                StatusCode::BAD_GATEWAY,
                "Timesketch is unavailable. Is the container running?",
            )
                .into_response();
        }
    };

    let status =
        StatusCode::from_u16(upstream_resp.status().as_u16()).unwrap_or(StatusCode::OK);

    // Capture content-type before consuming headers iterator.
    let content_type = upstream_resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();

    // ── Build response headers ───────────────────────────────────────────────
    let mut resp_headers = HeaderMap::new();
    for (name, value) in upstream_resp.headers() {
        match name.as_str().to_lowercase().as_str() {
            // Drop hop-by-hop response headers.
            "connection" | "transfer-encoding" | "keep-alive" => continue,

            // Rewrite redirect targets.
            "location" => {
                let rewritten = value
                    .to_str()
                    .map(rewrite_location)
                    .unwrap_or_default();
                if let Ok(v) = HeaderValue::from_str(&rewritten) {
                    resp_headers.insert(axum::http::header::LOCATION, v);
                }
                continue;
            }

            // Refresh: 0; url=/login/ – same treatment as Location.
            "refresh" => {
                if let Ok(s) = value.to_str() {
                    let rewritten = rewrite_refresh(s);
                    if let Ok(v) = HeaderValue::from_str(&rewritten) {
                        resp_headers.insert(
                            axum::http::HeaderName::from_static("refresh"),
                            v,
                        );
                    }
                }
                continue;
            }

            // Remove content-length – body size may change after rewriting.
            "content-length" => continue,

            _ => {}
        }
        if let Ok(hname) = axum::http::HeaderName::from_bytes(name.as_str().as_bytes()) {
            if let Ok(hval) = HeaderValue::from_bytes(value.as_bytes()) {
                resp_headers.append(hname, hval);
            }
        }
    }

    // ── Rewrite response body ────────────────────────────────────────────────
    let raw_bytes = upstream_resp.bytes().await.unwrap_or_default();

    let final_body: Vec<u8> = if content_type.contains("text/html") {
        let html = String::from_utf8_lossy(&raw_bytes);
        rewrite_html(&html).into_bytes()
    } else if content_type.contains("text/css") {
        let css = String::from_utf8_lossy(&raw_bytes);
        rewrite_css(&css).into_bytes()
    } else {
        raw_bytes.to_vec()
    };

    (status, resp_headers, final_body).into_response()
}

// ── Body rewriting ───────────────────────────────────────────────────────────

/// Rewrite root-relative URLs in HTML attributes and inject a small
/// fetch/XHR interceptor so that JavaScript API calls are also proxied.
fn rewrite_html(html: &str) -> String {
    // 1. Rewrite URLs in HTML attributes.
    let rewritten = html_attr_re().replace_all(html, |caps: &regex::Captures| {
        format!("{}{}{}", &caps[1], PROXY_PREFIX, &caps[2])
    });

    // 2. Inject a combined bootstrap script as the FIRST child of <head>.
    //
    //    It does three things, all before any application JS runs:
    //
    //    a) History virtualisation – strips the proxy prefix from the current
    //       URL so Vue Router (compiled with base '/') sees the real app path,
    //       then patches pushState/replaceState so every navigation Vue does is
    //       transparently re-prefixed for the browser's address bar.
    //
    //    b) fetch() patch – prepends the proxy prefix to every root-relative
    //       URL that application code passes to the Fetch API.
    //
    //    c) XHR patch – same for XMLHttpRequest.open().
    let interceptor = format!(
        r#"<script>
(function(){{
  var P='{PROXY_PREFIX}';

  /* ── a) Vue Router / history virtualisation ──────────────────────── */
  var curPath = window.location.pathname;
  if(curPath.startsWith(P)){{
    // Strip prefix before Vue Router reads window.location.pathname
    var stripped = curPath.slice(P.length)||'/';
    window.history.replaceState(
      window.history.state, document.title,
      stripped + window.location.search + window.location.hash
    );
  }}
  var _pushState    = window.history.pushState.bind(window.history);
  var _replaceState = window.history.replaceState.bind(window.history);
  function rePrefix(url){{
    if(typeof url==='string'&&url.startsWith('/')&&!url.startsWith('//')&&!url.startsWith(P))
      return P+url;
    return url;
  }}
  window.history.pushState=function(s,t,url){{
    return _pushState(s,t,rePrefix(url));
  }};
  window.history.replaceState=function(s,t,url){{
    return _replaceState(s,t,rePrefix(url));
  }};
  // popstate fires with the real (prefixed) URL already set; strip again
  // so Vue Router popstate handler sees the un-prefixed path.
  window.addEventListener('popstate',function(e){{
    var p=window.location.pathname;
    if(p.startsWith(P)){{
      _replaceState(e.state,document.title,
        p.slice(P.length)||'/' + window.location.search + window.location.hash);
    }}
  }},true);

  /* ── b) fetch patch ─────────────────────────────────────────────── */
  function fixUrl(u){{
    if(typeof u==='string'&&u.startsWith('/')&&!u.startsWith('//')&&!u.startsWith(P))
      return P+u;
    return u;
  }}
  var oFetch=window.fetch;
  window.fetch=function(input,init){{
    return oFetch(typeof input==='string'?fixUrl(input):input,init);
  }};

  /* ── c) XHR patch ───────────────────────────────────────────────── */
  var oOpen=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(method,url){{
    var args=Array.prototype.slice.call(arguments);
    args[1]=fixUrl(url);
    return oOpen.apply(this,args);
  }};
}})();
</script>"#
    );

    // Inject as the very first element inside <head> so it executes
    // before any other script, including deferred bundles.
    let with_interceptor = if let Some(pos) = rewritten.find("<head>") {
        let insert_at = pos + "<head>".len();
        format!("{}{}{}", &rewritten[..insert_at], interceptor, &rewritten[insert_at..])
    } else {
        // Fallback: insert before </head>
        rewritten.replacen("</head>", &format!("{interceptor}</head>"), 1)
    };
    with_interceptor
}

/// Rewrite url(/…) references in CSS.
fn rewrite_css(css: &str) -> String {
    css_url_re()
        .replace_all(css, |caps: &regex::Captures| {
            format!("url({}{})", PROXY_PREFIX, &caps[1])
        })
        .into_owned()
}

// ── Header rewriting ─────────────────────────────────────────────────────────

/// Rewrite a `Location` header value so redirects stay within the proxy.
fn rewrite_location(loc: &str) -> String {
    for prefix in &[
        "http://127.0.0.1:80",
        "http://127.0.0.1",
        "http://localhost:80",
        "http://localhost",
    ] {
        if let Some(rest) = loc.strip_prefix(prefix) {
            let path = if rest.is_empty() { "/" } else { rest };
            return format!("{PROXY_PREFIX}{path}");
        }
    }
    if loc.starts_with('/') && !loc.starts_with(PROXY_PREFIX) {
        return format!("{PROXY_PREFIX}{loc}");
    }
    loc.to_string()
}

/// Rewrite `Refresh: <n>; url=<path>` headers.
fn rewrite_refresh(refresh: &str) -> String {
    // Format: "0; url=/login/"  or  "0; URL=/login/"
    if let Some(url_pos) = refresh.to_lowercase().find("url=") {
        let (prefix, rest) = refresh.split_at(url_pos + 4); // keep "url="
        return format!("{prefix}{}", rewrite_location(rest));
    }
    refresh.to_string()
}
