pub mod config;
pub mod db;
pub mod ms_api;
pub mod reconcile;
pub mod routes;
pub mod session;

use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
pub use config::*;
use std::pin::Pin;
use thiserror::Error;
// use axum::
use maud::{Markup, html};

use axum::extract::State;
use opentelemetry::metrics::{Meter, Histogram, UpDownCounter};

use std::time::Instant;

// /// Record inside the current tracing span's OTel context so the measurement
// //// picks up a TraceBased exemplar. `f` MUST be synchronous — never await under the guard.
pub fn with_exemplar<R>(f: impl FnOnce() -> R) -> R {
    let cx: Context = Span::current().context();
    let _guard = cx.attach();
    f()
}

use axum::extract::MatchedPath;
use std::sync::Arc;
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use opentelemetry::Context;
// use std::task::Context;
// 
use axum::middleware::Next;
use opentelemetry::KeyValue;

#[derive(Debug)]
pub struct Metrics {
    pub http_req_duration: Histogram<f64>,   
    pub http_active_requests: UpDownCounter<i64>,
    pub http_request_body_size: Histogram<u64>,
    pub http_response_body_size: Histogram<u64>,

}

    use opentelemetry_semantic_conventions::metric::{
        HTTP_SERVER_REQUEST_DURATION, 
        HTTP_SERVER_ACTIVE_REQUESTS, 
        HTTP_SERVER_REQUEST_BODY_SIZE, 
        HTTP_SERVER_RESPONSE_BODY_SIZE
    };

impl Metrics {
    pub fn new(meter: Meter) -> Self {
        Self {
            http_req_duration: meter
                .f64_histogram(HTTP_SERVER_REQUEST_DURATION)
                .with_unit("s")
                // explicit latency buckets — the thing the MetricsLayer couldn't give you
                .with_boundaries(vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0])
                .build(),
            http_active_requests: meter
                .i64_up_down_counter(HTTP_SERVER_ACTIVE_REQUESTS)
                // .with_unit("")
                .build(),
            http_request_body_size: meter
                .u64_histogram(HTTP_SERVER_REQUEST_BODY_SIZE)
                .with_unit("by")
                .build(),
            http_response_body_size: meter
                .u64_histogram(HTTP_SERVER_RESPONSE_BODY_SIZE)
                .with_unit("by")
                .build()
        }

    }
}

struct InFlightGuard(UpDownCounter<i64>, [KeyValue; 2]);

impl InFlightGuard {
    fn new(metric: UpDownCounter<i64>, method: &str, scheme: &str) -> Self {
        let attrs = [
            KeyValue::new("http.request.method", method.to_owned()),
            KeyValue::new("url.scheme", scheme.to_owned()),
        ];
        metric.add(1, &attrs);
        Self(metric, attrs)
    }
}
impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.add(-1, &self.1); // or capture the handle
    }
}

pub async fn metrics_layer(
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
    next: Next
) -> axum::response::Response {
    let _inflight = InFlightGuard::new(state.metrics.http_active_requests.clone(), req.method().as_str(), req.uri().scheme_str().unwrap_or("http"));

    use opentelemetry_semantic_conventions::attribute::{
        HTTP_REQUEST_METHOD,
        HTTP_RESPONSE_STATUS_CODE,
        HTTP_ROUTE,
        //NETWORK_PROTOCOL_NAME,
        //NETWORK_PROTOCOL_VERSION,
        //ERROR_TYPE,
        //URL_SCHEME,
        //SERVER_ADDRESS,
        //SERVER_PORT,
    };

    // use opentelemetry_semantic_conventions::metric::{
    //     HTTP_SERVER_REQUEST_DURATION, 
    //     HTTP_SERVER_ACTIVE_REQUESTS, 
    //     HTTP_SERVER_REQUEST_BODY_SIZE, 
    //     HTTP_SERVER_RESPONSE_BODY_SIZE
    // };
    // {
    //     with_exemplar(|| state.metrics.http_req_duration.record(start.elapsed().as_secs_f64(), &attrs));
    //
    // }
    let method = req.method().to_string();
    let route = req.extensions().get::<MatchedPath>()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_else(|| req.uri().path().to_owned());
    let start = Instant::now();



    let res = next.run(req).await;


    let attrs = [
        KeyValue::new(HTTP_REQUEST_METHOD, method),
        KeyValue::new(HTTP_ROUTE, route),
        KeyValue::new(HTTP_RESPONSE_STATUS_CODE, res.status().as_u16() as i64),
    ];
    // with_exemplar(|| state.metrics.http_request_body_size.record(  ,&attrs))
    // with_exemplar(|| state.metrics.http_response_body_size.record(  ,&attrs))

    with_exemplar(|| state.metrics.http_req_duration.record(start.elapsed().as_secs_f64(), &attrs));
    res
}


#[derive(Debug)]
pub struct AppState {
    pub config: Config,
    pub pool: sqlx::postgres::PgPool,
    pub luckperms: luckperms_api::apis::configuration::Configuration,
    pub authentik: authentik_client::apis::configuration::Configuration,
    pub reconcile_req_sender: tokio::sync::mpsc::Sender<Option<tracing::span::Id>>,
    pub http_client: reqwest_middleware::ClientWithMiddleware,
    pub metrics: Metrics
}




// this represents the top level errors the user may see
#[derive(Debug, Error)]
pub enum AppError {
    #[error("Database error")]
    Database(#[from] sqlx::Error),

    #[error("Other error")]
    Other(#[from] anyhow::Error),

    #[error("Session error")]
    Session(#[from] tower_sessions::session::Error),

    #[error("")]
    Oauth(
        #[from]
        oauth2::RequestTokenError<
            oauth2::HttpClientError<reqwest_middleware::Error>,
            oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
        >,
    ),

    #[error("{0}")]
    InvalidAuthentikToken(&'static str),

    #[error("No oauth exchange data in session")]
    NoOauthExchangeDataInSession,

    #[error("Invalid csrf token")]
    InvalidCSRFToken,
}

fn render_error_page(
    status: StatusCode,
    message: impl AsRef<str>,
    trace_id: Option<impl AsRef<str>>,
) -> Markup {
    crate::routes::index::with_common(
        "Error",
        html! {
            div {
                h1 { (format!("{}", status) ) }
                h2 { (message.as_ref()) }
                @if let Some(trace_id) = trace_id {
                    p { (format!("trace id: {}", trace_id.as_ref()) ) }
                }
                //a ."bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-full" href="/logout" { "Logout" }
            }
        },
    )

    // with_common(
    //     "Accounts",
    //     html! {
    // todo!()
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let trace_id: Option<String> = None;

        let (status_code, message) = match self {
            AppError::Database(err) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{err}")),
            AppError::Other(err) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{err}")),
            AppError::Session(err) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{err}")),
            AppError::NoOauthExchangeDataInSession => (
                StatusCode::FORBIDDEN,
                "No oauth exchange data was present in your session".to_string(),
            ),
            AppError::InvalidCSRFToken => (
                StatusCode::FORBIDDEN,
                format!("{:?}", AppError::InvalidCSRFToken),
            ),
            AppError::Oauth(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")),
            AppError::InvalidAuthentikToken(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Invalid token received from authentik: {e}"),
            ),
        };

        // show the reference id for server errors (where you'd actually go look it up)
        let body = render_error_page(status_code, message, trace_id);

        (status_code, Html(body.into_string())).into_response()
    }
}

pub struct ReqwestClient(pub reqwest_middleware::ClientWithMiddleware);

impl<'c> oauth2::AsyncHttpClient<'c> for ReqwestClient {
    type Error = oauth2::HttpClientError<reqwest_middleware::Error>;
    type Future = Pin<Box<dyn Future<Output = Result<oauth2::HttpResponse, Self::Error>> + Send + 'c>>;

    fn call(&'c self, request: oauth2::HttpRequest) -> Self::Future {
        Box::pin(async move {
            let response = self
                .0
                .execute(request.try_into().map_err(reqwest_middleware::Error::Reqwest).map_err(Box::new)?)
                .await
                .map_err(Box::new)?;

            let mut builder = http::Response::builder().status(response.status());

            for (name, value) in response.headers().iter() {
                builder = builder.header(name, value);
            }

            builder
                .body(response.bytes().await
                    .map_err(reqwest_middleware::Error::Reqwest)
                    .map_err(Box::new)?.to_vec())
                .map_err(oauth2::HttpClientError::Http)
        })
    }
}
