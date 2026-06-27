
use opentelemetry::KeyValue;
use axum::{middleware::Next, extract::State, extract::MatchedPath};
use opentelemetry::metrics::{Meter, Histogram, UpDownCounter};
use std::{time::Instant, sync::Arc};
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use opentelemetry::Context;


use opentelemetry_semantic_conventions::{
    metric::{
        HTTP_SERVER_REQUEST_DURATION, 
        HTTP_SERVER_ACTIVE_REQUESTS, 
        HTTP_SERVER_REQUEST_BODY_SIZE, 
        HTTP_SERVER_RESPONSE_BODY_SIZE
    },
    attribute::{
        HTTP_REQUEST_METHOD,
        HTTP_RESPONSE_STATUS_CODE,
        HTTP_ROUTE,
        NETWORK_PROTOCOL_NAME,
        NETWORK_PROTOCOL_VERSION,
        URL_SCHEME,
        //ERROR_TYPE,
        //SERVER_ADDRESS,
        //SERVER_PORT,
    },
};

use crate::AppState;


pub fn with_exemplar<R>(f: impl FnOnce() -> R) -> R {
    let cx: Context = Span::current().context();
    let _guard = cx.attach();
    f()
}

#[derive(Debug)]
pub struct Metrics {
    pub http_req_duration: Histogram<f64>,   
    pub http_active_requests: UpDownCounter<i64>,
    pub http_request_body_size: Histogram<u64>,
    pub http_response_body_size: Histogram<u64>,

}

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
            KeyValue::new(HTTP_REQUEST_METHOD, method.to_owned()),
            KeyValue::new(URL_SCHEME, scheme.to_owned()),
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
    let scheme_str = req.uri().scheme_str().unwrap_or("http").to_string();
    let _inflight = InFlightGuard::new(state.metrics.http_active_requests.clone(), req.method().as_str(), &scheme_str);

    let method = req.method().to_string();
    let route = req.extensions().get::<MatchedPath>()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_else(|| req.uri().path().to_owned());
    let start = Instant::now();

    use axum::http::{Version, header::CONTENT_LENGTH};

    let req_size = req.headers().get(CONTENT_LENGTH).and_then(|s| s.to_str().ok()).and_then(|s| s.parse().ok());

    let protocol_version = match req.version() {
        Version::HTTP_09 => "0.9",
        Version::HTTP_10 => "1.0",
        Version::HTTP_11 => "1.1",
        Version::HTTP_2  => "2",
        Version::HTTP_3  => "3",
        _ => "unknown",
    };

    let res = next.run(req).await;

    let attrs = {
        let mut attrs = vec![
            KeyValue::new(HTTP_REQUEST_METHOD, method.clone()),
            KeyValue::new(HTTP_ROUTE, route.clone()),
            KeyValue::new(HTTP_RESPONSE_STATUS_CODE, res.status().as_u16() as i64),
            KeyValue::new(NETWORK_PROTOCOL_NAME, "http"),
            KeyValue::new(NETWORK_PROTOCOL_VERSION, protocol_version),
            KeyValue::new(URL_SCHEME, scheme_str)
        ];
        // if false {
        //     attrs.push(KeyValue::new(ERROR_TYPE), "error");
        // }

        attrs
    };

    with_exemplar(|| {
        state.metrics.http_req_duration.record(start.elapsed().as_secs_f64(), &attrs);
        if let Some(n) = req_size {
            state.metrics.http_request_body_size.record(n, &attrs);
        }
        if let Some(n) = res.headers().get(CONTENT_LENGTH).and_then(|s| s.to_str().ok()).and_then(|s| s.parse().ok()) {
            state.metrics.http_response_body_size.record(n, &attrs);
        }
    });
    res
}
