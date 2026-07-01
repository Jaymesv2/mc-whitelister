
use opentelemetry::KeyValue;
use axum::{
    http::{Version, header::CONTENT_LENGTH},
    middleware::Next, extract::State, 
    extract::MatchedPath
};

use opentelemetry::metrics::{Meter, Counter, Histogram, UpDownCounter};
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
    pub http_server: HttpServerMetrics,
    pub permission_sync_entities: Counter<u64>,
}

#[derive(Debug)]
pub struct HttpServerMetrics {
    pub request_duration: Histogram<f64>,   
    pub active_requests: UpDownCounter<i64>,
    pub request_body_size: Histogram<u64>,
    pub response_body_size: Histogram<u64>,
}
impl Metrics {
    pub fn new(meter: Meter) -> Self {
        Self {
            http_server: HttpServerMetrics::new(meter.clone()),
            permission_sync_entities: meter
                .u64_counter("permission.sync.entities")
                .with_unit("{entity}")
                .build(),
        }
    }
}


impl HttpServerMetrics {
    pub fn new(meter: Meter) -> Self {
        Self {
            request_duration: meter
                .f64_histogram(HTTP_SERVER_REQUEST_DURATION)
                .with_unit("s")
                // explicit latency buckets — the thing the MetricsLayer couldn't give you
                .with_boundaries(vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0])
                .build(),
            active_requests: meter
                .i64_up_down_counter(HTTP_SERVER_ACTIVE_REQUESTS)
                // .with_unit("")
                .build(),
            request_body_size: meter
                .u64_histogram(HTTP_SERVER_REQUEST_BODY_SIZE)
                .with_unit("by")
                .build(),
            response_body_size: meter
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
    let _inflight = InFlightGuard::new(state.metrics.http_server.active_requests.clone(), req.method().as_str(), &scheme_str);

    let method = req.method().to_string();
    let route = req.extensions().get::<MatchedPath>()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_else(|| req.uri().path().to_owned());
    let start = Instant::now();

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
        state.metrics.http_server.request_duration.record(start.elapsed().as_secs_f64(), &attrs);
        if let Some(n) = req_size {
            state.metrics.http_server.request_body_size.record(n, &attrs);
        }
        if let Some(n) = res.headers().get(CONTENT_LENGTH).and_then(|s| s.to_str().ok()).and_then(|s| s.parse().ok()) {
            state.metrics.http_server.response_body_size.record(n, &attrs);
        }
    });
    res
}



pub mod client_middleware {
    pub const AUTHENTIK_PATHS: &[&str] = &include!(concat!(env!("OUT_DIR"), "/authentik_paths"));
    pub const LUCKPERMS_PATHS: &[&str] = &include!(concat!(env!("OUT_DIR"), "/luckperms_paths"));
    pub const ALL_PATHS: &[&str] = constcat::concat_slices!( [&str]: AUTHENTIK_PATHS, LUCKPERMS_PATHS);

    use reqwest_middleware::Result;
    use http::Extensions;
    use reqwest::{Request, Response};
    use reqwest_middleware::ClientBuilder;
    use reqwest_tracing::{
        default_on_request_end, reqwest_otel_span, ReqwestOtelSpanBackend, TracingMiddleware,
        default_span_name,
    };
    use tracing::Span;
    use std::time::{Duration, Instant};
    use opentelemetry::KeyValue;
    use opentelemetry::metrics::{Meter, Histogram, UpDownCounter};
    

    use opentelemetry_semantic_conventions::{
        attribute::{
            HTTP_REQUEST_METHOD,
            HTTP_RESPONSE_STATUS_CODE,
            HTTP_ROUTE,
            URL_TEMPLATE,
            SERVER_PORT,
            SERVER_ADDRESS,
            NETWORK_PROTOCOL_NAME,
            NETWORK_PROTOCOL_VERSION,
            URL_SCHEME,
        },
        metric::{
            HTTP_CLIENT_ACTIVE_REQUESTS,
            HTTP_CLIENT_REQUEST_BODY_SIZE,
            HTTP_CLIENT_REQUEST_DURATION,
            HTTP_CLIENT_RESPONSE_BODY_SIZE
            
            // these need to be added at a lower layer
            // HTTP_CLIENT_CONNECTION_DURATION,
            // HTTP_CLIENT_OPEN_CONNECTIONS,
        }
    };
    
    // maybe this should be in an ARC but i'm assuming the requests don't get cloned too often
    // within reqwest
    #[derive(Clone)]
    pub struct ClientMeters {
        pub request_body_size: Histogram<u64>,
        pub response_body_size: Histogram<u64>,
        pub request_duration: Histogram<f64>,
        pub active_requests: UpDownCounter<i64>,
    }
    impl ClientMeters {
        pub fn new(meter: Meter) -> Self {
            Self {
                request_duration: meter
                    .f64_histogram(HTTP_CLIENT_REQUEST_DURATION)
                    .with_unit("s")
                    // explicit latency buckets — the thing the MetricsLayer couldn't give you
                    .with_boundaries(vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0])
                    .build(),
                request_body_size: meter
                    .u64_histogram(HTTP_CLIENT_REQUEST_BODY_SIZE)
                    .with_unit("by")
                    .build(),
                response_body_size: meter
                    .u64_histogram(HTTP_CLIENT_RESPONSE_BODY_SIZE)
                    .with_unit("by")
                    .build(),
                active_requests: meter
                    .i64_up_down_counter(HTTP_CLIENT_ACTIVE_REQUESTS)
                    .build(),
            }
        }
    }


    fn http_client_attrs_from_req(req: &Request, matcher: &Option<&reqwest_tracing::OtelPathNames>) -> Vec<KeyValue> {
        let mut attrs = vec![
            KeyValue::new(HTTP_REQUEST_METHOD, req.method().as_str().to_owned()),
            KeyValue::new(URL_SCHEME, req.url().scheme().to_owned()),
        ];

        let protocol_version = match req.version() {
            http::Version::HTTP_09 => Some("0.9"),
            http::Version::HTTP_10 => Some("1.0"),
            http::Version::HTTP_11 => Some("1.1"),
            http::Version::HTTP_2  => Some("2"),
            http::Version::HTTP_3  => Some("3"),
            _ => None,
        };

        if let Some(s) = protocol_version {
            attrs.push(KeyValue::new(NETWORK_PROTOCOL_VERSION, s.to_owned()));
        }

        // NETWORK_PROTOCOL_NAME
        // NETWORK_PROTOCOL_VERSION
        if let Some(s) = req.url().port_or_known_default() {
            attrs.push(KeyValue::new(SERVER_PORT, s as i64));
        }
        if let Some(s) = req.url().host_str() {
            attrs.push(KeyValue::new(SERVER_ADDRESS, s.to_owned()));
        }
        if let Some(matcher) = matcher && let Some(s) = matcher.find(req.url().path()) {
            attrs.push(KeyValue::new(URL_TEMPLATE, s.to_owned()))
        }
        attrs
    }

    // increments the updown counter when the request is started and decrements when dropped
    struct InFlightGuard(UpDownCounter<i64>, Vec<KeyValue>);

    impl InFlightGuard {
        fn new(metric: UpDownCounter<i64>, attrs: Vec<KeyValue>) -> Self {
            metric.add(1, &attrs);
            Self(metric, attrs)
        }
    }
    impl Drop for InFlightGuard {
        fn drop(&mut self) {
            self.0.add(-1, &self.1); // or capture the handle
        }
    }

    // use reqwest::{Client, Request, Response};
    // use reqwest_middleware::{ClientBuilder, Middleware, Next, Result, Extension};
    // use http::Extensions;

    // #[derive(Clone)]
    // struct LogName(&'static str);
    pub struct MetricsMiddleware {
        meters: ClientMeters
    }

    impl MetricsMiddleware {
        pub fn new(meter: Meter) -> Self {
            Self {
                meters: ClientMeters::new(meter)
            }
        }
    }


    #[async_trait::async_trait]
    impl reqwest_middleware::Middleware for MetricsMiddleware {
        async fn handle(
            &self,
            req: Request,
            ext: &mut Extensions,
            next: reqwest_middleware::Next<'_>,
        ) -> Result<Response> {
            let meters = &self.meters;
            let known_paths = ext.get::<reqwest_tracing::OtelPathNames>();

            let mut attrs = http_client_attrs_from_req(&req, &known_paths);
            let _guard = InFlightGuard::new(meters.active_requests.clone(), attrs.clone());

            // let meters = ext.get::<ClientMeters>().unwrap();
            


            let inst = Instant::now();
            let res = next.run(req, ext).await;

            let time_elapsed = inst.elapsed().as_secs_f64();

            if let Ok(ref s) = res {
                attrs.push(KeyValue::new(HTTP_RESPONSE_STATUS_CODE, s.status().as_str().to_owned() ));
            }

            super::with_exemplar(|| {
                meters.request_duration.record(time_elapsed, &attrs);
                // if let Some(n) = req_size {
                //     state.metrics.http_request_body_size.record(n, &attrs);
                // }
                // if let Some(n) = res.headers().get(CONTENT_LENGTH).and_then(|s| s.to_str().ok()).and_then(|s| s.parse().ok()) {
                //     state.metrics.http_response_body_size.record(n, &attrs);
                // }
            });
            res
            //
            // // ext.insert(Instant::now());
            //
            // let name = default_span_name(req, ext);
            // reqwest_otel_span!(name=name, req, time_elapsed = tracing::field::Empty)
        }
    }









    // pub struct MetricTimeTrace;

    // impl ReqwestOtelSpanBackend for MetricTimeTrace {
    //     fn on_request_start(req: &Request, ext: &mut Extensions) -> Span {
    //         let known_paths = ext.get::<reqwest_tracing::OtelPathNames>().unwrap();
    //         let meters = ext.get::<ClientMeters>().unwrap();
    //
    //
    //         
    //         let attrs = http_client_attrs_from_req(&req, &known_paths);
    //
    //         ext.insert(std::sync::Arc::new(InFlightGuard::new(meters.active_requests.clone(), attrs.clone())));
    //         ext.insert(Instant::now());
    //         ext.insert(attrs);
    //
    //         let name = default_span_name(req, ext);
    //         reqwest_otel_span!(name=name, req, time_elapsed = tracing::field::Empty)
    //     }
    //
    //     fn on_request_end(span: &Span, outcome: &Result<Response>, ext: &mut Extensions) {
    //         let mut attrs = ext.remove::<Vec<KeyValue>>().unwrap();
    //         let meters = ext.get::<ClientMeters>().unwrap();
    //         let time_elapsed = ext.get::<Instant>().unwrap().elapsed().as_secs_f64();
    //
    //         if let Ok(s) = outcome {
    //             attrs.push(KeyValue::new(HTTP_RESPONSE_STATUS_CODE, s.status().as_str().to_owned() ));
    //         }
    //
    //         default_on_request_end(span, outcome);
    //
    //         super::with_exemplar(|| {
    //             meters.request_duration.record(time_elapsed, &attrs);
    //             // if let Some(n) = req_size {
    //             //     state.metrics.http_request_body_size.record(n, &attrs);
    //             // }
    //             // if let Some(n) = res.headers().get(CONTENT_LENGTH).and_then(|s| s.to_str().ok()).and_then(|s| s.parse().ok()) {
    //             //     state.metrics.http_response_body_size.record(n, &attrs);
    //             // }
    //         });
    //     }
    // }

    // let http = ClientBuilder::new(reqwest::Client::new())
    //     .with(TracingMiddleware::<TimeTrace>::new())
    //     .build();
    // }

    // use reqwest::{Client, Request, Response};
    // use reqwest_middleware::{ClientBuilder, Middleware, Next, Result};
}



