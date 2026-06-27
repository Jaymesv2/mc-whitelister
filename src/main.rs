use axum::{Router, routing::*, extract::MatchedPath, http::Request};

use tower_sessions::{
    SessionManagerLayer,
    cookie::{Key, SameSite},
};
use tracing::*;

use oauth_bridge::{
    routes::{self, index::*},
    *,
};
use rand::Rng;
use std::sync::Arc;
use reqwest_middleware::ClientBuilder;
use reqwest_tracing::TracingMiddleware;



// use axum_tracing_opentelemetry::middleware::{OtelAxumLayer, OtelInResponseLayer};

use tower_sessions::session_store::ExpiredDeletion;
use tower_sessions_sqlx_store::PostgresStore;

use opentelemetry::global;
// use opentelemetry::propagation::Extractor;
use opentelemetry_otlp::ExporterBuildError;

use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::{propagation::TraceContextPropagator, trace::SdkTracerProvider, metrics::SdkMeterProvider};
// use tracing::{error, span};
use tracing_subscriber::layer::SubscriberExt;
use opentelemetry_http::HeaderExtractor;
// use tracing_subscriber::Registry;
//


use tower_http::trace::TraceLayer;
use tracing::{info_span, field};

use tracing_opentelemetry::OpenTelemetrySpanExt;



// use tracing::Span;



async fn setup_telemetry() -> Result<(), ExporterBuildError> {
    let resource = opentelemetry_sdk::Resource::builder().build();

    let otlp_metric_exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .build()?;

    let otlp_trace_exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .build()?;
    // .expect("failed to create otlp span exporter");


    let meter_provider = SdkMeterProvider::builder()
         .with_periodic_exporter(otlp_metric_exporter)
        .with_resource(resource.clone())
        .build();

    // Create a new OpenTelemetry trace pipeline that prints to stdout
    let tracer_provider = SdkTracerProvider::builder()
        .with_batch_exporter(otlp_trace_exporter) // was: with_simple_exporter
        .with_resource(resource)
        // .with_resource(Resource::builder().with_service_name("example").build())
        .build();


    let tracer = tracer_provider.tracer("example");

    global::set_tracer_provider(tracer_provider);

    global::set_text_map_propagator(TraceContextPropagator::new());

    global::set_meter_provider(meter_provider.clone());
    // what does this do??

    let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);

    // Create a tracer provider with the exporter
    // let tracer_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
    //     .with_batch_exporter(otlp_exporter)
    //     .build();

    // // Set it as the global provider
    // global::set_tracer_provider(tracer_provider);

    tracing_subscriber::registry()
        .with(telemetry)
        .with(EnvFilter::from_default_env())
        .with(fmt::layer().with_file(true).with_line_number(true))
        .init();
    Ok(())
}



#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    setup_telemetry().await.expect("failed to setup telemetry");

    let config: Config = match envy::from_env::<Config>() {
        Ok(config) => config,
        Err(error) => panic!("{:#?}", error),
    };

    if config.reconcile_webhook_key.is_none() {
        warn!("RECONCILE_WEBHOOK_KEY was not set, disabling the webhook");
    }

    debug!("loaded app config: {config:?}");

    debug!("connecting to db");

    let pool = sqlx::postgres::PgPool::connect_with(
        sqlx::postgres::PgConnectOptions::new()
            .host(&config.db_host)
            .port(config.db_port)
            .username(&config.db_user)
            .password(&config.db_password)
            .database(&config.db_name),
    )
    .await
    .expect("failed to connect to database");

    sqlx::migrate!()
        .run(&pool)
        .await
        .expect("failed to run database migrations");

    let secret = if let Some(s) = &config.session_secret {
        use base64::{Engine as _, engine::general_purpose};
        general_purpose::STANDARD
            .decode(s)
            .expect("failed to decode secret")
    } else {
        warn!("using random session secret");
        // This value lives the entire lifetime of the program so its fine to leak it.
        let mut l: Vec<u8> = vec![0; 64];
        rand::rng().fill_bytes(l.as_mut_slice());
        l
    };

    let session_store = PostgresStore::new(pool.clone());

    session_store
        .migrate()
        .await
        .expect("failed to apply session store migrations");

    let deletion_task = tokio::task::spawn(
        session_store
            .clone()
            .continuously_delete_expired(tokio::time::Duration::from_secs(60)),
    );

    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(true)
        .with_name("sid")
        .with_same_site(SameSite::None)
        .with_signed(Key::from(secret.as_slice()));

    // this could be a concurrency issue, if there are too many reconcile requests this could
    // bottleneck
    let (tx, rx) = tokio::sync::mpsc::channel(10);

    let meter = global::meter("mc-website");

    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to build requesst http client");

    let known_paths: reqwest_tracing::OtelPathNames = reqwest_tracing::OtelPathNames::known_paths( crate::client_middleware::ALL_PATHS.iter().copied()).expect("Failed to setup client tracing paths");
    let traced_http_client = ClientBuilder::new(http_client.clone())
        .with_init(reqwest_middleware::Extension(known_paths))
        .with(crate::client_middleware::MetricsMiddleware::new(meter.clone()))
        .with(TracingMiddleware::default())
        .build();


    let state = Arc::new(AppState {
        luckperms: {
            let mut cfg = luckperms_api::apis::configuration::Configuration::new();
            cfg.bearer_access_token = Some(config.luckperms_api_key.clone());
            cfg.base_path = config.luckperms_server.clone();
            cfg.client = traced_http_client.clone();
                //http_client.clone().into();
            cfg
        },
        authentik: {
            let mut cfg = authentik_client::apis::configuration::Configuration::new();
            cfg.bearer_access_token = Some(config.authentik_api_key.clone());
            cfg.base_path = config.authentik_server.clone();
            cfg.client = traced_http_client.clone();
                //http_client.clone().into();
            cfg
        },
        reconcile_req_sender: tx,
        config,
        http_client: traced_http_client,
        pool,
        metrics: crate::Metrics::new(meter),
    });

    let reconcile_task = tokio::spawn(reconcile::reconcile_task(state.clone(), rx));

    // includes the file in the binary on release but reads from fs in debug
    macro_rules! static_route {
        ($path:literal, $mimetype:literal) => {
            axum::response::Response::builder()
                .status(axum::http::StatusCode::OK)
                .header("content-type", $mimetype)
                .body(axum::body::Body::from(cfg_select! {
                    debug_assertions => std::fs::read_to_string(concat!("./static/", $path)).expect(concat!("Failed to read \"./static/", $path, "\"")),
                    _ => include_str!(concat!("../static/", $path)),
                }))
                .expect("failed to build response")
        }
    }

    let trace_layer = TraceLayer::new_for_http().make_span_with(|req: &Request<_>| {
        let route = req
            .extensions()
            .get::<MatchedPath>()
            .map(|m| m.as_str())
            .unwrap_or_else(|| req.uri().path())
            .to_owned();

        let span = info_span!(
            "http_request",
            otel.name = field::Empty,
            otel.kind = "server",
            otel.status_code = field::Empty,
            http.request.method = %req.method(),
            http.route = %route,
            http.response.status_code = field::Empty,
        );

        // dynamic, low-cardinality span name like "GET /reconcile/{id}"
        span.record("otel.name", format!("{} {}", req.method(), route).as_str());

        // the actual W3C extraction
        let parent = global::get_text_map_propagator(|prop| {
            prop.extract(&HeaderExtractor(req.headers()))
        });
        
        span.set_parent(parent);

        span
    })
    .on_response(|res: &http::Response<_>, _lat: std::time::Duration, span: &tracing::Span| {
        span.record("http.response.status_code", res.status().as_u16());
        if res.status().is_server_error() {
            span.record("otel.status_code", "ERROR"); // marks the OTel span status as error
        }
    });


    
    let static_router = Router::new()
        .route(
            "/scripts.js",
            get(async || static_route!("scripts.js", "application/javascript")),
        )
        .route(
            "/styles.css",
            get(async || static_route!("styles.css", "text/css")),
        );

    let app = Router::new()
        .route("/", get(index))
        .route("/login", get(routes::oauth::login))
        .route("/logout", get(routes::logout::logout))
        .route("/oauth/redirect", get(routes::oauth::redirect))
        .route(
            "/oauth/microsoft/redirect",
            get(routes::microsoft::redirect),
        )
        .route("/oauth/microsoft", get(routes::microsoft::login))
        .route("/remove/{uuid}", post(routes::accounts::remove))
        .route("/health", get(routes::health::health))
        .route("/reconcile/{id}", post(routes::reconcile::reconcile))
        .route("/reconcile", get(routes::reconcile::reconcile))
        .nest("/static", static_router)
        .layer(session_layer)
        .layer(axum::middleware::from_fn_with_state(state.clone(), crate::metrics_layer))
        .layer(trace_layer)
        .with_state(state);

    let bind_addr = "0.0.0.0:8080";
    info!("listening on {bind_addr}");

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .unwrap_or_else(|_| panic!("failed to bind to {bind_addr}"));

    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal(
            deletion_task.abort_handle(),
            reconcile_task.abort_handle(),
        ))
        .await
        .expect("failed to serve application content");

    deletion_task.await.unwrap().unwrap();
    reconcile_task.await.unwrap();
}
use tokio::task::AbortHandle;

async fn shutdown_signal(
    deletion_task_abort_handle: AbortHandle,
    reconcile_task_abort_handle: AbortHandle,
) {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            deletion_task_abort_handle.abort();
            reconcile_task_abort_handle.abort();
        },
        _ = terminate => {
            deletion_task_abort_handle.abort() ;
            reconcile_task_abort_handle.abort();
        },
    }
}
