use axum::{Router, routing::*};

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

use tower_sessions::session_store::ExpiredDeletion;
use tower_sessions_sqlx_store::PostgresStore;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    tracing_subscriber::registry()
        .with(fmt::layer().with_file(true).with_line_number(true))
        .with(EnvFilter::from_default_env())
        .init();

    let config: Config = match envy::from_env::<Config>() {
        Ok(config) => config,
        Err(error) => panic!("{:#?}", error),
    };

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

    // let state = AppState {
    // };

    sqlx::migrate!()
        .run(&pool)
        .await
        .expect("failed to run database migrations");

    let secret = if let Some(s) = &config.session_secret {
        use base64::{Engine as _, engine::general_purpose};
        // base64::Engine::de
        general_purpose::STANDARD
            .decode(s)
            .expect("failed to decode secret")
        // s.as_bytes()
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

    // .with_expiry(Expiry::OnInactivity(Duration::hours(24)));

    let state = Arc::new(AppState { 
        luckperms: {
            let mut cfg = luckperms_api::apis::configuration::Configuration::new();
            cfg.bearer_access_token = Some(config.luckperms_api_key.clone());
            cfg.base_path = config.luckperms_server.clone();
            cfg
        },
        authentik: {
            let mut cfg = authentik_client::apis::configuration::Configuration::new();
            cfg.bearer_access_token = Some(config.authentik_api_key.clone());
            cfg.base_path = config.authentik_server.clone();
            cfg
        },
        config, 
        pool, 
    });

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
        .route("/oauth/microsoft/redirect", get(routes::microsoft::redirect))
        .route("/oauth/microsoft", get(routes::microsoft::login))
        .route("/remove/{uuid}", post(routes::accounts::remove))
        .route("/health", get(routes::health::health))

        .route("/reconcile", get(routes::reconcile::reconcile))

        .nest("/static", static_router)
        .layer(session_layer)
        .with_state(state);

    let bind_addr = "0.0.0.0:8080";
    info!("listening on {bind_addr}");

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .unwrap_or_else(|_| panic!("failed to bind to {bind_addr}"));

    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal(deletion_task.abort_handle()))
        .await
        .expect("failed to serve application content");

    // deletion_task.await.unwrap().unwrap();
}
use tokio::task::AbortHandle;

async fn shutdown_signal(deletion_task_abort_handle: AbortHandle) {
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
        _ = ctrl_c => { deletion_task_abort_handle.abort() },
        _ = terminate => { deletion_task_abort_handle.abort() },
    }
}
