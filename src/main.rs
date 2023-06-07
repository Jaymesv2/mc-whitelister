use axum::{routing::*, Router};

use lazy_static::lazy_static;
use tracing::*;

use axum_sessions::{PersistencePolicy, SameSite, SessionLayer};

use mc_whitelister::{
    routes::{index::*, microsoft, oauth},
    *,
};
use rand::Rng;
use std::{sync::Arc, time::Duration};
use tera::Tera;

lazy_static!{
    pub static ref TEMPLATES: Tera = {
        let mut tera = match tera::Tera::new("templates/**/*") {
            Ok(s) => s,
            Err(e) => {
                error!("failed to load templates: {e}");
                panic!("failed to load templates: {e}");
            }
        };
        tera.autoescape_on(vec![".html", ".sql"]);
        tera
    };
}



#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    tracing_subscriber::fmt::init();

    let config = match envy::from_env::<Config>() {
        Ok(config) => config,
        Err(error) => panic!("{:#?}", error),
    };
    debug!("loaded app config: {config:?}");

    debug!("connecting to db");
    let pool = sqlx::mysql::MySqlPool::connect_with(
        sqlx::mysql::MySqlConnectOptions::new()
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
        .expect("failed to run migrations");

    let redis_conn_info = redis::ConnectionInfo {
        addr: Box::new(redis::ConnectionAddr::Tcp("localhost".to_string(), 6379)),
        db: 0,
        username: None,
        passwd: None,
    };
    let redis = redis::Client::open(redis_conn_info).expect("failed to connect to redis");

    let store = async_redis_session::RedisSessionStore::from_client(redis);

    let bind_addr = config.bind_addr;

    //let store = MemoryStore::new();
    let secret = if let Some(s) = &config.session_secret {

        s.as_bytes()
    } else {
        warn!("using random session secret");
        // This value lives the entire lifetime of the program so its fine to leak it.
        Box::leak(Box::new(rand::thread_rng().gen::<[u8; 128]>()))
    };
    let session_layer = SessionLayer::new(store, &secret)
        .with_secure(false)
        .with_cookie_name("session")
        //.with_cookie_path("/some/path")
        //.with_cookie_domain("www.example.com")
        .with_same_site_policy(SameSite::Lax)
        .with_session_ttl(Some(Duration::from_secs(60 * 5)))
        .with_persistence_policy(PersistencePolicy::Always);

    let state = Arc::new(AppState { config, pool, tera: TEMPLATES.clone() });

    let app = Router::new()
        .route("/", get(index))
        .route("/login", get(oauth::login))
        .route("/oauth/redirect", get(oauth::redirect))
        //.route("/userinfo", get(oauth::userinfo))
        .route("/oauth/microsoft/redirect", get(microsoft::redirect))
        .route("/oauth/microsoft", get(microsoft::login))
        .route("/update_mc_profile", get(microsoft::update_mc_profile))
        .layer(session_layer)
        .with_state(state);

    info!("listening on {bind_addr}");

    axum::Server::bind(&bind_addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
