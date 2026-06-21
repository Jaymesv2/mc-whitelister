pub mod config;
pub mod db;
pub mod ms_api;
pub mod routes;
pub mod session;
pub mod reconcile;
pub use config::*;

// use sqlx::mysql::MySqlPool;

#[derive(Debug)]
pub struct AppState {
    pub config: Config,
    pub pool: sqlx::postgres::PgPool,
    pub luckperms: luckperms_api::apis::configuration::Configuration,
    pub authentik: authentik_client::apis::configuration::Configuration,
}
