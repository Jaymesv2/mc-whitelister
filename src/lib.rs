pub mod config;
pub mod db;
pub mod ms_api;
pub mod reconcile;
pub mod routes;
pub mod session;
pub use config::*;

// use sqlx::mysql::MySqlPool;

#[derive(Debug)]
pub struct AppState {
    pub config: Config,
    pub pool: sqlx::postgres::PgPool,
    pub luckperms: luckperms_api::apis::configuration::Configuration,
    pub authentik: authentik_client::apis::configuration::Configuration,
    pub reconcile_req_sender: tokio::sync::mpsc::Sender<()>,
}
