pub mod config;
pub mod db;
pub mod ms_api;
pub mod routes;
pub mod session;
pub use config::*;

use sqlx::mysql::MySqlPool;
use tera::Tera;

#[derive(Debug)]
pub struct AppState {
    pub config: Config,
    pub pool: MySqlPool,
    pub tera: Tera,
}
