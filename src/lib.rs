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


use thiserror::Error;
// this represents the top level errors the user may see
#[derive(Debug,Error)]
pub enum AppError {
    #[error("Database error")]
    Database(#[from] sqlx::Error),

    #[error("Other error")]
    Other(#[from] anyhow::Error),

    #[error("Session error")]
    Session(#[from] tower_sessions::session::Error),

    #[error("")]
    Oauth(#[from] oauth2::RequestTokenError<oauth2::HttpClientError<reqwest::Error>, oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>>),
    
    #[error("{0}")]
    InvalidAuthentikToken(&'static str),

    #[error("No oauth exchange data in session")]
    NoOauthExchangeDataInSession,

    #[error("Invalid csrf token")]
    InvalidCSRFToken,
}

use axum::response::{Html, IntoResponse, Response};
use axum::http::StatusCode;
// use tracing_opentelemetry_instrumentation_sdk::find_current_trace_id;

use maud::{Markup, html};


fn render_error_page(status: StatusCode, message: impl AsRef<str>, trace_id: Option<impl AsRef<str>>) -> Markup {
    crate::routes::index::with_common(
        "Error",
        html!{
            div {
                h1 { (format!("{}", status) ) }
                //a ."bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-full" href="/logout" { "Logout" }
            }
        }
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
            AppError::NoOauthExchangeDataInSession => (StatusCode::FORBIDDEN, format!("No oauth exchange data was present in your session")),
            AppError::InvalidCSRFToken => (StatusCode::FORBIDDEN, format!("{:?}", AppError::InvalidCSRFToken)),
            AppError::Oauth(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")),
            AppError::InvalidAuthentikToken(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Invalid token received from authentik: {e}")),
        };

        // show the reference id for server errors (where you'd actually go look it up)
        let body = render_error_page(status_code, message, trace_id);

        (status_code, Html(body.into_string())).into_response()
    }
}
