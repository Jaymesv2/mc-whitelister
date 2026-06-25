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

#[derive(Debug)]
pub struct AppState {
    pub config: Config,
    pub pool: sqlx::postgres::PgPool,
    pub luckperms: luckperms_api::apis::configuration::Configuration,
    pub authentik: authentik_client::apis::configuration::Configuration,
    pub reconcile_req_sender: tokio::sync::mpsc::Sender<Option<tracing::span::Id>>,
    pub http_client: reqwest::Client,
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
            oauth2::HttpClientError<reqwest::Error>,
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
                format!("No oauth exchange data was present in your session"),
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

pub struct ReqwestClient(pub reqwest::Client);

impl<'c> oauth2::AsyncHttpClient<'c> for ReqwestClient {
    type Error = oauth2::HttpClientError<reqwest::Error>;
    type Future =
        Pin<Box<dyn Future<Output = Result<oauth2::HttpResponse, Self::Error>> + Send + Sync + 'c>>;

    fn call(&'c self, request: oauth2::HttpRequest) -> Self::Future {
        Box::pin(async move {
            let response = self
                .0
                .execute(request.try_into().map_err(Box::new)?)
                .await
                .map_err(Box::new)?;

            let mut builder = http::Response::builder().status(response.status());

            for (name, value) in response.headers().iter() {
                builder = builder.header(name, value);
            }

            builder
                .body(response.bytes().await.map_err(Box::new)?.to_vec())
                .map_err(oauth2::HttpClientError::Http)
        })
    }
}
