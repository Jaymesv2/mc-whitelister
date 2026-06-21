use crate::*;
use axum::{
    extract::State,
};
use reqwest::StatusCode;
use std::sync::Arc;
use tracing::*;

pub async fn health(
    State(_state): State<Arc<AppState>>
) -> StatusCode {
    debug!("Healthcheck OK");
    StatusCode::OK
}
