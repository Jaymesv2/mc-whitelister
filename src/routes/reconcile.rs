use crate::*;
use axum::{
    extract::{Path, State},
    response::{IntoResponse, Response},
};
use reqwest::StatusCode;
use std::sync::Arc;

pub async fn reconcile(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Response, StatusCode> {
    if let Some(reconcile_webhook_key) = &state.config.reconcile_webhook_key
        && *reconcile_webhook_key == id
    {
        state
            .reconcile_req_sender
            .send(tracing::Span::current().id())
            .await
            .expect("reconcile request could not be sent when reconcile task is died");
        Ok(String::from("Ok").into_response())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}
