use crate::*;
use axum::{
    extract::{State, Path},
    response::{IntoResponse, Response},
};
use reqwest::StatusCode;
use std::sync::Arc;

pub async fn reconcile(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>
) -> Result<Response, StatusCode> {
    if id != state.config.reconcile_webhook_key {
        return Err(StatusCode::FORBIDDEN);
    }
    crate::reconcile::reconcile_luckperms(&state).await.expect("failed to reconcile");
    Ok(String::from("Ok").into_response())
}


