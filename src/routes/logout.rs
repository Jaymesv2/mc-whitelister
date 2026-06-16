//use axum::*
use crate::*;
use axum::{extract::State, response::Redirect};
// use axum_sessions::extractors::WritableSession;
use std::sync::Arc;
use tower_sessions::Session;

pub async fn logout(session: Session, State(app_state): State<Arc<AppState>>) -> Redirect {
    session.clear().await;
    Redirect::to(app_state.config.oauth_logout_url.as_str())
}
