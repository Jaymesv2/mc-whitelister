
//use axum::*
use crate::*;
use axum::{
    extract::State,
    response::Redirect,
};
use axum_sessions::extractors::WritableSession;
use std::sync::Arc;

pub async fn logout(mut session: WritableSession, State(app_state): State<Arc<AppState>>) -> Redirect {
    session.destroy();
    Redirect::to(app_state.config.oauth_logout_url.as_str())
}
