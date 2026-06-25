use crate::session::*;
use crate::{db::*, *};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use serde::*;
use sqlx::{query, query_as};
use std::sync::Arc;
use tower_sessions::Session;
use tracing::*;

#[derive(Deserialize, Serialize, Debug)]
pub struct RemoveBody {
    pub uuid: String,
}

// TODO: the error handling here needs to be updated.
pub async fn remove(
    session: Session,
    State(app_state): State<Arc<AppState>>,
    Path(uuid): Path<String>,
) -> Result<Response, StatusCode> {
    let Some(user_id): Option<UserID> = session
        .get(UserID::SESSION_KEY)
        .await
        .inspect_err(|e| error!("session error: {e}"))
        .map_err(|_e| StatusCode::INTERNAL_SERVER_ERROR)?
    else {
        return Ok(Redirect::to("/").into_response());
    };

    let mut tx = app_state
        .pool
        .begin()
        .await
        .inspect_err(|e| error!("failed to start transaction: {e}"))
        .map_err(|_e| StatusCode::INTERNAL_SERVER_ERROR)?;

    let accounts = query_as!(
        MinecraftProfile,
        "SELECT * FROM minecraft_profile WHERE user_id = $1;",
        user_id.0
    )
    .fetch_all(&mut *tx)
    .await
    .inspect_err(|e| error!("Failed to get minecraft profiles: {e}"))
    .map_err(|_e| StatusCode::INTERNAL_SERVER_ERROR)?;

    let Some(account_to_remove) = accounts.iter().find(|x| x.uuid == uuid) else {
        return Ok((
            StatusCode::BAD_REQUEST,
            "The provided account uuid is not associated with the current user",
        )
            .into_response());
    };

    query!(
        "DELETE FROM minecraft_profile where uuid = $1;",
        account_to_remove.uuid
    )
    .execute(&mut *tx)
    .await
    .inspect_err(|e| error!("error occurd while executing sql: {e}"))
    .map_err(|_e| StatusCode::INTERNAL_SERVER_ERROR)?;

    tx.commit()
        .await
        .inspect_err(|e| error!("error occured while executing sql: {e}"))
        .map_err(|_e| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(axum::response::Html("").into_response())
}
