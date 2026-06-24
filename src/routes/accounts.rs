use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
// use axum_sessions::extractors::ReadableSession;
use crate::session::*;
use crate::{db::*, *};
use serde::*;
use sqlx::{query, query_as};
use std::sync::Arc;
use tracing::*;
// use crate::AppError;
use tower_sessions::Session;

// #[derive(Deserialize, Serialize, Debug)]
// pub struct MakePrimaryBody {
//     pub uuid: String
// }

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
        .expect("failed to get user id")
    else {
        return Ok(Redirect::to("/").into_response());
    };

    let mut tx = match app_state.pool.begin().await {
        Ok(s) => s,
        Err(e) => {
            error!("failed to start transaction: {e}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let Ok(accounts) = query_as!(
        MinecraftProfile,
        "SELECT * FROM minecraft_profile WHERE user_id = $1;",
        user_id.0
    )
    .fetch_all(&mut *tx)
    .await
    else {
        //info!("failed to get accounts");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };

    let Some(account_to_remove) = accounts.iter().find(|x| x.uuid == uuid) else {
        return Ok((
            StatusCode::BAD_REQUEST,
            "The provided account uuid is not associated with the current user",
        )
            .into_response());
    };

    if let Err(e) = query!(
        "DELETE FROM minecraft_profile where uuid = $1;",
        account_to_remove.uuid
    )
    .execute(&mut *tx)
    .await
    {
        warn!("error occurd while executing sql: {e}");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };

    if let Err(e) = tx.commit().await {
        warn!("error occured while executing sql: {e}");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    Ok(axum::response::Html("").into_response())
    // Ok(StatusCode::OK.into_response())
}
