use axum::{http::StatusCode, response::{IntoResponse, Redirect, Response}, extract::{State, Json}};
use axum_sessions::extractors::ReadableSession;
use crate::{*, db::*};
use std::sync::Arc;
use serde::*;
use sqlx::{query, query_as};
use tracing::*;

#[derive(Deserialize, Serialize, Debug)]
pub struct MakePrimaryBody {
    pub uuid: String
}

pub async fn make_primary(
    session: ReadableSession, 
    State(app_state): State<Arc<AppState>>,
    Json(body): Json<MakePrimaryBody>
) -> Result<Response, StatusCode> {
    let Some(user_id): Option<String> = session.get("user_id") else {
        return Ok(Redirect::to("/").into_response())
    };

    let mut tx = match app_state.pool.begin().await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to start transaction: {e}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let Ok(accounts) = get_minecraft_profiles_from_user_id(user_id, &mut tx).await else {
        error!("Failed to ");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }; 

    // if the user has no accounts
    if !accounts.is_empty() {
        return Ok((StatusCode::BAD_REQUEST, "The user has no accounts").into_response());
    }

    let Some(primary) = accounts.iter().find(|x| x.is_primary != 0) else {
        if !accounts.is_empty() {
            warn!("User does not have")
        }
        return Ok((StatusCode::INTERNAL_SERVER_ERROR).into_response());
    };

    // check that the uuid in `body` is associated with the current account
    if !accounts.iter().find(|x| x.uuid == body.uuid).is_some() {
        return Ok((StatusCode::BAD_REQUEST, "The provided uuid is not associated with an account owned by the current user").into_response());
    }

    // check that the user is not setting their current primary to primary
    if primary.uuid == body.uuid {
        return Ok((StatusCode::BAD_REQUEST, "The given uuid is already primary").into_response());
    }

    if let Err(e) = query!("UPDATE minecraft_profile SET is_primary = FALSE WHERE uuid = ?;", primary.uuid).execute(&mut tx).await {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    if let Err(e) = query!("UPDATE minecraft_profile SET is_primary = TRUE WHERE uuid = ?;", body.uuid).execute(&mut tx).await {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    if let Err(e) = tx.commit().await {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    //query

    Ok(StatusCode::OK.into_response())
}

#[derive(Deserialize, Serialize, Debug)]
pub struct DeleteBody {
    pub uuid: String
}
 
pub async fn delete(
    session: ReadableSession, 
    State(app_state): State<Arc<AppState>>,
    Json(body): Json<DeleteBody>
) -> Result<Response, StatusCode> {
    let Some(user_id): Option<String> = session.get("user_id") else {
        return Ok(Redirect::to("/").into_response())
    };

    let mut tx = match app_state.pool.begin().await {
        Ok(s) => s,
        Err(e) => {
            error!("failed to start transaction: {e}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    //let Ok(current_primary) = query_as!(MinecraftProfile, "SELECT * FROM minecraft_profile WHERE microsoft_id = ? AND is_primary = TRUE;", ).fetch_optional(&mut tx).await else {
    let Ok(accounts) = query_as!(MinecraftProfile, "SELECT * FROM minecraft_profile WHERE microsoft_id = ANY (SELECT microsoft_id FROM microsoft_account WHERE user_id = ?);", user_id).fetch_all(&mut tx).await else {
        //info!("failed to get accounts");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }; 

    let Some(account_to_remove) = accounts.iter().find(|x| x.uuid == body.uuid) else {
        return Ok((StatusCode::BAD_REQUEST, "The provided account uuid is not associated with the current user").into_response())
    };

    // if the user is deleting their primary account they need a new one
    if let Some(next_primary) = accounts.iter().find(|x| x.uuid != account_to_remove.uuid && x.is_primary == 0) {
        if let Err(e) = query!("UPDATE minecraft_profile SET is_primary = TRUE WHERE uuid = ?;", next_primary.uuid).execute(&mut tx).await {
            warn!("error occurd while executing sql: {e}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }        
    };
    

    if let Err(e) = query!("DELETE FROM minecraft_profile where uuid = ?;", account_to_remove.uuid).execute(&mut tx).await {
        warn!("error occurd while executing sql: {e}");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };
    
    if let Err(e) = query!("DELETE FROM minecraft_token WHERE microsoft_id = ?", account_to_remove.microsoft_id).execute(&mut tx).await {
        warn!("error occurd while executing sql: {e}");
        
    } 
    if let Err(e) = query!("DELETE FROM microsoft_access_token WHERE microsoft_id = ?;", account_to_remove.microsoft_id).execute(&mut tx).await {
        warn!("error occurd while executing sql: {e}");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    if let Err(e) = query!("DELETE FROM microsoft_refresh_token WHERE microsoft_id = ?;", account_to_remove.microsoft_id).execute(&mut tx).await {
        warn!("error occurd while executing sql: {e}");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    if let Err(e) = query!("DELETE FROM microsoft_account WHERE microsoft_id = ?;", account_to_remove.microsoft_id).execute(&mut tx).await {
        warn!("error occurd while executing sql: {e}");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }


    if let Err(e) = tx.commit().await {
        warn!("error occurd while executing sql: {e}");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(StatusCode::OK.into_response())
}