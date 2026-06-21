use axum::{extract::State, Json};
use std::collections::HashMap;
use axum::http::{StatusCode, HeaderMap};

use crate::AppState;
use std::sync::Arc;
use tracing::*;
use serde::*;

#[derive(Debug, Clone, Serialize)]
struct Account {
    uuid: String,
    username: String,
    user_id: String
}

#[derive(Debug, Clone, Serialize)]
pub struct ResponseAccount {
    uuid: String,
    username: String
}


pub async fn all_users(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>
) -> Result<Json<HashMap<String,Vec<ResponseAccount>>>, StatusCode> {
    // peak auth logic going on here

    // only ascii auth headers, i dont want to deal with random bytes
    let Some(token) = headers.get("Authorization").and_then(|x| x.to_str().ok()) else {
        return Err(StatusCode::FORBIDDEN)
    };

    if token != format!("Bearer: {}", state.config.reconciler_api_key) {
        return Err(StatusCode::FORBIDDEN)
    }


    let Ok(mut conn) = state.pool.acquire().await else {
        error!("failed to aquire db connection");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };

    let accounts: Vec<Account> = match sqlx::query_as!(
            Account,
            "SELECT user_id, username, uuid FROM minecraft_profile"
        )
        .fetch_all(&mut *conn)
        .await {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to get user accounts: {e:?}");
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };
    let mut resp: HashMap<String, Vec<ResponseAccount>> = HashMap::new();
    for i in accounts {
        resp.entry(i.user_id).or_insert( vec![] ).push(ResponseAccount {
            uuid: i.uuid,
            username: i.username
        });
    }

    Ok(Json(resp))
    // Ok(axum::response::Html(main_page(account, accounts).into_string()).into_response())
}  
