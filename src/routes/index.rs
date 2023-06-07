//use axum::*
use crate::*;
use axum::{
    extract::State,
    response::{self, IntoResponse, Response},
};
use axum_sessions::extractors::ReadableSession;
use reqwest::StatusCode;
use serde::*;
use sqlx::query_as;
use std::sync::Arc;
use tera::Context;
use tracing::*;

#[derive(Deserialize, Serialize, Debug)]
struct Account {
    image: String,
    username: String,
}

use crate::db::*;


pub async fn index(
    session: ReadableSession,
    State(state): State<Arc<AppState>>,
) -> Result<Response, StatusCode> {
    let Some(user_id): Option<String> = session.get("user_id") else {
        return Ok(response::Redirect::to("/login").into_response());
    };

    let Ok(mut conn) = state.pool.acquire().await else {
        error!("failed to aquire db connection");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };

    let Ok(account) = query_as!(User, "SELECT * FROM user WHERE id = ?", user_id).fetch_one(&mut conn).await else {
        error!("failed to get user account from database");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };

    let accounts: Vec<MicrosoftAccount> = match query_as!(
        MicrosoftAccount,
        "SELECT * FROM microsoft_account WHERE user_id = ?",
        user_id
    )
    .fetch_all(&mut conn)
    .await
    {
        Ok(s) => s,
        Err(e) => {
            error!("failed to get refresh token: {e:?}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let mut ctx = Context::new();

    //let accounts = query_as!(Vec<McAcc>, "");
    ctx.insert("user", &account);
    ctx.insert("accounts", &accounts);

    let cont = match state.tera.render("index.html", &ctx) {
        Ok(s) => s,
        Err(e) => {
            error!("error rendering template: {e:?}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    //ContentType

    Ok(axum::response::Html(cont).into_response())
}

//pub async fn
