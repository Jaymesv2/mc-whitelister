use axum::{
    extract::{Query, State},
    http::header::HeaderMap,
    response::{self, IntoResponse, Redirect, Response},
};

use axum_sessions::extractors::{ReadableSession, WritableSession};
use reqwest::StatusCode;
use tracing::*;

use crate::{db::*, *};
use serde::*;
use sqlx::query;
use sqlx::query_as;
use std::sync::Arc;

use oauth2::{AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier};

//type OAuthClient = BasicClient;
use crate::ms_api::*;

pub async fn login(
    mut session: WritableSession,
    State(state): State<Arc<AppState>>,
    _headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let client = get_oauth2_client(&state.config);

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (authorize_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        //XboxLive.signin offline_access User.Read
        .add_scopes(SCOPES.iter().cloned())
        //.set_pkce_challenge(pkce_challenge)
        .url();

    session
        .insert("msgraph_pkce", pkce_verifier)
        .expect("failed to insert pkce into session");

    session
        .insert("msgraph_csrf", csrf_token.secret())
        .expect("failed to insert oauth csrf token into session");

    Ok(Redirect::to(authorize_url.as_ref()))
}

#[derive(Debug, Deserialize)]
pub struct RedirectParams {
    pub code: Option<String>,
    pub error: Option<String>,
    pub state: String,
}

pub async fn redirect(
    mut session: WritableSession,
    State(app_state): State<Arc<AppState>>,
    //_headers: HeaderMap,
    Query(RedirectParams { error, state, code }): Query<RedirectParams>,
) -> Result<Response, StatusCode> {
    let client = get_oauth2_client(&app_state.config);

    let Some(user_id): Option<String> = session.get("user_id") else {
        return Ok(response::Redirect::to("/login").into_response());
    };

    let Some(code) = code else {
        if let Some(e) = error {
            warn!("error occured with msgraph sign in: {e}");
        }
        return Ok(Redirect::to("/").into_response());
    };

    let pkce: PkceCodeVerifier = session
        .get("msgraph_pkce")
        .expect("failed to get msgraph_pkce from session");

    if Some(state) != session.get("msgraph_csrf") {
        error!("Failed to validate csrf");
        return Err(StatusCode::FORBIDDEN);
    }

    let token = match client
        .exchange_code(AuthorizationCode::new(code))
        //.set_pkce_verifier(pkce)
        .request_async(oauth2::reqwest::async_http_client)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            error!("error occured while exchaging token: {e:?}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let microsoft_id = token.extra_fields().user_id.clone();

    let mut tx = match app_state.pool.begin().await {
        Ok(s) => s,
        Err(e) => {
            error!("Error starting transaction {e:?}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    if let Err(e) = query!(
        "INSERT INTO microsoft_account (microsoft_id, user_id) VALUES (?, ?);",
        microsoft_id,
        user_id
    )
    .execute(&mut tx)
    .await
    {
        error!("error occured while inserting into `microsoft_account`: {e:?}");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    //let access_t = token.access_token().secret().clone();

    if let Err(e) = insert_ms_access_token(&mut tx, MicrosoftAccessToken::from(token.clone())).await
    {
        error!("error occured while inserting into `microsoft_account`: {e:?}");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    if let Ok(s) = MicrosoftRefreshToken::try_from(token.clone()) {
        if let Err(e) = insert_ms_refresh_token(&mut tx, s).await {
            error!("error occured while inserting into `microsoft_account`: {e:?}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        };
    }

    if let Err(e) = tx.commit().await {
        error!("Failed to commit to database: {e:?}");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }


    //query

    session.remove("msgraph_pkce");
    session.remove("msgraph_csrf");
    Ok(response::Redirect::to("/update_mc_profile").into_response())
}


pub async fn update_mc_profile(
    session: ReadableSession,
    State(app_state): State<Arc<AppState>>,
) -> Result<Response, StatusCode> {
    
    let Some(user_id): Option<String> = session.get("user_id") else {
        warn!("user id could not be found");
        return Ok(Redirect::to("/").into_response());
    };

    let Ok(mut conn) = app_state.pool.acquire().await else {
        error!("failed to get db conn");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };

    let account = match query_as!(MicrosoftAccount, "SELECT * from microsoft_account WHERE user_id = ?;", user_id).fetch_one(&mut conn).await {
        Ok(s) => s,
        Err(e) => {
            error!("failed to get microsoft account: {e:?}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    //let http_client = reqwest::Client::new();

    if let Err(e) =
    update_mc_profile_from_db(&account.microsoft_id, &mut conn, &app_state.config).await
    {
        error!("Failed to update mc profile: {e:?}");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };

    //Ok(response::Redirect::to("/").into_response())
    Ok("success".into_response())
}