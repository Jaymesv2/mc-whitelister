use axum::{
    extract::{Query, State},
    http::header::HeaderMap,
    response::{IntoResponse, Redirect},
};

use chrono::NaiveDateTime;
use reqwest::StatusCode;
use tracing::*;

use axum_sessions::extractors::{ReadableSession, WritableSession};

use crate::*;
use serde::*;
use sqlx::query;
use sqlx::query_as;
use std::sync::Arc;

use oauth2::{
    basic::BasicClient,
    reqwest::async_http_client,
    AccessToken, AuthorizationCode, CsrfToken, 
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse,
};

const OAUTH_REDIRECT_PATH: &str = "/oauth/redirect";

type OAuthClient = BasicClient;

fn get_oauth2_client(conf: &crate::Config) -> OAuthClient {
    let redirect_url = conf
        .host_url
        .join(OAUTH_REDIRECT_PATH)
        .expect("failed to join host url with ms graph redirect path");
    OAuthClient::new(
        conf.oauth_client_id.clone(),
        Some(conf.oauth_client_secret.clone()),
        conf.oauth_auth_url.clone(),
        Some(conf.oauth_token_url.clone()),
    )
    .set_redirect_uri(RedirectUrl::from_url(redirect_url))
}

#[derive(Deserialize, Debug)]
pub struct RedirectParams {
    pub code: String,
    pub state: String,
}

use chrono::naive::serde::ts_seconds;

#[derive(Debug, Deserialize)]
struct TokenInfo {
    sub: String,
    #[serde(with = "ts_seconds")]
    exp: NaiveDateTime,
    #[serde(with = "ts_seconds")]
    iat: NaiveDateTime,
    name: String,
    groups: Vec<String>,
}

fn parse_access_token(token: &str) -> Option<TokenInfo> {
    let t = token.split('.').nth(1)?;
    let mut c = std::io::Cursor::new(t);
    match serde_json::from_reader(base64::read::DecoderReader::new(
        &mut c,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
    )) {
        Ok(s) => Some(s),
        Err(e) => {
            error!("failed to deserialize jwt: {e:?}");
            None
        }
    }
}

pub async fn redirect(
    mut session: WritableSession,
    State(app_state): State<Arc<AppState>>,
    Query(RedirectParams { code, state }): Query<RedirectParams>,
) -> Result<impl IntoResponse, StatusCode> {
    let client = get_oauth2_client(&app_state.config);

    let Some(ver): Option<String> = session.get("oauth_pkce") else {
        error!("failed to find oauth_pkce in session");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };

    if session.get("oauth_csrf") != Some(state) {
        error!("failed to verify csrf token");
        return Err(StatusCode::FORBIDDEN);
    }

    let token_result = client
        .exchange_code(AuthorizationCode::new(code))
        // Set the PKCE code verifier.
        .set_pkce_verifier(PkceCodeVerifier::new(ver))
        .request_async(async_http_client)
        .await
        .expect("failed to exchange code for tokens");

    //error!("{:?}", token_result.extra_fields());

    /*let Ok(userinfo) = get_user_info(&app_state.config, token_result.access_token()).await else{
        error!("failed get user info");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };*/

    let Some(userinfo) = parse_access_token(token_result.access_token().secret()) else {
        error!("failed to parse access token");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };

    let Ok(_) = session.insert("user_id", &userinfo.sub) else {
        error!("failed to insert user id into session");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };


    let mut tx = match app_state.pool.begin().await {
        Ok(s) => s,
        Err(e) => {
            error!("failed to start transaction: {e:?}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let Ok(user_query) = query_as!(db::User, "SELECT * FROM user WHERE id = ?", userinfo.sub).fetch_optional(&mut tx).await else {
        error!("failed to find a user");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };

    // detect if this is a login or a new account
    let new_account = user_query.is_none();

    if !user_query.is_some_and(|s| s.name == userinfo.name) {
        if let Err(e) = query!(
            "INSERT INTO user(id, name) VALUES (?, ?) ON DUPLICATE KEY UPDATE name=name;",
            userinfo.sub,
            userinfo.name,
        )
        .execute(&mut tx)
        .await {
            error!("database error occured: {e:?}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        };
    };

    if let Err(e) = query!(
        "INSERT INTO user_access_token(token, user_id, issued, expires) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE token=token, issued=issued;",
        token_result.access_token().secret(),
        userinfo.sub,
        userinfo.iat,
        // use token_result.expires_in and convert to 
        userinfo.exp
    )
    .execute(&mut tx)
    .await
    {
        error!("database error occured: {e:?}");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    if let Some(s) = token_result.refresh_token() {
        if let Err(e) = query!(
            "INSERT INTO user_refresh_token(token, user_id, issued) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE token=token, issued=issued;",
            s.secret(),
            userinfo.sub,
            // i'm using the issue time from the access token as they should be close
            userinfo.iat
        )
        .execute(&mut tx)
        .await
        {
            error!("database error occured: {e:?}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    if let Err(e) = tx.commit().await {
        error!("Failed to commit to database: {e:?}");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    session.remove("oauth_pkce");
    session.remove("oauth_csrf");

    Ok(Redirect::to(if new_account {"/oauth/microsoft"} else {"/"}))
}

#[derive(Deserialize, Debug)]
pub struct UserInfo {
    pub name: String,
    pub groups: Vec<String>,
    pub sub: String,
}

async fn get_user_info(conf: &Config, token: &AccessToken) -> Result<UserInfo, reqwest::Error> {
    reqwest::Client::new()
        .get(conf.oauth_userinfo_url.clone())
        .bearer_auth(token.secret())
        .send()
        .await?
        .json()
        .await
}

pub async fn login(
    mut session: WritableSession,
    State(state): State<Arc<AppState>>,
    _headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let client = get_oauth2_client(&state.config);

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token) = {
        let mut builder = client.authorize_url(CsrfToken::new_random);
        // Set the desired scopes.
        for scope in state.config.oauth_scopes.iter() {
            builder = builder.add_scope(Scope::new(scope.clone()));
        }

        // Set the PKCE code challenge.
        builder.set_pkce_challenge(pkce_challenge).url()
    };

    let Ok(_) = session.insert("oauth_pkce", pkce_verifier.secret()) else {
        error!("failed to serialize pkce verifier");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };

    let Ok(_) = session.insert("oauth_csrf", csrf_token.secret()) else {
        error!("failed to insert oauth csrf token into session");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };

    Ok(Redirect::to(auth_url.as_ref()))
}

//async fn redirect(mut session: WritableSession, State(state): State<Arc<AppState>>, _headers: HeaderMap, Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {

pub async fn userinfo(
    session: ReadableSession,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    if let Some(t) = session.get::<String>("access_token") {
        let a = reqwest::Client::new()
            .get(state.config.oauth_userinfo_url.clone())
            .bearer_auth(t)
            .send()
            .await
            .unwrap();

        debug!("{a:?}");

        let f = format!("{a:?}");
        let text = a.text().await.unwrap();
        format!("{f}\n\n{text}")
    } else {
        "not logged in".to_string()
    }
}

/*
async fn p() -> (StatusCode, &'static str) {
    (StatusCode::INTERNAL_SERVER_ERROR, "hi again")
}
*/
