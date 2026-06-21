use axum::{
    extract::{Query, State},
    http::header::HeaderMap,
    response::{self, IntoResponse, Redirect, Response},
};

// use axum_sessions::extractors::{ReadableSession, WritableSession};
use crate::session::*;
use reqwest::StatusCode;
use tower_sessions::Session;
use tracing::*;

use crate::{session::MSOAuthExchangeData, *};
use serde::*;
use std::sync::Arc;

use oauth2::{
    AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope, TokenResponse,
    reqwest,
};

//type OAuthClient = BasicClient;
//

use crate::ms_api::*;

pub async fn login(
    session: Session,
    State(state): State<Arc<AppState>>,
    _headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let client = get_ms_oauth2_client(&state.config);

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (authorize_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new(String::from("XboxLive.signin")))
        .add_scope(Scope::new(String::from("offline_access"))) // maybe optional
        .add_scope(Scope::new(String::from("openid")))
        // .add_scope(Scope::new(String::from("User.Read")))
        .set_pkce_challenge(pkce_challenge)
        .url();

    session
        .insert(
            MSOAuthExchangeData::SESSION_KEY,
            MSOAuthExchangeData {
                pkce: pkce_verifier.into_secret(),
                csrf: csrf_token.into_secret(),
            },
        )
        .await
        .expect("failed to insert ms oauth exchange data");

    Ok(Redirect::to(authorize_url.as_ref()))
}

#[derive(Debug, Deserialize)]
pub struct RedirectParams {
    pub code: Option<String>,
    pub error: Option<String>,
    pub state: String,
}

pub async fn redirect(
    session: Session,
    State(app_state): State<Arc<AppState>>,
    //_headers: HeaderMap,
    Query(RedirectParams { error, state, code }): Query<RedirectParams>,
) -> Result<Response, StatusCode> {
    let client = get_ms_oauth2_client(&app_state.config);

    let Some(user_id): Option<UserID> = session
        .get(UserID::SESSION_KEY)
        .await
        .expect("failed to get user id")
    else {
        return Ok(response::Redirect::to("/login").into_response());
    };

    let Some(code) = code else {
        if let Some(e) = error {
            warn!("error occured with msgraph sign in: {e}");
        }
        return Ok(Redirect::to("/").into_response());
    };

    // should add logging here
    let Some(exchange_data) = session
        .get::<MSOAuthExchangeData>(MSOAuthExchangeData::SESSION_KEY)
        .await
        .expect("failed to get exchange data")
    else {
        return Err(StatusCode::FORBIDDEN);
    };

    let pkce: PkceCodeVerifier = PkceCodeVerifier::new(exchange_data.pkce);
    if state != exchange_data.csrf {
        error!("Failed to validate csrf");
        return Err(StatusCode::FORBIDDEN);
    }

    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to build http client");

    let token = match client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(pkce)
        .request_async(&http_client)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            error!("error occured while exchaging token: {e:?}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // The id token should be verified using microsofts jwks
    #[derive(Debug, Serialize, Deserialize)]
    struct MsClaims {}
    let contents: biscuit::JWT<MsClaims, MsClaims> =
        biscuit::JWT::new_encoded(&token.extra_fields().id_token);

    let id_contents: biscuit::ClaimsSet<MsClaims> = contents.unverified_payload().unwrap(); // bad
    let sub = id_contents
        .registered
        .subject
        .expect("microsoft did not provide subject in id token");

    let mut tx = match app_state.pool.begin().await {
        Ok(s) => s,
        Err(e) => {
            error!("Error starting transaction {e:?}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    update_mc_profile_from_ms_token(
        &user_id.0,
        sub.as_str(),
        token.access_token().secret().as_str(),
        &mut tx,
        &http_client,
    )
    .await
    .expect("failed to update minecraft profile");


    if let Err(e) = tx.commit().await {
        error!("Failed to commit to database: {e:?}");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // if let Ok(s) = MicrosoftRefreshToken::try_from(token.clone()) {
    //     if let Err(e) = insert_ms_refresh_token(&mut *tx, s).await {
    //         error!("error occured while inserting into `microsoft_account`: {e:?}");
    //         return Err(StatusCode::INTERNAL_SERVER_ERROR);
    //     };
    // }

    //query
    let _ = session
        .remove::<MSOAuthExchangeData>(MSOAuthExchangeData::SESSION_KEY)
        .await
        .expect("failed to remove ms oauth exchange data from session");

    Ok(response::Redirect::to("/").into_response())
}

// pub async fn update_mc_profile(
//     session: Session<SessionPgPool>,
//     State(app_state): State<Arc<AppState>>,
// ) -> Result<Response, StatusCode> {
//
//     let Some(user_id): Option<String> = session.get("user_id") else {
//         warn!("user id could not be found");
//         return Ok(Redirect::to("/").into_response());
//     };
//
//     let Ok(mut conn) = app_state.pool.acquire().await else {
//         error!("failed to get db conn");
//         return Err(StatusCode::INTERNAL_SERVER_ERROR);
//     };
//
//     let account = match query_as!(MicrosoftAccount, "SELECT * from microsoft_account WHERE user_id = $1;", user_id).fetch_one(&mut *conn).await {
//         Ok(s) => s,
//         Err(e) => {
//             error!("failed to get microsoft account: {e:?}");
//             return Err(StatusCode::INTERNAL_SERVER_ERROR);
//         }
//     };
//
//     //let http_client = reqwest::Client::new();
//
//     if let Err(e) =
//     update_mc_profile_from_db(&account.microsoft_id, &mut conn, &app_state.config).await
//     {
//         error!("Failed to update mc profile: {e:?}");
//         return Err(StatusCode::INTERNAL_SERVER_ERROR);
//     };
//
//     //Ok(response::Redirect::to("/").into_response())
//     Ok("success".into_response())
// }
