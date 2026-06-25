use axum::{
    extract::{Query, State},
    http::header::HeaderMap,
    response::{IntoResponse, Redirect},
};

// use reqwest::StatusCode;
use time::OffsetDateTime;
use tracing::*;

use crate::session::*;
// use axum_sessions::extractors::{ReadableSession, WritableSession};
use tower_sessions::Session;

use crate::*;
use serde::*;
use sqlx::query;

use crate::AppError;
use sqlx::query_as;
use std::sync::Arc;

use oauth2::{
    AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse,
};

const OAUTH_REDIRECT_PATH: &str = "/oauth/redirect";

// type OAuthClient = BasicClient;

use oauth2::{
    Client, EmptyExtraTokenFields, EndpointNotSet, EndpointSet, RevocationErrorResponseType,
    StandardErrorResponse, StandardRevocableToken, StandardTokenIntrospectionResponse,
    StandardTokenResponse, basic::BasicErrorResponseType, basic::BasicTokenType,
};

type AuthentikOAuthClient = Client<
    StandardErrorResponse<BasicErrorResponseType>,
    StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
    StandardTokenIntrospectionResponse<EmptyExtraTokenFields, BasicTokenType>,
    StandardRevocableToken,
    StandardErrorResponse<RevocationErrorResponseType>,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
>;
// this is certainly a type
fn get_oauth2_client(conf: &crate::Config) -> AuthentikOAuthClient {
    let redirect_url = conf
        .host_url
        .join(OAUTH_REDIRECT_PATH)
        .expect("failed to join host url with ms graph redirect path");

    oauth2::basic::BasicClient::new(conf.oauth_client_id.clone())
        .set_client_secret(conf.oauth_client_secret.clone())
        .set_auth_uri(conf.oauth_auth_url.clone())
        .set_token_uri(conf.oauth_token_url.clone())
        .set_redirect_uri(RedirectUrl::from_url(redirect_url))
}

#[derive(Deserialize, Debug)]
pub struct RedirectParams {
    pub code: String,
    pub state: String,
}

// use chrono::naive::serde::ts_seconds;

// #[derive(Debug, Deserialize)]
// struct TokenInfo {
//     sub: String,
//     // #[serde(with = "ts_seconds")]
//     // exp: NaiveDateTime,
//     exp: PrimitiveDateTime,
//     // #[serde(with = "ts_seconds")]
//     iat: PrimitiveDateTime,
//     // iat: NaiveDateTime,
//     name: String,
//     groups: Vec<String>,
// }

// fn parse_access_token(token: &str) -> Option<TokenInfo> {
//     let t = token.split('.').nth(1)?;
//     let mut c = std::io::Cursor::new(t);
//     match serde_json::from_reader(base64::read::DecoderReader::new(
//         &mut c,
//         &base64::engine::general_purpose::STANDARD_NO_PAD,
//     )) {
//         Ok(s) => Some(s),
//         Err(e) => {
//             error!("failed to deserialize jwt: {e:?}");
//             None
//         }
//     }
// }

pub async fn redirect(
    session: Session,
    State(app_state): State<Arc<AppState>>,
    Query(RedirectParams { code, state }): Query<RedirectParams>,
) -> Result<impl IntoResponse, AppError> {
    let client = get_oauth2_client(&app_state.config);

    info!("serving request with session id: {:?}", session.id());
    let exchange_data = session
        .get::<OAuthExchangeData>(OAuthExchangeData::SESSION_KEY)
        .await ?
        .ok_or(AppError::NoOauthExchangeDataInSession)?;

    if exchange_data.csrf != state {
        error!("failed to verify csrf token");
        return Err(AppError::InvalidCSRFToken);
    }

    let token_result = client
        .exchange_code(AuthorizationCode::new(code))
        // Set the PKCE code verifier.
        .set_pkce_verifier(PkceCodeVerifier::new(exchange_data.pkce))
        .request_async(&crate::ReqwestClient(app_state.http_client.clone()))
        .await
        .inspect_err(|e| error!("Oauth token exchange error {e}"))?;


    // #[derive(Debug, Serialize, Deserialize)]
    // struct MsClaims { }
    // let contents: biscuit::JWT<MsClaims, MsClaims> = biscuit::JWT::new_encoded(&token.extra_fields().id_token);
    // error!("{}", token.extra_fields().id_token);
    // let id_contents: biscuit::ClaimsSet<MsClaims> = contents.unverified_payload().unwrap(); // bad
    // let sub = id_contents.registered.subject.expect("microsoft did not provide subject in id token");

    #[derive(Debug, Serialize, Deserialize)]
    struct Claims {
        name: Option<String>,
    }
    let token: biscuit::JWT<Claims, Claims> =
        biscuit::JWT::new_encoded(token_result.access_token().secret());

    let token_contents: biscuit::ClaimsSet<Claims> =
        token.unverified_payload().expect("failed to parse payload");

    // let id_contents: biscuit::ClaimsSet<Claims> = contents.unverified_payload().unwrap(); // bad
    // let sub = userinfo.registered.subject.expect("microsoft did not provide subject in id token");

    let subject = token_contents
        .registered
        .subject
        .ok_or(AppError::InvalidAuthentikToken("subject was missing")) ?;

    let username = token_contents
        .private
        .name
        .ok_or(AppError::InvalidAuthentikToken("name was missing"))?;

    let exp_odt = token_contents
        .registered
        .expiry
        .map(|s| {
            OffsetDateTime::from_unix_timestamp(s.timestamp()).expect("failed to convert timestamp")
        })
        .ok_or(AppError::InvalidAuthentikToken("expiry was missing"))?;

    let exp = exp_odt.date().with_time(exp_odt.time());

    let iat_odt = token_contents
        .registered
        .issued_at
        .map(|s| {
            OffsetDateTime::from_unix_timestamp(s.timestamp()).expect("failed to convert timestamp")
        })
        .ok_or(AppError::InvalidAuthentikToken("issued at was missing"))?;

    // this is so stupid and i hate it
    let iat = iat_odt.date().with_time(iat_odt.time());

    session
        .insert(UserID::SESSION_KEY, UserID(subject.clone()))
        .await?;

    let mut tx = app_state.pool.begin().await.inspect_err(|e| error!("failed to start transaction: {e:?}"))?;

    let user_query = query_as!(db::User, "SELECT * FROM users WHERE id = $1", subject)
        .fetch_optional(&mut *tx)
        .await
        .inspect_err(|e| error!("database error while searching for user {e}"))?;

    // detect if this is a login or a new account
    let new_account = user_query.is_none();

    if !user_query.is_some_and(|s| s.name == username) {
        query!(
            "INSERT INTO users(id, name) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET name=$2;",
            subject,
            username,
        )
        .execute(&mut *tx)
        .await
        .inspect_err(|e| error!("database error while inserting new user data: {e}"))?;
    }

    query!(
        "INSERT INTO user_access_token(token, user_id, issued, expires) VALUES ($1, $2, $3, $4) ON CONFLICT (user_id) DO UPDATE SET token=$1, issued=$3;",
        token_result.access_token().secret(),
        subject,
        iat,
        // use token_result.expires_in and convert to 
        exp
    )
    .execute(&mut *tx)
    .await
    .inspect_err(|e| error!("database error occured: {e:?}"))?;

    if let Some(s) = token_result.refresh_token() {
        query!(
            "INSERT INTO user_refresh_token(token, user_id, issued) VALUES ($1, $2, $3) ON CONFLICT (user_id) DO UPDATE SET token=$1, issued=$3;",
            s.secret(),
            subject,
            // i'm using the issue time from the access token as they should be close
            iat
        )
        .execute(&mut *tx)
        .await
        .inspect_err(|e| error!("database error inserting user refresh token: {e}"))?;
    }

    tx.commit().await?;
    session
        .remove::<OAuthExchangeData>(OAuthExchangeData::SESSION_KEY)
        .await
        .inspect_err(|e| error!("session error removing oauth exchange data {e}"))?;

    Ok(Redirect::to(if new_account {
        "/oauth/microsoft"
    } else {
        "/"
    }))
}

#[derive(Deserialize, Debug)]
pub struct UserInfo {
    pub name: String,
    pub groups: Vec<String>,
    pub sub: String,
}
pub async fn login(
    session: Session,
    State(state): State<Arc<AppState>>,
    _headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let client = get_oauth2_client(&state.config);

    info!("serving request with session id: {:?}", session.id());
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
    // let Ok(_) =
    let _ = session
        .insert(
            OAuthExchangeData::SESSION_KEY,
            OAuthExchangeData {
                pkce: pkce_verifier.into_secret(),
                csrf: csrf_token.into_secret(),
            },
        )
        .await
        .inspect_err(|e| error!("failed to insert oauth session data {e}"))?;

    info!("Inserted exchange data");

    Ok(Redirect::to(auth_url.as_ref()))
}
