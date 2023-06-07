use axum::http::header::HeaderMap;

use reqwest::{
    header::{ACCEPT, CONTENT_TYPE},
    StatusCode,
};
use tracing::*;

use crate::*;
use serde::*;
use serde_json::json;
use sqlx::{query, query_as, MySqlConnection};

use oauth2::{
    basic::{
        BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
        BasicTokenType,
    },
    AuthType, AuthUrl, Client, ExtraTokenFields, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl,
    Scope, StandardRevocableToken, StandardTokenResponse, TokenResponse, TokenType, TokenUrl, RequestTokenError, StandardErrorResponse,
};

pub mod models;

use crate::db::*;

pub fn get_oauth2_client(conf: &crate::Config) -> OAuthClient {
    let redirect_url = conf
        .host_url
        .join("/oauth/microsoft/redirect")
        .expect("failed to join host url with ms graph redirect path");
    OAuthClient::new(
        conf.msgraph_client_id.clone(),
        Some(conf.msgraph_client_secret.clone()),
        MS_GRAPH_AUTH_URL.clone(),
        Some(MS_GRAPH_TOKEN_URL.clone()),
    )
    .set_auth_type(AuthType::RequestBody)
    .set_redirect_uri(RedirectUrl::from_url(redirect_url))
}

#[derive(Deserialize, Debug, Serialize, Clone)]
pub struct MicrosoftExtraFields {
    pub user_id: String,
}
impl ExtraTokenFields for MicrosoftExtraFields {}

type OAuthTokenResponse = StandardTokenResponse<MicrosoftExtraFields, BasicTokenType>;
type OAuthClient = Client<
    BasicErrorResponse,
    OAuthTokenResponse,
    BasicTokenType,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
>;

lazy_static::lazy_static! {
    pub static ref SCOPES: [Scope; 3] =
        [Scope::new("XboxLive.signin".to_string()),
        Scope::new("offline_access".to_string()),
        //.add_scope(Scope::new("XboxLive.offline_access".to_string()))
        Scope::new("User.Read".to_string())];
    pub static ref MS_GRAPH_AUTH_URL: AuthUrl =
    AuthUrl::new("https://login.microsoftonline.com/common/oauth2/v2.0/authorize".to_string())
        .expect("Invalid authorization endpoint URL");

    pub static ref MS_GRAPH_TOKEN_URL: TokenUrl =
    //TokenUrl::new("https://login.microsoftonline.com/common/oauth2/v2.0/token".to_string())
    TokenUrl::new("https://login.live.com/oauth20_token.srf".to_string())
        .expect("Invalid token endpoint URL");

}

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("http error: {0}")]
    Reqwest(#[from] oauth2::reqwest::Error<reqwest::Error>),
    #[error("response parse error: {0}")]
    ResponseParse(#[from] serde_path_to_error::Error<serde_json::error::Error>),
    #[error("sql error {0:?}")]
    Sqlx(#[from] sqlx::Error),
    #[error("Other error: {0}")]
    Other(String),
    #[error("no refresh token")]
    NoRefreshToken,
    #[error("invalid refresh token")]
    InvalidRefreshToken
}

pub async fn refresh_microsoft_access_token(
    microsoft_id: &str,
    conn: &mut MySqlConnection,
    conf: &Config,
) -> Result<MicrosoftAccessToken, TokenError> {
    let Some(refresh_token) = get_ms_refresh_token(&mut *conn, microsoft_id).await? else {
        error!("failed to find microsoft token");
        return Err(TokenError::NoRefreshToken)
    };

    let c = get_oauth2_client(conf);
    let refresh_t = oauth2::RefreshToken::new(refresh_token.token);

    //todo fix this 
    let rx = match c
    .exchange_refresh_token(&refresh_t)
    .add_scopes(SCOPES.iter().cloned())
    .request_async(oauth2::reqwest::async_http_client)
    .await {
        Ok(s) => s,
        Err(e) => {
            match e {
                RequestTokenError::Request(e) => return Err(TokenError::Reqwest(e)),
                RequestTokenError::Parse(e, _) => return Err(TokenError::ResponseParse(e)),
                // include this with the value
                RequestTokenError::ServerResponse(e) => return Err(TokenError::InvalidRefreshToken),
                RequestTokenError::Other(e) => return Err(TokenError::Other(e)),
            }
        }
    };

    insert_ms_access_token(&mut *conn, MicrosoftAccessToken::from(rx.clone())).await?;

    if let Ok(s) = MicrosoftRefreshToken::try_from(rx.clone()) {
        insert_ms_refresh_token(conn, s).await?;
    }

    Ok(MicrosoftAccessToken::from(rx))
}

pub async fn update_mc_profile_from_db(
    microsoft_id: &str,
    conn: &mut MySqlConnection,
    conf: &Config,
) -> Result<(), anyhow::Error> {
    let access_token = if let Some(access_token) = get_ms_access_token(&mut *conn, microsoft_id)
        .await?{
        access_token
    } else {
        // try to refresh the token
        refresh_microsoft_access_token(microsoft_id, &mut *conn, conf).await?
    };

    let client = reqwest::Client::new();
    let _ = update_mc_profile_from_ms_token(microsoft_id, &access_token.token, conn, &client).await?;
    Ok(())
}

pub async fn update_mc_profile_from_ms_token(
    microsoft_id: &str,
    ms_access_token: &str,
    conn: &mut MySqlConnection,
    client: &reqwest::Client,
) -> Result<models::McProfileResponseSuccess, anyhow::Error> {
    let (_, xbox_token) = get_xbox_token(ms_access_token, client).await?;
    info!("got xbox token");
    let (uhash, xsts_token) = get_xsts_token(&xbox_token, client).await?;
    info!("got xsts token");
    let (mc_token, expires) = get_minecraft_token(&uhash, &xsts_token, client).await?;
    info!("got mc token");
    let now = chrono::Utc::now();
    query!(
        "INSERT INTO minecraft_token (microsoft_id, token, issued, expires) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE token=token, issued=issued, expires=expires;",
        microsoft_id,
        mc_token,
        now,
        now.checked_add_signed(chrono::Duration::seconds(expires as i64))
    ).execute(&mut *conn).await?;

    let mc_profile = get_minecraft_profile(&mc_token, client).await?;

    let skin = mc_profile
        .skins
        .iter()
        .find(|x| x.state == "ACTIVE")
        .unwrap();
    query!(
        "INSERT INTO minecraft_profile (microsoft_id, uuid, username, skin_id, skin_url, skin_variant, skin_alias) VALUES (?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE uuid=uuid, username=username, skin_id=skin_id,skin_url=skin_url,skin_variant=skin_variant,skin_alias=skin_alias;",
        microsoft_id,
        mc_profile.id,
        mc_profile.name,
        skin.id,
        skin.url,
        skin.variant,
        skin.alias
    ).execute(conn).await?;
    info!("inserted into mc profile");

    Ok(mc_profile)
}

/*
async fn get_minecraft_profile_from_ms_token(ms_access_token: &str, conn: &mut MySqlConnection, client: &reqwest::Client) -> Result<models::McProfileResponseSuccess, reqwest::Error> {
    get_minecraft_profile(&mc_token, client).await
}
*/


#[derive(Error, Debug)]
pub enum XboxApiError {
    #[error("help")]
    HttpError(#[from] reqwest::Error),
    #[error("forbidden: {body}")]
    Forbidden {
        body: String
    },
    #[error("non 200 status code")]
    OtherStatus(StatusCode), 
    #[error("xbox api error")]
    ApiError(models::XBLResponseError),
}

pub async fn get_xbox_token(
    ms_access_token: &str,
    client: &reqwest::Client,
) -> Result<(String, String), XboxApiError> {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
    headers.insert(ACCEPT, "application/json".parse().unwrap());
    let res = client
        .post("https://user.auth.xboxlive.com/user/authenticate")
        .headers(headers)
        .json(&json!({
            "Properties": {
                "AuthMethod": "RPS",
                "SiteName": "user.auth.xboxlive.com",
                "RpsTicket": &format!("d={}", ms_access_token)
            },
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT"
        }))
        .send()
        .await?;

    match res.status() {
        StatusCode::OK => {}
        StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => return Err(XboxApiError::Forbidden{ body: res.text().await? }),
        status => return Err(XboxApiError::OtherStatus(status)),
    }

    match res.json::<models::XBLResponse>().await? {
        models::XBLResponse::Success(s) => Ok((s.display_claims.xui[0].uhs.clone(), s.token)),
        models::XBLResponse::Error(e) => Err(XboxApiError::ApiError(e)),
    }
}


async fn get_xsts_token(
    xbox_access_token: &str,
    client: &reqwest::Client,
) -> Result<(String, String), XboxApiError> {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
    headers.insert(ACCEPT, "application/json".parse().unwrap());
    let res = client
        .post("https://xsts.auth.xboxlive.com/xsts/authorize")
        .headers(headers)
        .json(&json!({
            "Properties": {
                "SandboxId": "RETAIL",
                "UserTokens": [xbox_access_token]
            },
            "RelyingParty": "rp://api.minecraftservices.com/",
            "TokenType": "JWT"
        }))
        .send()
        .await?;

    match res.status() {
        StatusCode::OK => {}
        StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => return Err(XboxApiError::Forbidden{ body: res.text().await? }),
        status => return Err(XboxApiError::OtherStatus(status)),
    }

    let x = res.json::<models::XBLResponse>().await?;
    warn!("{x:?}");
    match x {
        models::XBLResponse::Success(s) => Ok((s.display_claims.xui[0].uhs.clone(), s.token)),
        models::XBLResponse::Error(e) => Err(XboxApiError::ApiError(e)),
    }
}

#[derive(Error, Debug)]
pub enum MinecraftApiError {
    #[error("http error {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("forbidden: {body}")]
    Forbidden {
        body: String,
    },
    #[error("Unexpected status code returned: {0}")]
    UnexpectedStatus(StatusCode),

    #[error("Api Error")]
    ApiError(models::McResponseError)

    
}

async fn get_minecraft_token(
    user_hash: &str,
    xsts_access_token: &str,
    client: &reqwest::Client,
) -> Result<(String, i32), MinecraftApiError> {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
    //headers.insert(ACCEPT, "application/json".parse().unwrap());
    let res = client
        .post("https://api.minecraftservices.com/authentication/login_with_xbox")
        //.headers(headers)
        .json(&json!({
            "identityToken":
                format!(
                    "XBL3.0 x={user_hash};{xsts_token}",
                    user_hash = user_hash,
                    xsts_token = xsts_access_token
                )
        }))
        .send()
        .await?;

    match res.status() {
        StatusCode::OK => {}
        StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => return Err(MinecraftApiError::Forbidden { body: res.text().await? }),
        status => return Err(MinecraftApiError::UnexpectedStatus(status)),
    }

    match res.json::<models::McResponse>().await? {
        models::McResponse::Success(s) => Ok((s.access_token, s.expires_in)),
        models::McResponse::Error(e) => Err(MinecraftApiError::ApiError(e)),
    }
}

async fn get_minecraft_profile(
    minecraft_access_token: &str,
    client: &reqwest::Client,
) -> Result<models::McProfileResponseSuccess, MinecraftApiError> {
    let res = client
        .post("https://api.minecraftservices.com/minecraft/profile")
        .bearer_auth(minecraft_access_token)
        .send()
        .await?;

    match res.status() {
        StatusCode::OK => {}
        StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => return Err(MinecraftApiError::Forbidden { body: res.text().await? }),
        status => return Err(MinecraftApiError::UnexpectedStatus(status)),
    }

    match res.json::<models::McProfileResponse>().await? {
        models::McProfileResponse::Success(s) => Ok(s),
        models::McProfileResponse::Error(e) =>  todo!(), //Err(MinecraftApiError::ApiError(e)),
    }
}

/*
async fn refresh_microsoft_access_token(conn: &mut MySqlConnection, ms_id: String) -> Result<(), sqlx::Error> {

}
*/
