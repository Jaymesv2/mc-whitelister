use axum::http::header::HeaderMap;

use axum::http::header::HeaderValue;
use reqwest::{
    StatusCode,
    header::{ACCEPT, CONTENT_TYPE},
};
use serde::*;
use serde_json::json;
use sqlx::{PgConnection, query};
use tracing::*;

use oauth2::{
    AuthType, AuthUrl, Client, ExtraTokenFields, RedirectUrl, StandardErrorResponse,
    StandardRevocableToken, StandardTokenResponse, TokenUrl, basic::BasicTokenType,
};

pub mod models;

#[derive(Deserialize, Debug, Serialize, Clone)]
pub struct MicrosoftExtraFields {
    // pub user_id: String,
    pub id_token: String,
}
impl ExtraTokenFields for MicrosoftExtraFields {}

use std::sync::LazyLock;

pub static MS_GRAPH_AUTH_URL: LazyLock<AuthUrl> = LazyLock::new(|| {
    AuthUrl::new("https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize".to_string())
        .expect("Invalid authorization endpoint URL")
});

pub static MS_GRAPH_TOKEN_URL: LazyLock<TokenUrl> = LazyLock::new(|| {
    TokenUrl::new("https://login.microsoftonline.com/consumers/oauth2/v2.0/token".to_string())
        .expect("Invalid token endpoint URL")
});

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("http error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("response parse error: {0}")]
    ResponseParse(#[from] serde_path_to_error::Error<serde_json::error::Error>),
    #[error("sql error {0:?}")]
    Sqlx(#[from] sqlx::Error),
    #[error("Other error: {0}")]
    Other(String),

    #[error("no refresh token")]
    NoRefreshToken,
    #[error("invalid refresh token")]
    InvalidRefreshToken,
}

use oauth2::{
    EmptyExtraTokenFields, EndpointNotSet, EndpointSet, RevocationErrorResponseType,
    StandardTokenIntrospectionResponse, basic::BasicErrorResponseType,
};

type MsOAuthClient = Client<
    StandardErrorResponse<BasicErrorResponseType>,
    StandardTokenResponse<MicrosoftExtraFields, BasicTokenType>,
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
pub fn get_ms_oauth2_client(conf: &crate::Config) -> MsOAuthClient {
    let redirect_url = conf
        .host_url
        .join("/oauth/microsoft/redirect")
        .expect("failed to join host url with ms graph redirect path");

    oauth2::Client::new(conf.msgraph_client_id.clone())
        .set_client_secret(conf.msgraph_client_secret.clone())
        .set_auth_uri(MS_GRAPH_AUTH_URL.clone())
        .set_token_uri(MS_GRAPH_TOKEN_URL.clone())
        .set_auth_type(AuthType::RequestBody)
        .set_redirect_uri(RedirectUrl::from_url(redirect_url))
}

pub async fn update_mc_profile_from_ms_token(
    user_id: &str,
    microsoft_id: &str,
    ms_access_token: &str,
    conn: &mut PgConnection,
    client: &reqwest::Client,
) -> Result<models::McProfileResponseSuccess, anyhow::Error> {
    let (_, xbox_token) = get_xbox_token(ms_access_token, client).await?;
    info!("got xbox token");
    let (uhash, xsts_token) = get_xsts_token(&xbox_token, client).await?;
    info!("got xsts token");
    let (mc_token, _expires) = get_minecraft_token(&uhash, &xsts_token, client).await?;
    info!("got mc token");

    let mc_profile = get_minecraft_profile(&mc_token, client).await?;

    let skin = mc_profile
        .skins
        .iter()
        .find(|x| x.state == "ACTIVE")
        .unwrap(); // fix
    query!(
        "INSERT INTO minecraft_profile (microsoft_id, uuid, username, skin_id, skin_url, skin_variant, skin_alias, user_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (microsoft_id) DO UPDATE SET uuid=$2, username=$3, skin_id=$4,skin_url=$5,skin_variant=$6,skin_alias=$7;",
        microsoft_id,
        mc_profile.id,
        mc_profile.name,
        skin.id,
        skin.url,
        skin.variant,
        skin.alias,
        user_id
    ).execute(conn).await?;
    info!("inserted into mc profile");

    Ok(mc_profile)
}

#[derive(Error, Debug)]
pub enum XboxApiError {
    #[error("help")]
    HttpError(#[from] reqwest::Error),
    #[error("forbidden: {body}")]
    Forbidden { body: String },
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
    headers.insert(
        CONTENT_TYPE,
        const { HeaderValue::from_static("application/json") },
    );
    headers.insert(
        ACCEPT,
        const { HeaderValue::from_static("application/json") },
    );

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
        StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => {
            return Err(XboxApiError::Forbidden {
                body: res.text().await?,
            });
        }
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
    // make these static
    headers.insert(
        CONTENT_TYPE,
        const { HeaderValue::from_static("application/json") },
    );
    headers.insert(
        ACCEPT,
        const { HeaderValue::from_static("application/json") },
    );
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
        StatusCode::OK => match res.json::<models::XBLResponse>().await? {
            models::XBLResponse::Success(s) => Ok((
                s.display_claims
                    .xui
                    .get(0)
                    .expect("failed to get xui")
                    .uhs
                    .clone(),
                s.token,
            )),
            models::XBLResponse::Error(e) => Err(XboxApiError::ApiError(e)),
        },
        StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => Err(XboxApiError::Forbidden {
            body: res.text().await?,
        }),
        status => Err(XboxApiError::OtherStatus(status)),
    }
}

#[derive(Error, Debug)]
pub enum MinecraftApiError {
    #[error("http error {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("forbidden: {body}")]
    Forbidden { body: String },
    #[error("Unexpected status code returned: {0}")]
    UnexpectedStatus(StatusCode),
    #[error("Api Error")]
    ApiError(models::McResponseError),

    #[error("No Associated Minecraft Account")]
    NoAssociatedMinecraftAccount,
}

async fn get_minecraft_token(
    user_hash: &str,
    xsts_access_token: &str,
    client: &reqwest::Client,
) -> Result<(String, i32), MinecraftApiError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        const { HeaderValue::from_static("application/json") },
    );
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
        StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => {
            return Err(MinecraftApiError::Forbidden {
                body: res.text().await?,
            });
        }
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
        .get("https://api.minecraftservices.com/minecraft/profile")
        .bearer_auth(minecraft_access_token)
        .send()
        .await?;

    match res.status() {
        StatusCode::OK => {}
        StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => {
            return Err(MinecraftApiError::Forbidden {
                body: res.text().await?,
            });
        }
        StatusCode::NOT_FOUND => {
            return Err(MinecraftApiError::NoAssociatedMinecraftAccount);
        }
        status => return Err(MinecraftApiError::UnexpectedStatus(status)),
    }

    match res.json::<models::McProfileResponse>().await? {
        models::McProfileResponse::Success(s) => Ok(s),
        models::McProfileResponse::Error(_e) => todo!(), //Err(MinecraftApiError::ApiError(e)),
    }
}
