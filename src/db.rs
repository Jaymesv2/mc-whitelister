use crate::ms_api::MicrosoftExtraFields;
use chrono::NaiveDateTime;
use oauth2::{
    StandardTokenResponse, TokenResponse, TokenType,
};
use serde::*;
use sqlx::FromRow;

type DB = sqlx::MySql;

#[derive(Deserialize, Serialize, Debug, FromRow)]
pub struct User {
    pub id: String,
    pub name: String,
}

#[derive(Deserialize, Serialize, Debug, FromRow)]
pub struct AccessToken {
    pub user_id: String,
    pub token: String,
    pub issued: NaiveDateTime,
    pub expires: Option<NaiveDateTime>,
}

pub type RefreshToken = AccessToken;

#[derive(Deserialize, Serialize, Debug, FromRow)]
pub struct MicrosoftAccount {
    pub microsoft_id: String,
    pub user_id: String,
}

#[derive(Deserialize, Serialize, Debug, FromRow)]
pub struct MicrosoftAccessToken {
    pub microsoft_id: String,
    pub token: String,
    pub issued: NaiveDateTime,
    pub expires: Option<NaiveDateTime>,
}

#[derive(Deserialize, Serialize, Debug, FromRow)]
pub struct MicrosoftRefreshToken {
    pub microsoft_id: String,
    pub token: String,
    pub issued: NaiveDateTime,
    pub expires: Option<NaiveDateTime>,
}


#[derive(Deserialize, Serialize, Debug, FromRow)]
pub struct MinecraftAccessToken {
    pub minecraft_uuid: String,
    pub token: String,
    pub issued: NaiveDateTime,
    pub expires: Option<NaiveDateTime>,

}

#[derive(Deserialize, Serialize, Debug, FromRow)]
pub struct MinecraftProfile {
    pub microsoft_id: String,
    pub is_primary: u8,
    pub uuid: String,
    pub username: String,
    pub skin_id: String,
    pub skin_url: String,
    pub skin_variant: String,
    pub skin_alias: String
}

impl<TT: TokenType> TryFrom<StandardTokenResponse<MicrosoftExtraFields, TT>>
    for MicrosoftRefreshToken
{
    type Error = ();
    fn try_from(
        value: StandardTokenResponse<MicrosoftExtraFields, TT>,
    ) -> Result<Self, Self::Error> {
        if let Some(r) = value.refresh_token() {
            let now = chrono::Utc::now().naive_utc();

            Ok(Self {
                microsoft_id: value.extra_fields().user_id.clone(),
                token: r.secret().clone(),
                issued: now,
                // this would be nicer if i had monads
                expires: None,
            })
        } else {
            Err(())
        }
    }
}

impl<TT: TokenType> From<StandardTokenResponse<MicrosoftExtraFields, TT>> for MicrosoftAccessToken {
    fn from(x: StandardTokenResponse<MicrosoftExtraFields, TT>) -> Self {
        let now = chrono::Utc::now().naive_utc();
        Self {
            microsoft_id: x.extra_fields().user_id.clone(),
            token: x.access_token().secret().clone(),
            issued: now,
            // this would be nicer if i had monads
            expires: x.expires_in().and_then(|y| {
                chrono::Duration::from_std(y)
                    .ok()
                    .and_then(|z| now.checked_add_signed(z))
            }),
        }
    }
}

use sqlx::{query, query_as, Error as SqlxError, Executor};

pub async fn insert_ms_access_token<'a, E: Executor<'a, Database = DB>>(
    exec: E,
    token: MicrosoftAccessToken,
) -> Result<(), SqlxError> {
    query!(
            "INSERT INTO microsoft_access_token (microsoft_id, token, expires, issued) values (?, ?, ?, ?);",
            token.microsoft_id,
            token.token,
            token.expires,
            token.issued
            ).execute(exec).await?;
    Ok(())
}

/// Fetches a valid access token from the database
pub async fn get_ms_access_token<'a, E: Executor<'a, Database = DB>>(
    exec: E,
    microsoft_id: impl AsRef<str>,
) -> Result<Option<MicrosoftAccessToken>, SqlxError> {
    query_as!(MicrosoftAccessToken, "SELECT * FROM microsoft_access_token WHERE microsoft_id = ? AND (expires IS NULL OR expires > (? - 30));", microsoft_id.as_ref(), chrono::Utc::now())
        .fetch_optional(exec)
        .await
}

pub async fn insert_ms_refresh_token<'a, E: Executor<'a, Database = DB>>(
    exec: E,
    token: MicrosoftRefreshToken,
) -> Result<(), SqlxError> {
    query!(
            "INSERT INTO microsoft_refresh_token (microsoft_id, token, expires, issued) values (?, ?, ?, ?);",
            token.microsoft_id,
            token.token,
            token.expires,
            token.issued
            ).execute(exec).await?;
    Ok(())
}

/// Fetches a valid refresh token from the database
pub async fn get_ms_refresh_token<'a, E: Executor<'a, Database = DB>>(
    exec: E,
    microsoft_id: impl AsRef<str>,
) -> Result<Option<MicrosoftRefreshToken>, SqlxError> {
    query_as!(MicrosoftRefreshToken, "SELECT * FROM microsoft_refresh_token WHERE microsoft_id = ? AND (expires IS NULL OR expires > (? - 30));", microsoft_id.as_ref(), chrono::Utc::now())
        .fetch_optional(exec)
        .await
}


pub async fn get_minecraft_profiles_from_user_id<'a, E: Executor<'a, Database = DB>>(user_id: String, conn: E) -> Result<Vec<MinecraftProfile>, sqlx::Error> {
    query_as!(MinecraftProfile, "SELECT * FROM minecraft_profile WHERE microsoft_id = ANY (SELECT microsoft_id FROM microsoft_account WHERE user_id = ?);", user_id).fetch_all(conn).await
}