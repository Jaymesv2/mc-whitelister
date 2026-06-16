use serde::*;
use sqlx::FromRow;

type DB = sqlx::Postgres;

#[derive(Deserialize, Serialize, Debug, FromRow)]
pub struct User {
    pub id: String,
    pub name: String,
}

#[derive(Deserialize, Serialize, Debug, FromRow)]
pub struct AccessToken {
    pub user_id: String,
    pub token: String,
    pub issued: PrimitiveDateTime,
    pub expires: Option<PrimitiveDateTime>,
}

pub type RefreshToken = AccessToken;

#[derive(Deserialize, Serialize, Debug, FromRow)]
pub struct MinecraftAccessToken {
    pub minecraft_uuid: String,
    pub token: String,
    pub issued: PrimitiveDateTime,
    pub expires: Option<PrimitiveDateTime>,
}

#[derive(Deserialize, Serialize, Debug, FromRow)]
pub struct MinecraftProfile {
    pub microsoft_id: String,
    pub user_id: String,
    // pub is_primary: u8,
    pub uuid: String,
    pub username: String,
    pub skin_id: String,
    pub skin_url: String,
    pub skin_variant: String,
    pub skin_alias: Option<String>,
}

use sqlx::{Executor, query_as};
use time::PrimitiveDateTime;

pub async fn get_minecraft_profiles_from_user_id<'a, E: Executor<'a, Database = DB>>(
    user_id: String,
    conn: E,
) -> Result<Vec<MinecraftProfile>, sqlx::Error> {
    query_as!(
        MinecraftProfile,
        "SELECT * FROM minecraft_profile WHERE user_id = $1;",
        user_id
    )
    .fetch_all(conn)
    .await
}
