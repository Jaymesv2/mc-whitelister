use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use serde::*;
use std::net::SocketAddr;
use url::Url;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub oauth_client_id: ClientId,
    pub oauth_client_secret: ClientSecret,
    pub oauth_auth_url: AuthUrl,
    pub oauth_token_url: TokenUrl,
    pub oauth_redirect_url: RedirectUrl,
    pub oauth_userinfo_url: Url,
    pub oauth_scopes: Vec<String>,

    pub user_groups: Vec<String>,
    pub op_groups: Vec<String>,

    pub msgraph_client_id: ClientId,
    pub msgraph_client_secret: ClientSecret,

    pub db_host: String,
    pub db_port: u16,
    pub db_user: String,
    pub db_password: String,
    pub db_name: String,

    pub redis_host: String,

    pub host_url: Url,

    pub session_secret: Option<String>,

    pub bind_addr: SocketAddr,
}
