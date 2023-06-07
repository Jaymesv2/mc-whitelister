use serde::{Deserialize, Serialize};

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum MsOauthResponse {
    Success(MsOauthResponseSuccess),
    Error(MsOauthResponseError),
}
#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct MsOauthResponseSuccess {
    pub token_type: String,
    pub expires_in: u64,
    pub scope: String,
    pub access_token: String,
    pub refresh_token: String,
    //id_token: String,
    pub user_id: String,
    //    foci: u32,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct MsOauthResponseError {
    pub error: String,
    pub error_description: String,
    pub error_codes: Vec<u64>,
    pub timestamp: String,
    pub trace_id: String,
    pub correlation_id: String,
    pub error_uri: String,
}

#[derive(Debug, Serialize)]
pub struct XBLBody {
    #[serde(rename = "Properties")]
    pub properties: XBLProps,
    #[serde(rename = "RelyingParty")]
    pub relying_party: String,
    #[serde(rename = "TokenType")]
    pub token_type: String,
}

impl XBLBody {
    pub fn from(access_token: impl AsRef<str>) -> XBLBody {
        XBLBody {
            properties: XBLProps {
                auth_method: "RPS".to_owned(),
                site_name: "user.auth.xboxlive.com".to_owned(),
                rps_ticket: format!("d={}", access_token.as_ref()),
            },
            relying_party: "http://auth.xboxlive.com".to_owned(),
            token_type: "JWT".to_owned(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct XBLProps {
    #[serde(rename = "AuthMethod")]
    pub auth_method: String,
    #[serde(rename = "SiteName")]
    pub site_name: String,
    #[serde(rename = "RpsTicket")]
    pub rps_ticket: String,
}
//todo: convert to type XBLResponse = Result<SBLXSTSResponseSuccess, XBLXSTSResponseError>;
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum XBLResponse {
    Success(XBLResponseSuccess),
    Error(XBLResponseError),
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct XBLResponseError {
    #[serde(rename = "Identity")]
    pub identity: String,
    #[serde(rename = "XErr")]
    pub err: i32,
    #[serde(rename = "Message")]
    pub message: String,
    #[serde(rename = "Redirect")]
    pub redirect: String,
}
//Again, it will complain if you don't set Content-Type: application/json and Accept: application/json
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct XBLResponseSuccess {
    #[serde(rename = "IssueInstant")]
    pub issue_instant: String,
    #[serde(rename = "NotAfter")]
    pub not_after: String,
    #[serde(rename = "Token")]
    pub token: String,
    #[serde(rename = "DisplayClaims")]
    pub display_claims: XBLResponseDisplayClaims,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct XBLResponseDisplayClaims {
    pub xui: Vec<XBLResponseDisplayClaimsXui>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct XBLResponseDisplayClaimsXui {
    pub uhs: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum McResponse {
    Success(McResponseSuccess),
    Error(McResponseError),
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct McResponseSuccess {
    pub username: String,
    pub roles: Vec<String>,
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i32,
}

#[derive(Debug, Deserialize)]
pub struct McResponseError {}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum McProfileResponse {
    Success(McProfileResponseSuccess),
    Error(McProfileResponseError),
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct McProfileResponseSuccess {
    pub id: String,
    pub name: String,
    pub skins: Vec<McProfileSkin>,
    pub capes: Vec<McProfileCape>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct McProfileSkin {
    pub id: String,
    pub state: String,
    pub url: String,
    pub variant: String,
    pub alias: Option<String>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct McProfileCape {
    pub id: String,
    pub state: String,
    pub url: String,
    pub alias: Option<String>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct McProfileResponseError {
    pub path: String,
    #[serde(rename = "errorType")]
    pub error_type: String,
    pub error: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    #[serde(rename = "developerMessage")]
    pub developer_message: String,
}
