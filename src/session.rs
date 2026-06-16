use serde::*;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OAuthExchangeData {
    pub pkce: String,
    pub csrf: String,
}

impl OAuthExchangeData {
    pub const SESSION_KEY: &str = "OAuthExchangeData";
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MSOAuthExchangeData {
    pub pkce: String,
    pub csrf: String,
}

impl MSOAuthExchangeData {
    pub const SESSION_KEY: &str = "OAuthExchangeData";
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserID(pub String);
impl UserID {
    pub const SESSION_KEY: &str = "UserID";
}

// pub struct SessionData {
//     pub state: SessionState,
// }
//
// pub enum SessionState {
//     LoggedIn,
//     Enrolement(EnrolementState),
// }
//
// pub enum EnrolementState {}

/*pub fn get_state(mut ) {

}*/
