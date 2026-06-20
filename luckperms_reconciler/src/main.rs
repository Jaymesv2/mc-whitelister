

use serde::*;
use tracing::*;
#[derive(Debug, Deserialize)]
struct Config {
    pub authentik_api_key: String,
    pub authentik_user: String,
    pub authentik_server: String,
    pub luckperms_server: String,
    pub luckperms_api_key: String
}

use luckperms_api::apis::{users_api, groups_api};

use authentik_client::apis::core_api;

use std::sync::Arc;


struct AppState {
    luckperms: luckperms_api::apis::configuration::Configuration,
    authentik: authentik_client::apis::configuration::Configuration
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().unwrap();

    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    tracing_subscriber::registry()
        .with(fmt::layer().with_file(true).with_line_number(true))
        .with(EnvFilter::from_default_env())
        .init();

    let config: Config = match envy::from_env::<Config>() {
        Ok(config) => config,
        Err(error) => panic!("{:#?}", error),
    };

    // let client = reqwest::Client::new();

    let state = AppState {
        luckperms: {
            let mut cfg = luckperms_api::apis::configuration::Configuration::new();
            cfg.bearer_access_token = Some(config.luckperms_api_key);
            cfg.base_path = config.luckperms_server;
            // cfg.client = client.clone();
            cfg
        },
        authentik: {
            let mut cfg = authentik_client::apis::configuration::Configuration::new();
            cfg.bearer_access_token = Some(config.authentik_api_key);
            cfg.base_path = config.authentik_server;
            cfg
        }
    };


    reconcile_luckperms(&state).await;
}





async fn reconcile_luckperms(state: &AppState) -> Result<(),()> {
    let x = users_api::get_users(&state.luckperms).await;
    println!("{:?}", x);

    let authentik_users_req = core_api::core_users_list(&state.authentik, 
        None, //Some("minecraft"), // only query certain attributes
        None,
        None,
        None,
        None,
        None,
        None, // groups by name
        None, // groups by pk
        None, //Some(true), // include groups
        None, //Some(false),// include roles
        None, // Some(true), // is active
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(1000), // request up to 1k users
        None,
        None,
        None,
        None,
        None,
        None, //Some(vec![authentik_client::models::user_type_enum::UserTypeEnum::Internal]),
        None,
        None
        ).await.expect("failed to get authentik users");
    // for usr in authentik_users_req.results {
    //     println!("{}: {:?}", usr.username, usr.attributes);
    // }


    Ok(())

    // println!("{:?}", y);
    // let luckperms_groups_api = GroupsApiClient::new(luckperms_api_config.clone());

    
}


#[derive(Debug)]
struct AuthentikGroup {
    name: String,
    member_authentik_ids: Vec<i32>,
    nodes: AuthentikLuckpermsGroupAttribute 
}

async fn get_authentik_groups(state: &AppState) -> Result<Vec<AuthentikGroup>, authentik_client::apis::Error<authentik_client::apis::core_api::CoreGroupsListError>> {
    let authentik_groups_req = core_api::core_groups_list(&state.authentik, 
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        ).await?;

    Ok(authentik_groups_req.results.into_iter().filter_map(|group| {
        let Some(attrs) = group.attributes else {
            info!("skipping group {}, attributes were empty", group.name);
            return None
        };
        let Some(luckperms_data) = attrs.get("luckperms") else {
            info!("skipping group {}, no \"luckperms\" attribute", group.name);
            return None
        };
        let luckperms_data = match serde_json::from_value::<AuthentikLuckpermsGroupAttribute>(luckperms_data.clone()) {
            Ok(s) => s,
            Err(e) => {
                warn!("invalid luckperms attribute on group {}, \"{:?}\"", group.name, e);
                return None
            }
        };
        Some(AuthentikGroup{ 
            name: group.name,
            member_authentik_ids: group.users.unwrap_or_else(|| vec![]),
            nodes: luckperms_data
        })
    }).collect())
}

#[derive(Debug, Deserialize)]
struct AuthentikMinecraftUserAttribute {
    accounts: Vec<AuthentikMinecraftAccount>,
}

#[derive(Debug, Deserialize)]
struct AuthentikMinecraftAccount {
    uuid: String,
    last_updated: Option<String>,
}





#[derive(Debug, Deserialize)]
struct AuthentikLuckpermsGroupAttribute {
    nodes: Vec<AuthentikLuckpermsNode>,
}

#[derive(Debug, Deserialize)]
struct AuthentikLuckpermsNode {
    key: String,
    r#type: String,
    value: bool,
    context: Vec<AuthentikLuckpermsContext>
}

#[derive(Debug, Deserialize)]
struct AuthentikLuckpermsContext {
    key: String,
    value: String
}



