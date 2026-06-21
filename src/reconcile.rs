use serde::*;
use std::collections::HashSet;
use tracing::*;
use crate::AppState;

use luckperms_api::apis::{users_api, groups_api};

use authentik_client::apis::core_api;
use std::collections::HashMap;
use std::sync::Arc;
use axum::http::StatusCode;
use uuid::Uuid;


#[derive(Debug, Clone, Serialize, Deserialize)]
struct Account {
    uuid: String,
    username: String,
    user_id: String
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAccount {
    uuid: Uuid,
    username: String
}

pub async fn reconcile_luckperms(state: &Arc<AppState>) -> Result<(),()> {
    let Ok(mut conn) = state.pool.acquire().await else {
        error!("failed to aquire db connection");
        panic!("lazy");
    };

    let agroups: Vec<AuthentikGroup> = get_authentik_groups(&state).await.expect("failed to get authentik groups");
    let lgroups = groups_api::get_groups(&state.luckperms).await.expect("failed to get luckperms groups");
    
    // maps users to a list of groups
    let user_auid_lp_groups: HashMap<&String, Vec<&String>> = {
        let mut acc = HashMap::new();
        for agroup in agroups.iter() {
            for auid in &agroup.member_authentik_uids {
                acc.entry(auid).or_insert( vec![] ).push(&agroup.data.name );
            }
        }
        acc
    };

    let luckperms_group_names: HashSet<&String> = agroups.iter().map(|x| &x.data.name).collect();

    // ensure all of the groups exist
    // I think this is O(n^2) but i'm too lazy to make it O(n*log(n))
    for agroup in &agroups {
        if lgroups.iter().find(|x| **x == agroup.data.name).is_none() {
            info!("authentik group {} did not exist in luckperms, creating minecraft group named {}", agroup.name, agroup.data.name);
            groups_api::create_group(&state.luckperms, Some(luckperms_api::models::new_group::NewGroup { name: agroup.data.name.clone() })).await.expect(&format!("failed to create group {}", agroup.name));
        }
    }
    
    // since all of the groups exist (big assumption i know) we set their permissions
    for agroup in &agroups {
        info!("setting group permissions for authentik group {} named {}", agroup.name, agroup.data.name);
        groups_api::set_group_nodes(&state.luckperms, &agroup.data.name, Some(agroup.data.clone().into())).await.expect("failed to set group nodes");
    }

    let accounts: Vec<Account> = match sqlx::query_as!(
            Account,
            "SELECT user_id, username, uuid FROM minecraft_profile"
        )
        .fetch_all(&mut *conn)
        .await {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to get user accounts: {e:?}");
                todo!("lazy")
                // return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

    let mut authentik_uid_uuid_mapping: HashMap<String, Vec<ResponseAccount>> = HashMap::new();
    for i in accounts {

        if let Ok(iuuid) = Uuid::parse_str(&i.uuid) {
            authentik_uid_uuid_mapping.entry(i.user_id).or_insert( vec![] ).push(ResponseAccount {
                uuid: iuuid,
                username: i.username
            });
        } else {
            warn!("acount {} has an invalid uuid in the database", i.username)
        }
    }

    
    error!("{authentik_uid_uuid_mapping:?}");

    use uuid::Uuid;

    let luckperms_users: Vec<Uuid> = users_api::get_users(&state.luckperms).await.expect("failed to get luckperms users");
    
    for account in authentik_uid_uuid_mapping.values().flat_map(|x| x.iter()) {
        if luckperms_users.iter().find(|uuid| account.uuid == **uuid).is_none() {
            info!("creating user \"{}\" with uuid \"{}\" in luckperms", account.username, account.uuid);
            users_api::create_user(&state.luckperms, Some(luckperms_api::models::new_user::NewUser::new(account.uuid, account.username.clone())) ).await.expect("failed to create luckperms user");
        }
    }

    info!("created luckperms users");
 
    // you have to collect this iter because the flatmap function can't be persisted across awaits :(
    for (auid, account) in authentik_uid_uuid_mapping.iter().flat_map(|(uid, v)| v.iter().map(move |x| (uid, x))).collect::<Vec<_>>() {
        let user_uuid: String = format!("{}", account.uuid.hyphenated());
        let user_data = users_api::get_user(&state.luckperms, &user_uuid ).await.expect("failed to get user data");

        info!("data for {}: {:?}", account.username, user_data);

        // SEMANTICS
        // If a user has groups that are defined in authentik but they don't have in authentik they
        // should be removed
        // If they have a group in authentik but not in luckperms then it should be added.
        // Any other groups should be ignored.
    
        let user_groups = user_data.parent_groups.unwrap_or_else(|| vec![]);

        let expected_groups = user_auid_lp_groups.get(auid).expect("failed to find groups for user");
        info!("expecting {} to have groups: {:?}", account.username, expected_groups);

        let to_remove: Vec<&String> = user_groups.iter().filter(|gname| 
             luckperms_group_names.contains(gname) && expected_groups.iter().find(|n| *n == gname).is_none()
        ).collect();

        if !to_remove.is_empty() {
            info!("removing groups {:?} from {}", to_remove, account.username);
            users_api::clear_user_nodes(&state.luckperms, &user_uuid, Some(
                to_remove.into_iter().map(|name| luckperms_api::models::new_node::NewNode::new(format!("group.{}", name )) ).collect()
            )).await.expect("failed to remove extra groups")
        }

        let to_add: Vec<&String> = expected_groups.iter().filter(|gname| 
             luckperms_group_names.contains(*gname) && !user_groups.iter().find(|n| n == *gname).is_some() 
        ).copied().collect();

        if !to_add.is_empty() {
            info!("adding groups {:?} to {}", to_add, account.username);

            users_api::add_user_nodes(&state.luckperms, &user_uuid, None, Some(
                to_add.into_iter().map(|name| luckperms_api::models::new_node::NewNode { key: format!("group.{}", name ), value: Some(true), context: None, expiry: None } ).collect()
            )).await.expect("failed to remove extra groups");
        }
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct AuthentikGroup {
    name: String,
    member_authentik_uids: Vec<String>,
    data: AuthentikLuckpermsGroupAttribute 
}

async fn get_authentik_groups(state: &Arc<AppState>) -> Result<Vec<AuthentikGroup>, authentik_client::apis::Error<authentik_client::apis::core_api::CoreGroupsListError>> {
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
            member_authentik_uids: group.users_obj.unwrap_or_else(|| vec![]).into_iter().map(|x| x.uid).collect(),
            data: luckperms_data
        })
    }).collect())
}

#[derive(Debug, Clone, Deserialize)]
struct AuthentikMinecraftUserAttribute {
    accounts: Vec<AuthentikMinecraftAccount>,
}

#[derive(Debug, Clone, Deserialize)]
struct AuthentikMinecraftAccount {
    uuid: String,
    last_updated: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct AuthentikLuckpermsGroupAttribute {
    name: String,
    nodes: Vec<AuthentikLuckpermsNode>,
}

impl Into<Vec<luckperms_api::models::new_node::NewNode>> for AuthentikLuckpermsGroupAttribute {
    fn into(self) ->  Vec<luckperms_api::models::new_node::NewNode> {
        self.nodes.into_iter().map(|x| 
            luckperms_api::models::new_node::NewNode {
               key: x.key,
               value: Some(x.value),
               context: x.context.map(|u| u.into_iter().map(|y|
                    luckperms_api::models::context::Context {
                        key: y.key,
                        value: y.value
                    }
               ).collect() ),
               expiry: None
            }
        ).collect()
    }
}

#[derive(Debug, Clone, Deserialize)]
struct AuthentikLuckpermsNode {
    key: String,
    // r#type: String,
    value: bool,
    context: Option<Vec<AuthentikLuckpermsContext>>
}

#[derive(Debug, Clone, Deserialize)]
struct AuthentikLuckpermsContext {
    key: String,
    value: String
}
