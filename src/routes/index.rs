//use axum::*
use crate::db::*;
use crate::session::*;
use crate::*;
use axum::{
    extract::State,
    response::{self, IntoResponse, Response},
};
use reqwest::StatusCode;
use serde::*;
use sqlx::query_as;
use std::sync::Arc;
use tower_sessions::Session;
use tracing::*;

use maud::{DOCTYPE, Markup, html};

#[derive(Deserialize, Serialize, Debug)]
struct Account {
    microsoft_id: String,
    uuid: String,
    username: String,
    skin_id: String,
    skin_url: String,
}

fn header(title: &str) -> Markup {
    html! {
        (DOCTYPE)
        head {
            title{ (title) }
            // include bootstrap
            script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4" {}
            script src="https://cdn.jsdelivr.net/npm/htmx.org@2.0.10/dist/htmx.min.js" integrity="sha384-H5SrcfygHmAuTDZphMHqBJLc3FhssKjG7w/CeCpFReSfwBWDTKpkzPP8c+cLsK+V" crossorigin="anonymous" {}
            link rel="stylesheet" href="/static/styles.css" {}
        }
    }
}

fn with_common(title: &str, content: Markup) -> Markup {
    html! {
        (header(title))
        body {
            div id="content" {
                (content)
            }
        }
    }
}

// fn main_script() -> Markup {
//     let script = r#"
// // javascript
// window.onload = function() {
//
// }
//
// function remove_account_clicked(uuid) {
//     console.log(uuid);
//     fetch('/accounts/remove', {
//         method: 'POST',
//         headers: {
//             'Content-Type': 'application/json'
//         },
//         body: JSON.stringify({
//             uuid: uuid
//         })
//     }).then(response => response.json())
//     .then(data => {
//         console.log(data);
//         Document.location.reload();
//     });
// }
//         "#;
//
//     html!{
//         script { (script) }
//     }
// }

fn main_page(user: User, accs: Vec<Account>) -> Markup {
    with_common(
        "Accounts",
        html! {
            div {
                h1 { (user.name) }
                a ."bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-full" href="/logout" { "Logout" }
            }
            div ."flex justify-evenly" {
                // minecraft accounts
                div ."content-center" {
                    h1 { "Minecraft accounts" }

                    @for acc in accs {
                        div ."w-96" ."rounded-full" ."p-4" ."grid" ."grid-flow-col" ."grid-rows-3" ."bg-gray-100" id=(format!("{}-row", acc.uuid)) uuid=(acc.uuid) {

                            div ."row-span-3" {
                                div ."mc-face" style=(format!("background-image: url('{}')", acc.skin_url)) {
                                }
                            }
                            div ."col-span-2" { (acc.username) }
                            div ."col-span-2" ."row-span-2" {
                                button ."bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-full" hx-post=(format!("/remove/{}", acc.uuid)) hx-target=(format!("#{}-row", acc.uuid)) hx-swap="outerHTML" { "Remove" }
                            }
                        }
                    }
                    a ."bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded-full" href="/oauth/microsoft" { "add account" }
                }


                div {
                    h1 { "Steam accounts" }
                }
            }


            /*table ."table-auto" ."border-collapse" ."border" ."border-gray-400"  {
                tr {
                    th ."border" ."border-gray-300" { "username" }
                    th ."border" ."border-gray-300" { "remove" }
                }
                @for acc in accs {
                    tr id=(format!("{}-row", acc.uuid)) uuid=(acc.uuid) {
                        td ."border" ."border-gray-300" {
                            div ."mc-face" style=(format!("background-image: url('{}')", acc.skin_url)) {
                            }

                        }
                        td ."border" ."border-gray-300" { (acc.username) }
                        td ."border" ."border-gray-300" {
                            button hx-post=(format!("/remove/{}", acc.uuid)) hx-target=(format!("#{}-row", acc.uuid)) hx-swap="outerHTML" { "Remove" }
                        }
                    }
                }
                tr {
                    td ."border" ."border-gray-300" {}
                    td ."border" ."border-gray-300" {
                        a href="/oauth/microsoft" { "add account" }
                    }
                }
            }*/
            /*(main_script())*/
            script src="/static/scripts.js" {}
        },
    )
}

pub async fn index(
    session: Session,
    State(state): State<Arc<AppState>>,
) -> Result<Response, StatusCode> {
    let Some(user_id): Option<UserID> = session
        .get(UserID::SESSION_KEY)
        .await
        .expect("failed to get user id")
    else {
        return Ok(response::Redirect::to("/login").into_response());
    };

    let Ok(mut conn) = state.pool.acquire().await else {
        error!("failed to aquire db connection");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };

    let account = match query_as!(User, "SELECT * FROM users WHERE id = $1", user_id.0)
        .fetch_one(&mut *conn)
        .await
    {
        Ok(account) => account,
        Err(sqlx::Error::RowNotFound) => {
            warn!("user account row not found");
            session.clear().await;
            return Ok(axum::response::Redirect::temporary("/login").into_response());
        }
        Err(e) => {
            error!("failed to get user account from database: error {e}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let accounts: Vec<Account> = match sqlx::query_as!(
            Account,
            "SELECT microsoft_id, uuid, username, skin_id, skin_url FROM minecraft_profile WHERE user_id = $1",
            user_id.0
        )
        .fetch_all(&mut *conn)
        .await {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to get user accounts: {e:?}");
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

    Ok(axum::response::Html(main_page(account, accounts).into_string()).into_response())
}
