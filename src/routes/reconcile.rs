use crate::*;
use axum::{
    extract::State,
    response::{IntoResponse, Response},
};
use reqwest::StatusCode;
use std::sync::Arc;
// use tracing::*;

use axum::debug_handler;
#[debug_handler]
pub async fn reconcile(
    State(state): State<Arc<AppState>>
) -> Result<Response, StatusCode> {

    // let Ok(mut conn) = state.pool.acquire().await else {
    //     error!("failed to aquire db connection");
    //     return Err(StatusCode::INTERNAL_SERVER_ERROR);
    // };
    // todo!()
    crate::reconcile::reconcile_luckperms(&state).await.expect("failed to  reconcile");
    Ok(String::from("Ok").into_response())
    // Ok(axum::response::Html(main_page(account, accounts).into_string()).into_response())
}


