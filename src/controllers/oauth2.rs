use axum_session::SessionNullPool;
// use axum_session::Session;
// use axum::Extension;
// use loco_oauth2::controllers::middleware::OAuth2CookieUser;
// use loco_oauth2::controllers::oauth2::get_authorization_url;
// use loco_oauth2::OAuth2ClientStore;
use crate::models::{o_auth2_sessions, users, users::OAuth2UserProfile};

// use axum_session::SessionNullPool;
// use loco_oauth2::controllers::oauth2::callback;
// use loco_oauth2::OAuth2ClientStore;
// use crate::models::{o_auth2_sessions, users, users::OAuth2UserProfile};

use loco_rs::prelude::*;
// use crate::{
    // models::{o_auth2_sessions, users, users::OAuth2UserProfile},
    // views::auth::LoginResponse,
// };

use loco_oauth2::controllers::{
    oauth2::{google_authorization_url, google_callback_jwt},
};

/// The authorization URL for the `OAuth2` flow
/// This will redirect the user to the `OAuth2` provider's login page
/// and then to the callback URL

/// # Arguments
/// * `session` - The axum session
/// * `oauth_store` - The `OAuth2ClientStore` extension
/// # Returns
/// The HTML response with the link to the `OAuth2` provider's login page
/// # Errors
/// `loco_rs::errors::Error` - When the `OAuth2` client cannot be retrieved
// pub async fn google_authorization_url(
//     session: Session<SessionNullPool>,
//     Extension(oauth2_store): Extension<OAuth2ClientStore>,
// ) -> Result<String> {
//     // Get the `google` Authorization Code Grant client from the `OAuth2ClientStore`
//     let mut client = oauth2_store
//         .get_authorization_code_client("google")
//         .await
//         .map_err(|e| {
//             tracing::error!("Error getting client: {:?}", e);
//             Error::InternalServerError
//         })?;
//     // Get the authorization URL and save the csrf token in the session
//     let auth_url = get_authorization_url(session, &mut client).await;
//     drop(client);
//     Ok(auth_url)
// }

/// The callback URL for the `OAuth2` flow
/// This will exchange the code for a token and then get the user profile
/// then upsert the user and the session and set the token in a short live
/// cookie Lastly, it will redirect the user to the protected URL
/// # Generics
/// * `T` - The user profile, should implement `DeserializeOwned` and `Send`
/// * `U` - The user model, should implement `OAuth2UserTrait` and `ModelTrait`
/// * `V` - The session model, should implement `OAuth2SessionsTrait` and `ModelTrait`
/// * `W` - The database pool
/// # Arguments
/// * `ctx` - The application context
/// * `session` - The axum session
/// * `params` - The query parameters
/// * `oauth2_store` - The `OAuth2ClientStore` extension
/// # Return
/// * `Result<impl IntoResponse>` - The response with the jwt token
/// # Errors
/// * `loco_rs::errors::Error`
// pub async fn google_callback_jwt(
//     State(ctx): State<AppContext>,
//     session: Session<SessionNullPool>,
//     Query(params): Query<AuthParams>,
//     Extension(oauth2_store): Extension<OAuth2ClientStore>,
// ) -> Result<impl IntoResponse> {
//     let mut client = oauth2_store
//         .get_authorization_code_client("google")
//         .await
//         .map_err(|e| {
//             tracing::error!("Error getting client: {:?}", e);
//             Error::InternalServerError
//         })?;
//     // Get JWT secret from the config
//     let jwt_secret = ctx.config.get_jwt_config()?;
//     let user = callback_jwt::<OAuth2UserProfile, users::Model, o_auth2_sessions::Model, SessionNullPool>(&ctx, session, params, &mut client).await?;
//     drop(client);
//     let token = user
//         .generate_jwt(&jwt_secret.secret, &jwt_secret.expiration)
//         .or_else(|_| unauthorized("unauthorized!"))?;
//     // Return jwt token
//     Ok(token)
// }

// async fn protected(
//     State(ctx): State<AppContext>,
//     // Extract the user from the Cookie via middleware
//     user: OAuth2CookieUser<OAuth2UserProfile, users::Model, o_auth2_sessions::Model>,
// ) -> Result<Response> {
//     let user: &users::Model = user.as_ref();
//     let jwt_secret = ctx.config.get_jwt_config()?;
//     // Generate a JWT token
//     let token = user
//         .generate_jwt(&jwt_secret.secret, &jwt_secret.expiration)
//         .or_else(|_| unauthorized("unauthorized!"))?;
//     // Return the user and the token in JSON format
//     format::json(LoginResponse::new(user, &token))
// }


pub fn routes() -> Routes {
    Routes::new()
        .prefix("api/oauth2")
        .add("/google", get(google_authorization_url::<SessionNullPool>))
        // Route for the JWT callback
        .add(
            "/google/callback/jwt",
            get(google_callback_jwt::<
                OAuth2UserProfile,
                users::Model,
                o_auth2_sessions::Model,
                SessionNullPool,
            >),
        )
}
