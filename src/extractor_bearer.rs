use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{header::AUTHORIZATION, request::Parts, StatusCode},
};

pub struct ExtractBearer(pub Option<String>);

#[async_trait]
impl<S> FromRequestParts<S> for ExtractBearer
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if let Some(val) = parts.headers.get(AUTHORIZATION) {
            const SCHEME: &str = "Bearer";

            let slice = val.as_bytes();
            if (slice.starts_with(SCHEME.as_bytes())
                || slice.starts_with(SCHEME.to_lowercase().as_bytes()))
                && slice.len() > SCHEME.len()
                && slice[SCHEME.len()] == b' '
            {
                return Ok(ExtractBearer(Some(String::from(val.to_str().unwrap()))));
            }
        }
        Err((
            StatusCode::BAD_REQUEST,
            "`Authorization` header or `Bearer` scheme is missing",
        ))
    }
}
