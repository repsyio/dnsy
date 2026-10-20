//! `certs` route group (stub; filled in by its API story).

use utoipa_axum::router::OpenApiRouter;

use crate::state::ApiState;

/// Routes of this group, relative to `/api/v1`.
#[must_use]
pub fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
}
