//! dnsy-resolver: upstream client, cache, load balancing and the validating forwarder.

mod cache;
pub mod forward;
pub mod groups;
pub mod upstream;

pub use cache::{Cache, CacheKey, CacheLookup, CacheStats, RefreshGuard, Refreshes};
pub use upstream::{
    TlsRoots, Upstream, UpstreamClient, UpstreamConfig, UpstreamError, UpstreamTransport,
};
