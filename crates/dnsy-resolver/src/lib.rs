//! dnsy-resolver: upstream client, cache, load balancing and the validating forwarder.

mod cache;
pub mod forward;
pub mod groups;
pub mod upstream;

pub use cache::{
    Cache, CacheKey, CacheLookup, CacheOptions, CacheStats, Joined, PrefetchOptions, RefreshGuard,
    RefreshWait, Refreshes, ServeStaleOptions,
};
pub use upstream::{
    TlsRoots, Upstream, UpstreamClient, UpstreamConfig, UpstreamError, UpstreamTransport,
};
