//! dnsy-resolver: upstream client, cache, load balancing and the validating forwarder.

mod cache;

pub use cache::{Cache, CacheKey, CacheLookup, CacheStats};
