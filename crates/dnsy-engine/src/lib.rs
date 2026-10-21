//! dnsy-engine: the transport-agnostic request pipeline.
//!
//! Transports (UDP, TCP, `DoT`, `DoH`) only frame bytes, decode them into a
//! [`dnsy_proto::Message`] and call a [`Handler`] with a [`RequestContext`]. [`Engine`] is the
//! pipeline (spec 5.2); [`EngineBuilder::from_config`] assembles it from the configuration and
//! the store. [`RefusedHandler`] remains as a trivial handler for listener tests.

mod builder;
mod engine;
pub mod handler;
mod response;

pub use builder::{EngineBuilder, EngineError, cache_options, dnssec_options};
pub use engine::{Engine, MAX_MISS_WAITERS};
pub use handler::{Admission, Handler, RefusedHandler, RequestContext};
pub use response::{RESPONSE_IP_LIST, ResponseIpPolicy};

#[cfg(test)]
mod tests;
