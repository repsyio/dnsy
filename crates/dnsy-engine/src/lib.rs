//! dnsy-engine: the transport-agnostic request handler.
//!
//! Transports (UDP, TCP, later `DoT` and `DoH`) only frame bytes, decode them into a
//! [`dnsy_proto::Message`] and call a [`Handler`] with a [`RequestContext`]. The full request
//! pipeline is wired in a later story; [`RefusedHandler`] is the stub until then.

pub mod handler;

pub use handler::{Handler, RefusedHandler, RequestContext};
