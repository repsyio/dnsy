//! Content filtering: blocklist parsers, the suffix matcher, allowlist and block responses, the
//! persisted ACL rules and list sources.
//!
//! The `fetch` feature adds fetching list sources from URLs on a schedule ([`ListManager`]) and
//! the HTTP client behind it; without it the crate needs no TLS or HTTP stack.

#[cfg(feature = "fetch")]
mod fetch;
#[cfg(feature = "fetch")]
pub mod http;
mod location;
#[cfg(feature = "fetch")]
mod manager;
mod matcher;
mod parse;
mod response;
mod rules;
mod sources;

#[cfg(feature = "fetch")]
pub use fetch::{
    FETCH_TIMEOUT, Fetched, Fetcher, MAX_LIST_BYTES, MAX_REDIRECTS, Validators, is_public,
};
pub use location::{FetchError, Location};
#[cfg(feature = "fetch")]
pub use manager::{ListManager, RefreshError, RefreshOutcome};
pub use matcher::{
    BlockMode, BlocklistError, CUSTOM_LIST, DEFAULT_MAX_ENTRIES, DEFAULT_MAX_INPUT_BYTES,
    FilterLimits, FilterSet, FilterSetBuilder, Verdict,
};
pub use parse::{ListFormat, MAX_LINE_LEN, ParseStats};
pub use response::{BLOCK_TTL, block_response};
pub use rules::{AclAction, AclMatcher, AclRule, FilterError, RuleStore};
pub use sources::{
    CustomRule, FetchRecord, ListSource, LoadedMeta, NewSource, RuleKind, SourceStore,
};

#[cfg(test)]
mod blocklist_tests;
#[cfg(all(test, feature = "fetch"))]
mod http_tests;
#[cfg(test)]
mod parse_edge_tests;
#[cfg(all(test, feature = "fetch"))]
mod source_tests;
