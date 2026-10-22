//! Client filtering: CIDR and client-certificate ACL, per-client rate limit and
//! their persistence; blocklist parsers, suffix matcher, allowlist and block responses; list
//! sources fetched from files or URLs on a schedule and swapped in atomically.

mod acl;
mod fetch;
pub mod http;
mod manager;
mod matcher;
mod parse;
mod ratelimit;
mod response;
mod rules;
mod sources;

pub use acl::{Acl, AclAction, AclMatcher};
pub use fetch::{
    FETCH_TIMEOUT, FetchError, Fetched, Fetcher, Location, MAX_LIST_BYTES, MAX_REDIRECTS,
    Validators, is_public,
};
pub use manager::{ListManager, RefreshError, RefreshOutcome};
pub use matcher::{
    BlockMode, BlocklistError, CUSTOM_LIST, DEFAULT_MAX_ENTRIES, DEFAULT_MAX_INPUT_BYTES,
    FilterLimits, FilterSet, FilterSetBuilder, Verdict,
};
pub use parse::{ListFormat, MAX_LINE_LEN, ParseStats};
pub use ratelimit::{RateLimiter, RateVerdict, client_key};
pub use response::{BLOCK_TTL, block_response};
pub use rules::{AclRule, FilterError, RuleStore};
pub use sources::{
    CustomRule, FetchRecord, ListSource, LoadedMeta, NewSource, RuleKind, SourceStore,
};

#[cfg(test)]
mod blocklist_tests;
#[cfg(test)]
mod http_tests;
#[cfg(test)]
mod parse_edge_tests;
#[cfg(test)]
mod source_tests;
