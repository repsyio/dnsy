//! Client filtering: CIDR and client-certificate ACL, per-client rate limit and
//! their persistence; blocklist parsers, suffix matcher, allowlist and block responses.

mod acl;
mod matcher;
mod parse;
mod ratelimit;
mod response;
mod rules;

pub use acl::{Acl, AclAction, AclMatcher};
pub use matcher::{
    BlockMode, BlocklistError, CUSTOM_LIST, DEFAULT_MAX_ENTRIES, DEFAULT_MAX_INPUT_BYTES,
    FilterLimits, FilterSet, FilterSetBuilder, Verdict,
};
pub use parse::{ListFormat, MAX_LINE_LEN, ParseStats};
pub use ratelimit::{RateLimiter, RateVerdict, client_key};
pub use response::{BLOCK_TTL, block_response};
pub use rules::{AclRule, FilterError, RuleStore};

#[cfg(test)]
mod blocklist_tests;
