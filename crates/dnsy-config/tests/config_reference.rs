//! The configuration reference page must list exactly the keys the schema accepts.

use std::collections::{BTreeMap, BTreeSet};

const MODEL: &str = include_str!("../src/model.rs");
const REFERENCE: &str = include_str!("../../../docs/book/src/configuration.md");

/// Maps each struct in `model.rs` to its `(field, type)` pairs.
fn structs() -> BTreeMap<String, Vec<(String, String)>> {
    let mut out = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in MODEL.lines() {
        if let Some(rest) = line.strip_prefix("pub struct ") {
            let name = rest.split_whitespace().next().unwrap_or_default();
            current = Some(name.to_owned());
            out.insert(name.to_owned(), Vec::new());
        } else if line == "}" {
            current = None;
        } else if let (Some(name), Some((key, ty))) = (
            &current,
            line.strip_prefix("    pub ")
                .and_then(|f| f.split_once(':')),
        ) {
            let ty = ty.trim().trim_end_matches(',').to_owned();
            out.get_mut(name).unwrap().push((key.to_owned(), ty));
        }
    }
    out
}

/// Every `section.key` leaf the schema defines, walking from `Config`.
fn schema_keys() -> BTreeSet<String> {
    fn walk(
        all: &BTreeMap<String, Vec<(String, String)>>,
        ty: &str,
        prefix: &str,
        out: &mut BTreeSet<String>,
    ) {
        for (key, field_ty) in &all[ty] {
            let path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            if all.contains_key(field_ty) {
                walk(all, field_ty, &path, out);
            } else {
                out.insert(path);
            }
        }
    }
    let all = structs();
    let mut out = BTreeSet::new();
    walk(&all, "Config", "", &mut out);
    out
}

/// Splits on commas that are not inside parentheses.
fn items(cell: &str) -> Vec<&str> {
    let (mut depth, mut start, mut out) = (0_u32, 0, Vec::new());
    for (i, c) in cell.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                out.push(&cell[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&cell[start..]);
    out
}

/// Every `section.key` the reference table lists.
fn documented_keys() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for row in REFERENCE.lines().filter(|l| l.starts_with("| `")) {
        let cells: Vec<&str> = row.trim_matches('|').split('|').map(str::trim).collect();
        let section = cells[0].trim_matches('`');
        for item in items(cells[1]) {
            let key = item.trim().trim_start_matches('`');
            let key = key.split('`').next().unwrap_or_default();
            if !key.is_empty() {
                out.insert(format!("{section}.{key}"));
            }
        }
    }
    out
}

#[test]
fn config_reference_lists_all_keys() {
    let schema = schema_keys();
    let documented = documented_keys();
    assert!(schema.len() > 40, "schema scan found only {schema:?}");
    let missing: Vec<_> = schema.difference(&documented).collect();
    let unknown: Vec<_> = documented.difference(&schema).collect();
    assert!(
        missing.is_empty() && unknown.is_empty(),
        "configuration.md is out of sync with dnsy-config: undocumented {missing:?}, not in schema {unknown:?}"
    );
}

#[test]
fn example_config_keys_are_documented() {
    let example: toml::Table = include_str!("../../../examples/dnsy.toml").parse().unwrap();
    let documented = documented_keys();
    for (section, value) in &example {
        let table = value.as_table().unwrap();
        for (key, value) in table {
            if let Some(nested) = value.as_table() {
                for nested_key in nested.keys() {
                    assert!(documented.contains(&format!("{section}.{key}.{nested_key}")));
                }
            } else {
                assert!(
                    documented.contains(&format!("{section}.{key}")),
                    "{section}.{key} missing from the reference"
                );
            }
        }
    }
}
