//! Offline administration commands: they open the database and zones directory directly.

use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use dnsy_auth::{TokenService, UserService};
use dnsy_config::Config;
use dnsy_core::{Role, Scope};
use dnsy_dnssec::{Algorithm, DigestType, KeyRole, KeyState, SystemClock, ds_for};
use dnsy_proto::Name;
use dnsy_zone::{
    KeyStore, Passphrase, ZoneSigning, ZoneStore, export_bind, passphrase_from_environment,
};

use crate::cli::{
    DnssecCommand, KeysCommand, PassphraseCommand, RolloverCommand, TokenCommand, UserCommand,
    ZoneCommand,
};
use crate::{Error, Result, db_path, open_store};

/// Environment variable holding the password for `user create` / `reset-password`.
const PASSWORD_ENV: &str = "DNSY_PASSWORD";
/// Environment variable holding the passphrase of a key backup bundle.
const BACKUP_PASSPHRASE_ENV: &str = "DNSY_DNSSEC_BACKUP_PASSPHRASE";
/// Environment variable holding the new key passphrase for `dnssec passphrase change`.
const NEW_PASSPHRASE_ENV: &str = "DNSY_DNSSEC_NEW_PASSPHRASE";
/// Shortest passphrase accepted for a bundle or the key store.
const MIN_PASSPHRASE_LEN: usize = 12;

pub(crate) fn openapi(out: &mut impl Write) -> Result<()> {
    writeln!(out, "{}", dnsy_api::openapi().to_pretty_json()?)?;
    Ok(())
}

/// Validates the file; every problem goes to the error, a clean file prints a summary.
pub(crate) fn config_check(path: &Path, out: &mut impl Write) -> Result<()> {
    let config = Config::load(path)?;
    let mut problems = Vec::new();
    match ZoneStore::open(&config.zones.dir) {
        Ok(zones) => {
            for (file, reason) in zones.load_errors() {
                problems.push(format!("zone {file}: {reason}"));
            }
        }
        Err(e) => problems.push(format!(
            "zones directory {}: {e}",
            config.zones.dir.display()
        )),
    }
    for (what, file) in [
        ("dot.cert", &config.dot.cert),
        ("dot.key", &config.dot.key),
        ("dot.client_ca", &config.dot.client_ca),
        ("doh.cert", &config.doh.cert),
        ("doh.key", &config.doh.key),
        ("api.tls_cert", &config.api.tls_cert),
        ("api.tls_key", &config.api.tls_key),
        ("dnssec.trust_anchor_file", &config.dnssec.trust_anchor_file),
        (
            "dnssec.key_passphrase_file",
            &config.dnssec.key_passphrase_file,
        ),
    ] {
        if let Some(file) = file
            && !file.is_file()
        {
            problems.push(format!("{what}: {} is not a readable file", file.display()));
        }
    }
    if !problems.is_empty() {
        return Err(Error::msg(format!(
            "configuration has problems:\n  {}",
            problems.join("\n  ")
        )));
    }
    for warning in config.warnings() {
        writeln!(out, "warning: {warning}")?;
    }
    writeln!(out, "{}: ok", path.display())?;
    Ok(())
}

pub(crate) fn migrate(config: &Config, status: bool, out: &mut impl Write) -> Result<()> {
    let path = db_path(config);
    let rows = if status {
        dnsy_store::migration_status_at(&path)?
    } else {
        open_store(config)?;
        dnsy_store::migration_status_at(&path)?
    };
    for m in rows {
        let state = m
            .applied_at
            .map_or_else(|| "pending".to_owned(), |at| format!("applied at {at}"));
        writeln!(out, "{:04} {:<24} {state}", m.version, m.name)?;
    }
    Ok(())
}

fn parse_role(s: &str) -> Result<Role> {
    serde_json::from_value(serde_json::Value::String(s.to_owned()))
        .map_err(|_| Error::msg(format!("unknown role `{s}` (admin, operator or viewer)")))
}

fn parse_scope(s: &str) -> Result<Scope> {
    serde_json::from_value(serde_json::Value::String(s.to_owned())).map_err(|_| {
        Error::msg(format!(
            "unknown scope `{s}` (dns:query, api:read, api:write or admin)"
        ))
    })
}

/// The password from stdin, `DNSY_PASSWORD`, or a generated one; the flag says it was generated.
fn password(from_stdin: bool, input: &mut impl std::io::BufRead) -> Result<(String, bool)> {
    if from_stdin {
        let mut line = String::new();
        input.read_line(&mut line)?;
        let line = line.trim_end_matches(['\r', '\n']).to_owned();
        if line.is_empty() {
            return Err(Error::msg("no password on stdin"));
        }
        return Ok((line, false));
    }
    if let Some(p) = std::env::var(PASSWORD_ENV).ok().filter(|p| !p.is_empty()) {
        return Ok((p, false));
    }
    let mut raw = [0_u8; 18];
    rand::fill(&mut raw[..]);
    Ok((URL_SAFE_NO_PAD.encode(raw), true))
}

pub(crate) async fn user(config: &Config, cmd: UserCommand, out: &mut impl Write) -> Result<()> {
    let users = UserService::new(open_store(config)?);
    match cmd {
        UserCommand::Create {
            username,
            role,
            password_stdin,
        } => {
            let role = parse_role(&role)?;
            let (pw, generated) = password(password_stdin, &mut std::io::stdin().lock())?;
            let user = users.create(&username, &pw, role).await?;
            writeln!(
                out,
                "created {} ({:?}, id {})",
                user.username, user.role, user.id.0
            )?;
            if generated {
                writeln!(out, "password (shown once): {pw}")?;
            }
        }
        UserCommand::ResetPassword {
            username,
            password_stdin,
        } => {
            let id = find_user(&users, &username).await?.id;
            let (pw, generated) = password(password_stdin, &mut std::io::stdin().lock())?;
            users.set_password(id, &pw).await?;
            writeln!(out, "password of {username} changed")?;
            if generated {
                writeln!(out, "password (shown once): {pw}")?;
            }
        }
        UserCommand::Disable { username } => {
            let id = find_user(&users, &username).await?.id;
            users.set_disabled(id, true).await?;
            writeln!(out, "{username} disabled")?;
        }
        UserCommand::Enable { username } => {
            let id = find_user(&users, &username).await?.id;
            users.set_disabled(id, false).await?;
            writeln!(out, "{username} enabled")?;
        }
        UserCommand::List => {
            for u in users.list().await? {
                let state = if u.is_active() { "" } else { " (disabled)" };
                writeln!(out, "{:<6} {:<24} {:?}{state}", u.id.0, u.username, u.role)?;
            }
        }
    }
    Ok(())
}

async fn find_user(users: &UserService, username: &str) -> Result<dnsy_auth::User> {
    users
        .list()
        .await?
        .into_iter()
        .find(|u| u.username.eq_ignore_ascii_case(username))
        .ok_or_else(|| Error::msg(format!("no user `{username}`")))
}

pub(crate) async fn token(config: &Config, cmd: TokenCommand, out: &mut impl Write) -> Result<()> {
    let TokenCommand::Create {
        user,
        name,
        scopes,
        expires_days,
    } = cmd;
    let store = open_store(config)?;
    let owner = find_user(&UserService::new(store.clone()), &user).await?;
    let scopes = scopes
        .iter()
        .map(|s| parse_scope(s))
        .collect::<Result<Vec<_>>>()?;
    let expires_at = expires_days.map(|d| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |t| i64::try_from(t.as_secs()).unwrap_or(i64::MAX));
        now.saturating_add(i64::from(d) * 86_400)
    });
    let (secret, meta) = TokenService::new(store)
        .create(owner.id, &name, &scopes, expires_at)
        .await?;
    writeln!(out, "token {} created for {user}", meta.id.0)?;
    writeln!(out, "secret (shown once): {secret}")?;
    Ok(())
}

fn zone_name(s: &str) -> Result<Name> {
    Ok(Name::from_ascii(s)
        .map_err(|e| Error::msg(format!("`{s}` is not a domain name: {e}")))?
        .to_lowercase())
}

fn key_store(config: &Config) -> Result<KeyStore> {
    let passphrase = passphrase_from_environment(config.dnssec.key_passphrase_file.as_deref())?;
    Ok(KeyStore::open(
        open_store(config)?,
        passphrase,
        Arc::new(SystemClock),
    ))
}

pub(crate) async fn zone(config: &Config, cmd: ZoneCommand, out: &mut impl Write) -> Result<()> {
    let ZoneCommand::Export { name, signed } = cmd;
    let origin = zone_name(&name)?;
    let zones = ZoneStore::open(&config.zones.dir)?;
    let snapshot = zones.snapshot();
    let zone = snapshot.get(&origin).cloned().ok_or_else(|| {
        Error::msg(format!(
            "no zone `{origin}` in {}",
            config.zones.dir.display()
        ))
    })?;
    if !signed {
        write!(out, "{}", export_bind(&zone, None))?;
        return Ok(());
    }
    if zone.dnssec.as_ref().is_none_or(|p| !p.enabled) {
        return Err(Error::msg(format!(
            "zone `{origin}` has no enabled dnssec policy"
        )));
    }
    ZoneSigning::new(Arc::clone(&zones), key_store(config)?)
        .sign_due()
        .await;
    let snapshot = zones.snapshot();
    let signed = snapshot
        .signed(&origin)
        .ok_or_else(|| Error::msg(format!("zone `{origin}` could not be signed (see the log)")))?;
    write!(out, "{}", export_bind(&zone, Some(signed)))?;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02X}");
        s
    })
}

fn key_role(s: &str) -> Result<KeyRole> {
    KeyRole::parse(s).ok_or_else(|| Error::msg(format!("unknown key role `{s}` (csk, ksk or zsk)")))
}

fn algorithm(n: u8) -> Result<Algorithm> {
    let a = Algorithm::from(n);
    if a.can_sign() {
        Ok(a)
    } else {
        Err(Error::msg(format!(
            "algorithm {n} cannot sign (use 13 or 15)"
        )))
    }
}

/// A passphrase from the first line of stdin or from `env`; never printed.
fn passphrase_input(
    from_stdin: bool,
    env: &str,
    input: &mut impl std::io::BufRead,
) -> Result<Passphrase> {
    let text = if from_stdin {
        let mut line = String::new();
        input.read_line(&mut line)?;
        line.trim_end_matches(['\r', '\n']).to_owned()
    } else {
        std::env::var(env).unwrap_or_default()
    };
    if text.chars().count() < MIN_PASSPHRASE_LEN {
        return Err(Error::msg(format!(
            "the passphrase needs at least {MIN_PASSPHRASE_LEN} characters (stdin with the flag, else ${env})"
        )));
    }
    Ok(Passphrase::new(text))
}

pub(crate) async fn dnssec(
    config: &Config,
    cmd: DnssecCommand,
    out: &mut impl Write,
) -> Result<()> {
    let keys = key_store(config)?;
    match cmd {
        DnssecCommand::Keys(cmd) => dnssec_keys(&keys, cmd, out).await,
        DnssecCommand::Rollover(RolloverCommand::Abort { zone, role }) => {
            let role = role.as_deref().map(key_role).transpose()?;
            let aborted = keys.abort_rollover(&zone_name(&zone)?, role).await?;
            for k in &aborted {
                writeln!(
                    out,
                    "aborted {} rollover: key {} (tag {}) withdrawn{}",
                    k.role,
                    k.id,
                    k.key_tag,
                    if k.ds_confirmed_at.is_some() {
                        "; its DS was confirmed, remove it at the registrar"
                    } else {
                        ""
                    }
                )?;
            }
            Ok(())
        }
        DnssecCommand::DsConfirmed { zone, key } => {
            let zone = zone_name(&zone)?;
            let id = match key {
                Some(id) => id,
                None => waiting_for_ds(&keys, &zone).await?,
            };
            keys.confirm_ds(id).await?;
            writeln!(out, "DS of key {id} confirmed")?;
            Ok(())
        }
        DnssecCommand::Passphrase(PassphraseCommand::Change {
            new_passphrase_stdin,
        }) => {
            let new = passphrase_input(
                new_passphrase_stdin,
                NEW_PASSPHRASE_ENV,
                &mut std::io::stdin().lock(),
            )?;
            let n = keys.change_passphrase(new).await?;
            writeln!(
                out,
                "{n} key(s) re-encrypted; configure the new passphrase before the next start"
            )?;
            Ok(())
        }
    }
}

/// The one published KSK or CSK of `zone` whose DS the operator has not confirmed.
async fn waiting_for_ds(keys: &KeyStore, zone: &Name) -> Result<i64> {
    let waiting: Vec<_> = keys
        .keys(zone)
        .await?
        .into_iter()
        .filter(|k| {
            k.role.is_sep() && k.state == KeyState::Published && k.ds_confirmed_at.is_none()
        })
        .collect();
    match waiting.as_slice() {
        [k] => Ok(k.id),
        [] => Err(Error::msg(format!(
            "zone `{zone}` has no published KSK or CSK waiting for a DS"
        ))),
        _ => Err(Error::msg(
            "several keys wait for a DS; pick one with --key",
        )),
    }
}

/// `dnssec keys export` and `import`: the passphrase never reaches the output.
async fn key_backup(keys: &KeyStore, cmd: KeysCommand, out: &mut impl Write) -> Result<()> {
    match cmd {
        KeysCommand::Export {
            file,
            zone,
            passphrase_stdin,
        } => {
            let pass = passphrase_input(
                passphrase_stdin,
                BACKUP_PASSPHRASE_ENV,
                &mut std::io::stdin().lock(),
            )?;
            let zone = zone.as_deref().map(zone_name).transpose()?;
            keys.export_bundle_to_file(zone.as_ref(), &pass, &file)
                .await?;
            writeln!(out, "keys exported to {}", file.display())?;
        }
        KeysCommand::Import {
            file,
            passphrase_stdin,
        } => {
            let pass = passphrase_input(
                passphrase_stdin,
                BACKUP_PASSPHRASE_ENV,
                &mut std::io::stdin().lock(),
            )?;
            let added = keys.import_bundle_from_file(&file, &pass).await?;
            writeln!(out, "{added} key(s) imported")?;
        }
        _ => {}
    }
    Ok(())
}

async fn dnssec_keys(keys: &KeyStore, cmd: KeysCommand, out: &mut impl Write) -> Result<()> {
    match cmd {
        cmd @ (KeysCommand::Export { .. } | KeysCommand::Import { .. }) => {
            return key_backup(keys, cmd, out).await;
        }
        KeysCommand::List { zone } => {
            let zone = zone_name(&zone)?;
            for k in keys.keys(&zone).await? {
                writeln!(
                    out,
                    "{:<4} {:<4} alg {:<3} tag {:<5} {:<10} ds-confirmed: {}",
                    k.id,
                    k.role,
                    k.algorithm.number(),
                    k.key_tag,
                    k.state,
                    k.ds_confirmed_at.is_some()
                )?;
            }
        }
        KeysCommand::Generate {
            zone,
            role,
            algorithm: alg,
        } => {
            let k = keys
                .generate_key(&zone_name(&zone)?, key_role(&role)?, algorithm(alg)?)
                .await?;
            writeln!(
                out,
                "generated key {} (tag {}, {})",
                k.id, k.key_tag, k.state
            )?;
        }
        KeysCommand::Rollover {
            zone,
            role,
            algorithm: alg,
        } => {
            let k = keys
                .start_rollover(&zone_name(&zone)?, key_role(&role)?, algorithm(alg)?)
                .await?;
            writeln!(
                out,
                "rollover started: new key {} (tag {}, {})",
                k.id, k.key_tag, k.state
            )?;
        }
        KeysCommand::Ds { zone } => {
            let zone = zone_name(&zone)?;
            let mut found = false;
            for (record, dnskey) in keys.dnskeys(&zone).await? {
                if !record.role.is_sep()
                    || !matches!(record.state, KeyState::Published | KeyState::Active)
                {
                    continue;
                }
                for digest in [DigestType::Sha256, DigestType::Sha384] {
                    let ds = ds_for(&zone, &dnskey, digest)?;
                    writeln!(
                        out,
                        "{zone} IN DS {} {} {} {}",
                        ds.key_tag,
                        ds.algorithm,
                        ds.digest_type,
                        hex(&ds.digest)
                    )?;
                    found = true;
                }
            }
            if !found {
                return Err(Error::msg(format!(
                    "zone `{zone}` has no published key to make a DS from"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_from_stdin_strips_newline_and_rejects_empty() {
        let (p, generated) = password(true, &mut std::io::Cursor::new(b"s3cret\r\n")).unwrap();
        assert_eq!((p.as_str(), generated), ("s3cret", false));
        assert!(password(true, &mut std::io::Cursor::new(b"\n")).is_err());
    }

    #[test]
    fn roles_and_scopes_parse() {
        assert_eq!(parse_role("viewer").unwrap(), Role::Viewer);
        assert!(parse_role("root").is_err());
        assert_eq!(parse_scope("dns:query").unwrap(), Scope::DnsQuery);
        assert!(parse_scope("all").is_err());
    }
}
