// ACME account storage.
//
// An ACME account *is* a key pair.  The CA identifies the account by
// that key; everything else -- the account URL a given directory
// assigns it, the contact addresses -- is a property of the key's
// registration at one CA.  One key may be registered at any number
// of directories (Let's Encrypt production and staging, a private
// step-ca, ...), and the operator may point a certificate at a
// different directory at any time without the account changing.
//
// So the only state persisted here is the key itself, at
// `{state_dir}/acme/account-key.pem`.  Registrations are rediscovered
// from the key on first use after startup (`create_from_key` finds
// the existing account or creates one) and cached in memory per
// directory URL for the life of the process.  Nothing on disk binds
// the key to a URL, so a config change can never leave a stale
// binding behind.
//
// Earlier releases stored `{state_dir}/acme_account.json`, an
// instant-acme `AccountCredentials` blob that embedded the directory
// URL and was consulted *instead of* the configured `server=`.  On
// first start the key is lifted out of that file; the file itself is
// left in place so a downgrade keeps working.

use anyhow::{Context, anyhow, bail};
use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use instant_acme::{Account, AccountCredentials, Key};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::sync::OnceCell;

const TARGET: &str = "hypershunt::acme";

/// One registration of the account key at one directory.
struct Registration {
    account: Arc<Account>,
    /// Contact registered (or confirmed) at this directory by the
    /// first certificate that used it in this process.
    contact: Option<String>,
}

/// Process-wide holder of the ACME account key and its per-directory
/// registrations.  Shared by every `AcmeManager`; one per `state-dir`.
pub struct AccountStore {
    key_path: PathBuf,
    legacy_path: PathBuf,
    /// PKCS#8 DER of the account key, loaded or generated on first
    /// use so a config that never issues a certificate never touches
    /// the state directory.
    key: OnceCell<Vec<u8>>,
    /// Directory URL -> registration.  One cell per directory: two
    /// blocks starting together against the same CA register the
    /// key once rather than racing, while a slow CA holds up only
    /// the certificates that use it.  The map lock is never held
    /// across a network call.
    registrations: Mutex<HashMap<String, Arc<OnceCell<Registration>>>>,
}

impl AccountStore {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            key_path: state_dir.join("acme").join("account-key.pem"),
            legacy_path: state_dir.join("acme_account.json"),
            key: OnceCell::new(),
            registrations: Mutex::new(HashMap::new()),
        }
    }

    /// The account as registered at `directory_url`, registering it
    /// on first use.  `email` is the contact to attach to that
    /// registration; when another certificate already registered
    /// this directory with a different contact in this process the
    /// first one stands and the mismatch is logged, since a CA holds
    /// one contact set per account.
    pub async fn account(
        &self,
        directory_url: &str,
        email: Option<&str>,
    ) -> anyhow::Result<Arc<Account>> {
        let cell = {
            let mut regs = self
                .registrations
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            regs.entry(directory_url.to_owned()).or_default().clone()
        };
        let reg = cell
            .get_or_try_init(|| self.register(directory_url, email))
            .await?;
        if contact_conflicts(reg.contact.as_deref(), email) {
            tracing::warn!(target: TARGET,
                directory = directory_url,
                registered = reg.contact.as_deref().unwrap_or(""),
                requested = email.unwrap_or(""),
                "ACME contact differs between certificates using \
                 the same directory; keeping the first"
            );
        }
        Ok(reg.account.clone())
    }

    /// Present the key to `directory_url`, creating the account there
    /// if the CA has not seen it before, and attach the contact.
    async fn register(
        &self,
        directory_url: &str,
        email: Option<&str>,
    ) -> anyhow::Result<Registration> {
        let der = self.key_der().await?;
        let key = Key::from_pkcs8_der(PrivatePkcs8KeyDer::from(der.as_slice()))
            .context("parsing ACME account key")?;
        let pkcs8 = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der));
        tracing::info!(target: TARGET, directory = directory_url,
            "registering ACME account key");
        let (account, _creds) = Account::builder()
            .context("building ACME account")?
            .create_from_key((key, pkcs8), directory_url.to_owned())
            .await
            .context("registering ACME account")?;

        if let Some(email) = email {
            let mailto = format!("mailto:{email}");
            // Best effort: a rejected contact must not block issuance.
            // Running this on every first use also means a changed
            // `email=` reaches the CA on the next restart.
            if let Err(e) = account.update_contacts(&[&mailto]).await {
                tracing::warn!(target: TARGET,
                    directory = directory_url, email,
                    "could not set ACME account contact: {e}");
            }
        }

        Ok(Registration {
            account: Arc::new(account),
            contact: email.map(str::to_owned),
        })
    }

    async fn key_der(&self) -> anyhow::Result<Vec<u8>> {
        let der = self
            .key
            .get_or_try_init(|| async {
                let key_path = self.key_path.clone();
                let legacy_path = self.legacy_path.clone();
                tokio::task::spawn_blocking(move || {
                    load_or_create_key(&key_path, &legacy_path)
                })
                .await
                .context("account key task")?
            })
            .await?;
        Ok(der.clone())
    }
}

/// Whether a requested contact disagrees with the one already
/// registered.  Absence on either side is not a conflict.
fn contact_conflicts(
    registered: Option<&str>,
    requested: Option<&str>,
) -> bool {
    matches!((registered, requested), (Some(a), Some(b)) if a != b)
}

/// Load the account key from `key_path`, lifting it out of the legacy
/// credentials file or generating a fresh one when absent.  Returns
/// PKCS#8 DER.
fn load_or_create_key(
    key_path: &Path,
    legacy_path: &Path,
) -> anyhow::Result<Vec<u8>> {
    if key_path.exists() {
        let pem = std::fs::read(key_path).with_context(|| {
            format!("reading ACME account key {}", key_path.display())
        })?;
        return pkcs8_der_from_pem(&pem).with_context(|| {
            format!("parsing ACME account key {}", key_path.display())
        });
    }

    let (der, origin) = if legacy_path.exists() {
        let json = std::fs::read_to_string(legacy_path).with_context(|| {
            format!("reading {}", legacy_path.display())
        })?;
        let creds: AccountCredentials = serde_json::from_str(&json)
            .with_context(|| {
                format!("parsing legacy {}", legacy_path.display())
            })?;
        (creds.private_key().secret_pkcs8_der().to_vec(), "migrated")
    } else {
        let (_, pkcs8) =
            Key::generate_pkcs8().context("generating ACME account key")?;
        (pkcs8.secret_pkcs8_der().to_vec(), "generated")
    };

    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("creating {}", parent.display())
        })?;
    }
    write_private_file(key_path, pem_from_pkcs8_der(&der).as_bytes())
        .with_context(|| {
            format!("writing ACME account key {}", key_path.display())
        })?;
    tracing::info!(target: TARGET, path = %key_path.display(), origin,
        "ACME account key");
    Ok(der)
}

/// Wrap PKCS#8 DER in a `PRIVATE KEY` PEM block.
fn pem_from_pkcs8_der(der: &[u8]) -> String {
    let b64 = BASE64_STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for line in b64.as_bytes().chunks(64) {
        // chunks of ASCII base64 are always valid UTF-8
        pem.push_str(std::str::from_utf8(line).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    pem
}

/// Extract PKCS#8 DER from a PEM file holding exactly one private key.
fn pkcs8_der_from_pem(pem: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut reader = std::io::Cursor::new(pem);
    match rustls_pemfile::private_key(&mut reader)? {
        Some(PrivateKeyDer::Pkcs8(k)) => Ok(k.secret_pkcs8_der().to_vec()),
        Some(_) => bail!("expected a PKCS#8 PRIVATE KEY block"),
        None => Err(anyhow!("no private key found")),
    }
}

fn write_private_file(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(data)?;
    // O_CREAT only applies the mode to a new file; enforce it on an
    // existing one too.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;

    fn fresh_der() -> Vec<u8> {
        Key::generate_pkcs8().unwrap().1.secret_pkcs8_der().to_vec()
    }

    #[cfg(unix)]
    fn mode_of(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn pem_round_trips_der() {
        let der = fresh_der();
        let pem = pem_from_pkcs8_der(&der);
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(pem.lines().all(|l| l.len() <= 64));
        assert_eq!(pkcs8_der_from_pem(pem.as_bytes()).unwrap(), der);
    }

    #[test]
    fn pem_without_key_is_an_error() {
        assert!(pkcs8_der_from_pem(b"not a pem").is_err());
    }

    #[test]
    fn generates_key_when_nothing_exists() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("acme").join("account-key.pem");
        let legacy = dir.path().join("acme_account.json");

        let first = load_or_create_key(&key_path, &legacy).unwrap();
        assert!(key_path.exists());
        assert!(!legacy.exists());
        #[cfg(unix)]
        assert_eq!(mode_of(&key_path), 0o600);
        // Key::from_pkcs8_der accepting it proves it is a usable key.
        Key::from_pkcs8_der(PrivatePkcs8KeyDer::from(first.as_slice()))
            .unwrap();

        let second = load_or_create_key(&key_path, &legacy).unwrap();
        assert_eq!(first, second);
    }

    fn legacy_json(der: &[u8]) -> String {
        format!(
            r#"{{"id":"https://acme.example/acct/1",
                 "key_pkcs8":"{}",
                 "directory":"https://acme.example/directory"}}"#,
            BASE64_URL_SAFE_NO_PAD.encode(der)
        )
    }

    #[test]
    fn migrates_key_from_legacy_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("acme").join("account-key.pem");
        let legacy = dir.path().join("acme_account.json");
        let der = fresh_der();
        std::fs::write(&legacy, legacy_json(&der)).unwrap();

        let got = load_or_create_key(&key_path, &legacy).unwrap();
        assert_eq!(got, der);
        assert_eq!(pkcs8_der_from_pem(&std::fs::read(&key_path).unwrap())
            .unwrap(), der);
        // Left behind on purpose so a downgrade still finds it.
        assert!(legacy.exists());
    }

    #[test]
    fn pem_wins_over_legacy_when_both_exist() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("acme").join("account-key.pem");
        let legacy = dir.path().join("acme_account.json");
        let pem_der = fresh_der();
        let legacy_der = fresh_der();
        std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
        std::fs::write(&key_path, pem_from_pkcs8_der(&pem_der)).unwrap();
        std::fs::write(&legacy, legacy_json(&legacy_der)).unwrap();

        let got = load_or_create_key(&key_path, &legacy).unwrap();
        assert_eq!(got, pem_der);
    }

    #[test]
    fn unparseable_legacy_is_an_error_not_a_new_key() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("acme").join("account-key.pem");
        let legacy = dir.path().join("acme_account.json");
        std::fs::write(&legacy, "{").unwrap();
        // Silently generating a new key here would orphan the
        // operator's real account; surface the problem instead.
        assert!(load_or_create_key(&key_path, &legacy).is_err());
        assert!(!key_path.exists());
    }

    #[test]
    fn contact_conflict_rules() {
        assert!(!contact_conflicts(None, None));
        assert!(!contact_conflicts(Some("a@x"), None));
        assert!(!contact_conflicts(None, Some("a@x")));
        assert!(!contact_conflicts(Some("a@x"), Some("a@x")));
        assert!(contact_conflicts(Some("a@x"), Some("b@x")));
    }

    #[test]
    fn store_paths_follow_state_dir() {
        let store = AccountStore::new(Path::new("/var/lib/hs"));
        assert_eq!(
            store.key_path,
            Path::new("/var/lib/hs/acme/account-key.pem")
        );
        assert_eq!(
            store.legacy_path,
            Path::new("/var/lib/hs/acme_account.json")
        );
    }
}
