use anyhow::Result;
use beacon_core::{DnsConfig, TlsConfig};
use rcgen::{generate_simple_self_signed, CertificateParams, DistinguishedName, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::process::Command;
use tokio::sync::RwLock;

/// Executes a certificate issuance or renewal request. The lifecycle decides
/// when to issue and where to install the resulting files.
pub trait AcmeTransport: Send + Sync {
    fn execute<'a>(
        &'a self,
        tls: &'a TlsConfig,
        dns: &'a DnsConfig,
        domains: &'a [String],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(PathBuf, PathBuf)>> + Send + 'a>>;
}

/// Adapter to the external lego client using the shared capability registry.
pub struct LegoTransport;
fn lego_command(
    tls: &TlsConfig,
    dns: &DnsConfig,
    domains: &[String],
    renew: bool,
) -> Result<Command> {
    let spec = beacon_core::provider::provider_spec(&dns.provider)?;
    let environment = spec.lego_environment(dns)?;
    let mut cmd = Command::new("lego");
    cmd.arg("--accept-tos")
        .arg("--email")
        .arg(&tls.acme_email)
        .arg("--path")
        .arg(&tls.acme_work_dir)
        .arg("--dns")
        .arg(spec.lego_name);
    for domain in domains {
        cmd.arg("-d").arg(domain);
    }
    cmd.arg(if renew { "renew" } else { "run" });
    if renew {
        cmd.arg("--days").arg(tls.acme_renew_days.to_string());
    }
    for (key, value) in environment {
        cmd.env(key, value);
    }
    Ok(cmd)
}
impl AcmeTransport for LegoTransport {
    fn execute<'a>(
        &'a self,
        tls: &'a TlsConfig,
        dns: &'a DnsConfig,
        domains: &'a [String],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(PathBuf, PathBuf)>> + Send + 'a>>
    {
        Box::pin(async move {
            // Validate before creating files or attempting a process.
            let spec = beacon_core::provider::provider_spec(&dns.provider)?;
            spec.lego_environment(dns)?;
            tokio::fs::create_dir_all(&tls.acme_work_dir).await?;
            let certs_dir = Path::new(&tls.acme_work_dir).join("certificates");
            let renew = locate_lego_certificates(&certs_dir, domains)
                .await?
                .is_some();
            let mut cmd = lego_command(tls, dns, domains, renew)?;
            if tls.acme_staging {
                cmd.arg("--server")
                    .arg("https://acme-staging-v02.api.letsencrypt.org/directory");
            }
            let action = if renew { "renew" } else { "run" };
            let out = cmd
                .output()
                .await
                .map_err(|e| anyhow::anyhow!("could not execute lego: {e}"))?;
            if !out.status.success() {
                anyhow::bail!("lego {action} failed");
            }
            locate_lego_certificates(&certs_dir, domains)
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!("lego finished but certificate files were not found")
                })
        })
    }
}

pub struct TlsManager {
    certs: Arc<RwLock<HashMap<String, (Vec<CertificateDer<'static>>, Vec<u8>)>>>,
    /// Sync mirror of `certs` so the sync SNI resolver never touches async.
    sync_certs: std::sync::RwLock<HashMap<String, (Vec<CertificateDer<'static>>, Vec<u8>)>>,
}

impl TlsManager {
    pub fn new() -> Self {
        Self {
            certs: Arc::new(RwLock::new(HashMap::new())),
            sync_certs: std::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Sync read for the SNI resolver (hot handshake path, no await allowed).
    pub fn get_cert_sync(&self, domain: &str) -> Option<(Vec<CertificateDer<'static>>, Vec<u8>)> {
        self.sync_certs.read().ok()?.get(domain).cloned()
    }

    pub async fn get_cert(
        &self,
        domain: &str,
    ) -> Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let certs = self.certs.read().await;
        let (chain, key_der) = certs.get(domain)?;
        let key = PrivateKeyDer::try_from(key_der.clone()).ok()?;
        Some((chain.clone(), key))
    }

    pub async fn generate_self_signed(&self, domain: &str) -> Result<()> {
        let mut params = CertificateParams::new(vec![domain.to_string()])?;
        params.distinguished_name = DistinguishedName::new();
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

        let key_pair = KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;
        let cert_der = cert.der().clone();
        let key_der = key_pair.serialize_der();

        {
            let mut certs = self.certs.write().await;
            certs.insert(
                domain.to_string(),
                (vec![cert_der.clone()], key_der.clone()),
            );
        }
        if let Ok(mut sc) = self.sync_certs.write() {
            sc.insert(domain.to_string(), (vec![cert_der], key_der));
        }

        tracing::info!("Generated self-signed cert for {}", domain);
        Ok(())
    }

    pub async fn drop_cert(&self, domain: &str) {
        {
            let mut certs = self.certs.write().await;
            certs.remove(domain);
        }
        if let Ok(mut sc) = self.sync_certs.write() {
            sc.remove(domain);
        }
        tracing::info!("Dropped cert for {}", domain);
    }

    pub async fn load_from_pem(&self, domain: &str, cert_pem: &str, key_pem: &str) -> Result<()> {
        use rustls::pki_types::pem::PemObject;

        let certs: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(cert_pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
        let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())?;
        let key_der = key.secret_der().to_vec();

        {
            let mut store = self.certs.write().await;
            store.insert(domain.to_string(), (certs.clone(), key_der.clone()));
        }
        if let Ok(mut sc) = self.sync_certs.write() {
            sc.insert(domain.to_string(), (certs, key_der));
        }

        tracing::info!("Loaded cert for {}", domain);
        Ok(())
    }

    pub fn generate_self_signed_pem(&self, domains: &[String]) -> Result<(String, String)> {
        let names = if domains.is_empty() {
            vec!["localhost".to_string()]
        } else {
            domains.to_vec()
        };
        let ck = generate_simple_self_signed(names)?;
        Ok((ck.cert.pem(), ck.key_pair.serialize_pem()))
    }

    pub async fn ensure_pem_files(
        &self,
        cert_pem_path: &str,
        key_pem_path: &str,
        domains: &[String],
    ) -> Result<()> {
        let cert_exists = Path::new(cert_pem_path).exists();
        let key_exists = Path::new(key_pem_path).exists();
        if cert_exists && key_exists {
            let cert_meta = tokio::fs::metadata(cert_pem_path).await?;
            let key_meta = tokio::fs::metadata(key_pem_path).await?;
            if cert_meta.len() > 0 && key_meta.len() > 0 {
                return Ok(());
            }
        }

        let cert_dir = Path::new(cert_pem_path)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| Path::new(".").to_path_buf());
        let key_dir = Path::new(key_pem_path)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| Path::new(".").to_path_buf());
        tokio::fs::create_dir_all(cert_dir).await?;
        tokio::fs::create_dir_all(key_dir).await?;

        let (cert_pem, key_pem) = self.generate_self_signed_pem(domains)?;
        tokio::fs::write(cert_pem_path, cert_pem).await?;
        tokio::fs::write(key_pem_path, key_pem).await?;
        tracing::warn!(
            "Generated self-signed TLS cert at {} and {}",
            cert_pem_path,
            key_pem_path
        );
        Ok(())
    }

    pub async fn ensure_edge_certificate(
        &self,
        tls: &TlsConfig,
        dns: &DnsConfig,
        domains: &[String],
    ) -> Result<()> {
        self.ensure_edge_certificate_with_transport(tls, dns, domains, &LegoTransport)
            .await
    }

    pub async fn ensure_edge_certificate_with_transport(
        &self,
        tls: &TlsConfig,
        dns: &DnsConfig,
        domains: &[String],
        transport: &dyn AcmeTransport,
    ) -> Result<()> {
        if tls.acme_enabled {
            match self.ensure_acme(tls, dns, domains, transport).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if !tls.auto_self_signed {
                        return Err(e);
                    }
                    tracing::warn!(
                        "ACME certificate acquisition failed, falling back to self-signed: {}",
                        e
                    );
                }
            }
        }

        if tls.auto_self_signed {
            self.ensure_pem_files(&tls.cert_pem_path, &tls.key_pem_path, domains)
                .await?;
            return Ok(());
        }

        if pem_files_exist(&tls.cert_pem_path, &tls.key_pem_path).await? {
            return Ok(());
        }
        Err(anyhow::anyhow!(
            "TLS cert/key not found and auto_self_signed is disabled"
        ))
    }

    pub async fn ensure_acme(
        &self,
        tls: &TlsConfig,
        dns: &DnsConfig,
        domains: &[String],
        transport: &dyn AcmeTransport,
    ) -> Result<()> {
        if tls.acme_email.trim().is_empty() {
            return Err(anyhow::anyhow!("ACME email is required"));
        }
        let mut dedup = domains
            .iter()
            .map(|d| d.trim().to_string())
            .filter(|d| !d.is_empty())
            .collect::<Vec<_>>();
        dedup.sort();
        dedup.dedup();
        if dedup.is_empty() {
            return Err(anyhow::anyhow!(
                "No domains available for ACME certificate request"
            ));
        }

        let (crt, key) = transport.execute(tls, dns, &dedup).await?;

        ensure_parent_dirs(&tls.cert_pem_path, &tls.key_pem_path).await?;
        tokio::fs::copy(crt, &tls.cert_pem_path).await?;
        tokio::fs::copy(key, &tls.key_pem_path).await?;
        tracing::info!(
            "ACME certificate ready at {} and {}",
            tls.cert_pem_path,
            tls.key_pem_path
        );
        Ok(())
    }
}

async fn ensure_parent_dirs(cert_pem_path: &str, key_pem_path: &str) -> Result<()> {
    let cert_dir = Path::new(cert_pem_path)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| Path::new(".").to_path_buf());
    let key_dir = Path::new(key_pem_path)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| Path::new(".").to_path_buf());
    tokio::fs::create_dir_all(cert_dir).await?;
    tokio::fs::create_dir_all(key_dir).await?;
    Ok(())
}

async fn pem_files_exist(cert_pem_path: &str, key_pem_path: &str) -> Result<bool> {
    let cert_exists = Path::new(cert_pem_path).exists();
    let key_exists = Path::new(key_pem_path).exists();
    if !(cert_exists && key_exists) {
        return Ok(false);
    }
    let cert_meta = tokio::fs::metadata(cert_pem_path).await?;
    let key_meta = tokio::fs::metadata(key_pem_path).await?;
    Ok(cert_meta.len() > 0 && key_meta.len() > 0)
}

async fn locate_lego_certificates(
    certs_dir: &Path,
    domains: &[String],
) -> Result<Option<(PathBuf, PathBuf)>> {
    for domain in domains {
        let candidates = [
            certs_dir.join(format!("{}.crt", domain)),
            certs_dir.join(format!("{}.key", domain)),
            certs_dir.join(format!(
                "_wildcard_.{}.crt",
                domain.trim_start_matches("*.")
            )),
            certs_dir.join(format!(
                "_wildcard_.{}.key",
                domain.trim_start_matches("*.")
            )),
        ];
        if candidates[0].exists() && candidates[1].exists() {
            return Ok(Some((candidates[0].clone(), candidates[1].clone())));
        }
        if candidates[2].exists() && candidates[3].exists() {
            return Ok(Some((candidates[2].clone(), candidates[3].clone())));
        }
    }

    if !certs_dir.exists() {
        return Ok(None);
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Fixture {
        cert: PathBuf,
        key: PathBuf,
        domains: Mutex<Vec<String>>,
    }
    impl AcmeTransport for Fixture {
        fn execute<'a>(
            &'a self,
            _: &'a TlsConfig,
            _: &'a DnsConfig,
            domains: &'a [String],
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(PathBuf, PathBuf)>> + Send + 'a>,
        > {
            *self.domains.lock().unwrap() = domains.to_vec();
            Box::pin(async move { Ok((self.cert.clone(), self.key.clone())) })
        }
    }

    #[tokio::test]
    async fn lifecycle_normalizes_domains_and_installs_transport_output() {
        let root = std::env::temp_dir().join(format!(
            "beacon-tls-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        tokio::fs::create_dir_all(&root).await.unwrap();
        let fixture = Fixture {
            cert: root.join("source.crt"),
            key: root.join("source.key"),
            domains: Mutex::new(Vec::new()),
        };
        tokio::fs::write(&fixture.cert, "certificate fixture")
            .await
            .unwrap();
        tokio::fs::write(&fixture.key, "key fixture").await.unwrap();
        let tls = TlsConfig {
            acme_email: "ops@example.invalid".into(),
            cert_pem_path: root.join("installed/cert").to_string_lossy().into(),
            key_pem_path: root.join("installed/key").to_string_lossy().into(),
            ..TlsConfig::default()
        };
        let dns = DnsConfig {
            provider: String::new(),
            api_key: String::new(),
            secret_key: String::new(),
            default_ip: "192.0.2.1".into(),
        };
        let manager = TlsManager::new();
        manager
            .ensure_acme(
                &tls,
                &dns,
                &["b.example".into(), "a.example".into(), "b.example".into()],
                &fixture,
            )
            .await
            .unwrap();
        assert_eq!(
            *fixture.domains.lock().unwrap(),
            vec!["a.example", "b.example"]
        );
        assert_eq!(
            tokio::fs::read_to_string(&tls.cert_pem_path).await.unwrap(),
            "certificate fixture"
        );
        assert_eq!(
            tokio::fs::read_to_string(&tls.key_pem_path).await.unwrap(),
            "key fixture"
        );
        tokio::fs::write(&fixture.cert, "renewed certificate fixture")
            .await
            .unwrap();
        manager
            .ensure_acme(&tls, &dns, &["example.com".into()], &fixture)
            .await
            .unwrap();
        assert_eq!(
            tokio::fs::read_to_string(&tls.cert_pem_path).await.unwrap(),
            "renewed certificate fixture"
        );
        tokio::fs::remove_dir_all(root).await.unwrap();
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    struct Fail;
    #[test]
    fn lego_dispatch_and_renewal_plan_are_data_driven() {
        use beacon_core::provider::ProviderError;
        let tls = TlsConfig::default();
        let mut dns = DnsConfig {
            provider: "porkbun".into(),
            api_key: uuid::Uuid::new_v4().to_string(),
            secret_key: uuid::Uuid::new_v4().to_string(),
            default_ip: "192.0.2.1".into(),
        };
        for renew in [false, true] {
            let command = lego_command(&tls, &dns, &["example.com".into()], renew).unwrap();
            let args: Vec<_> = command
                .as_std()
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            assert!(args.windows(2).any(|p| p == ["--dns", "porkbun"]));
            assert!(args
                .iter()
                .any(|a| a == if renew { "renew" } else { "run" }));
            assert_eq!(args.iter().any(|a| a == "--days"), renew);
            assert_eq!(command.as_std().get_envs().count(), 2);
        }
        dns.provider = "cloudflare".into();
        assert_eq!(
            lego_command(&tls, &dns, &[], false)
                .err()
                .unwrap()
                .downcast_ref::<ProviderError>(),
            Some(&ProviderError::Skeleton)
        );
        dns.provider = "unsupported".into();
        assert_eq!(
            lego_command(&tls, &dns, &[], false)
                .err()
                .unwrap()
                .downcast_ref::<ProviderError>(),
            Some(&ProviderError::Unsupported)
        );
        dns.provider = "porkbun".into();
        dns.api_key.clear();
        assert_eq!(
            lego_command(&tls, &dns, &[], false)
                .err()
                .unwrap()
                .downcast_ref::<ProviderError>(),
            Some(&ProviderError::MissingConfiguration)
        );
    }

    #[tokio::test]
    async fn renewal_never_selects_an_unrelated_certificate() {
        let root = std::env::temp_dir().join(format!("beacon-renew-{}", std::process::id()));
        tokio::fs::create_dir_all(&root).await.unwrap();
        tokio::fs::write(root.join("other.example.com.crt"), "fixture")
            .await
            .unwrap();
        tokio::fs::write(root.join("other.example.com.key"), "fixture")
            .await
            .unwrap();
        assert!(locate_lego_certificates(&root, &["example.com".into()])
            .await
            .unwrap()
            .is_none());
        tokio::fs::write(root.join("_wildcard_.example.com.crt"), "fixture")
            .await
            .unwrap();
        tokio::fs::write(root.join("_wildcard_.example.com.key"), "fixture")
            .await
            .unwrap();
        let pair = locate_lego_certificates(&root, &["*.example.com".into()])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pair.0, root.join("_wildcard_.example.com.crt"));
        tokio::fs::remove_dir_all(root).await.unwrap();
    }
    impl AcmeTransport for Fail {
        fn execute<'a>(
            &'a self,
            _: &'a TlsConfig,
            _: &'a DnsConfig,
            _: &'a [String],
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(PathBuf, PathBuf)>> + Send + 'a>,
        > {
            Box::pin(async { anyhow::bail!("fixture failure") })
        }
    }
    #[tokio::test]
    async fn failure_validation_and_fallback() {
        let dir = std::env::temp_dir().join(format!("beacon-lifecycle-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut tls = TlsConfig {
            acme_enabled: true,
            auto_self_signed: false,
            cert_pem_path: dir.join("cert").to_string_lossy().into(),
            key_pem_path: dir.join("key").to_string_lossy().into(),
            ..Default::default()
        };
        let dns = DnsConfig {
            provider: "cloudflare".into(),
            api_key: String::new(),
            secret_key: String::new(),
            default_ip: "192.0.2.1".into(),
        };
        let manager = TlsManager::new();
        assert!(manager
            .ensure_acme(&tls, &dns, &["example.com".into()], &Fail)
            .await
            .unwrap_err()
            .to_string()
            .contains("email is required"));
        tls.acme_email = "ops@example.com".into();
        assert!(manager
            .ensure_acme(&tls, &dns, &[], &Fail)
            .await
            .unwrap_err()
            .to_string()
            .contains("No domains"));
        assert!(manager
            .ensure_edge_certificate_with_transport(&tls, &dns, &["example.com".into()], &Fail)
            .await
            .is_err());
        tls.auto_self_signed = true;
        manager
            .ensure_edge_certificate_with_transport(&tls, &dns, &["example.com".into()], &Fail)
            .await
            .unwrap();
        assert!(pem_files_exist(&tls.cert_pem_path, &tls.key_pem_path)
            .await
            .unwrap());
        let cert = tokio::fs::read_to_string(&tls.cert_pem_path).await.unwrap();
        let key = tokio::fs::read_to_string(&tls.key_pem_path).await.unwrap();
        manager
            .load_from_pem("example.com", &cert, &key)
            .await
            .unwrap();
        assert!(manager.get_cert_sync("example.com").is_some());
        tokio::fs::write(dir.join("example.com.crt"), "fixture")
            .await
            .unwrap();
        tokio::fs::write(dir.join("example.com.key"), "fixture")
            .await
            .unwrap();
        assert!(locate_lego_certificates(&dir, &["example.com".into()])
            .await
            .unwrap()
            .is_some());
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }
}
