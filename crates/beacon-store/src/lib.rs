#[cfg(all(feature = "test-seams", not(debug_assertions)))]
compile_error!("test-seams is restricted to debug test builds");

use anyhow::Result;
use beacon_core::{AuditLog, OperationRecord, Site};
use chrono::{DateTime, Utc};
use sqlx_core::{pool::Pool, row::Row};
use sqlx_postgres::{PgPoolOptions, Postgres};
use std::time::Duration;
use uuid::Uuid;

pub struct Store {
    pool: Pool<Postgres>,
    site_refresh: tokio::sync::Mutex<()>,
    #[cfg(any(test, feature = "test-seams"))]
    seam: std::sync::RwLock<Option<std::sync::Arc<dyn TestSeam>>>,
}

/// Failure and scheduling hooks exist only in explicitly selected test builds.
#[cfg(any(test, feature = "test-seams"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestPoint {
    AfterSiteRead,
    BeforeSiteReread,
    BeforeListSites,
    AfterListSites,
    AfterSiteDelete,
}

#[cfg(any(test, feature = "test-seams"))]
pub trait TestSeam: Send + Sync {
    fn visit(
        &self,
        point: TestPoint,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>>;
}

impl Store {
    /// Hold from before loading a site snapshot until after publishing it.
    pub async fn lock_site_refresh(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.site_refresh.lock().await
    }

    #[cfg(any(test, feature = "test-seams"))]
    pub fn set_test_seam(&self, seam: Option<std::sync::Arc<dyn TestSeam>>) {
        *self.seam.write().expect("test seam lock") = seam;
    }

    #[cfg(any(test, feature = "test-seams"))]
    async fn test_visit(&self, point: TestPoint) -> Result<()> {
        let seam = self.seam.read().expect("test seam lock").clone();
        if let Some(seam) = seam {
            seam.visit(point).await?;
        }
        Ok(())
    }

    pub async fn connect(database_url: &str) -> Result<Self> {
        let db_url = database_url.to_string();
        let handle = tokio::spawn(async move {
            PgPoolOptions::new()
                .max_connections(5)
                .acquire_timeout(Duration::from_secs(8))
                .connect(&db_url)
                .await
        });

        let pool = match tokio::time::timeout(Duration::from_secs(20), handle).await {
            Ok(joined) => {
                let result = joined
                    .map_err(|e| anyhow::anyhow!("database connect task join error: {}", e))?;
                result.map_err(|e| anyhow::anyhow!("database connect failed: {}", e))?
            }
            Err(_) => return Err(anyhow::anyhow!("database connect timeout after 20s")),
        };

        tokio::time::timeout(
            Duration::from_secs(8),
            sqlx_core::query::query("SELECT 1").execute(&pool),
        )
        .await
        .map_err(|_| anyhow::anyhow!("database ping timeout after 8s"))?
        .map_err(|e| anyhow::anyhow!("database ping failed: {}", e))?;

        Ok(Self {
            pool,
            site_refresh: tokio::sync::Mutex::new(()),
            #[cfg(any(test, feature = "test-seams"))]
            seam: std::sync::RwLock::new(None),
        })
    }

    pub async fn run_migrations(&self) -> Result<()> {
        let statements = migration_statements();

        for stmt in statements {
            sqlx_core::query::query(stmt).execute(&self.pool).await?;
        }
        Ok(())
    }

    #[cfg(feature = "game_forward")]
    pub async fn list_forwards(&self) -> Result<Vec<beacon_forward::GameForward>> {
        let rows = sqlx_core::query::query(
            "SELECT id, game_name, public_host, public_port, protocol, target_host, target_port, forward_mode, tunnel_path, owner FROM game_forwards ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| beacon_forward::GameForward {
                id: r.get("id"),
                game_name: r.get("game_name"),
                public_host: r.get("public_host"),
                public_port: r.get::<i32, _>("public_port") as u16,
                protocol: parse_protocol(r.get::<String, _>("protocol")),
                target_host: r.get("target_host"),
                target_port: r.get::<i32, _>("target_port") as u16,
                forward_mode: parse_mode(r.get::<String, _>("forward_mode")),
                tunnel_path: r.get("tunnel_path"),
                owner: r.get("owner"),
            })
            .collect())
    }

    #[cfg(feature = "game_forward")]
    pub async fn upsert_forward(&self, f: &beacon_forward::GameForward) -> Result<()> {
        sqlx_core::query::query(
            r#"INSERT INTO game_forwards (id, game_name, public_host, public_port, protocol, target_host, target_port, forward_mode, tunnel_path, owner)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
               ON CONFLICT (id) DO UPDATE SET
                 game_name=EXCLUDED.game_name, public_host=EXCLUDED.public_host,
                 public_port=EXCLUDED.public_port, protocol=EXCLUDED.protocol,
                 target_host=EXCLUDED.target_host, target_port=EXCLUDED.target_port,
                 forward_mode=EXCLUDED.forward_mode, tunnel_path=EXCLUDED.tunnel_path,
                 owner=EXCLUDED.owner, updated_at=NOW()"#,
        )
        .bind(&f.id).bind(&f.game_name).bind(&f.public_host)
        .bind(f.public_port as i32).bind(protocol_str(f.protocol))
        .bind(&f.target_host).bind(f.target_port as i32)
        .bind(mode_str(f.forward_mode)).bind(&f.tunnel_path).bind(&f.owner)
        .execute(&self.pool).await?;
        Ok(())
    }

    #[cfg(feature = "game_forward")]
    pub async fn delete_forward(&self, id: &str) -> Result<bool> {
        let res = sqlx_core::query::query("DELETE FROM game_forwards WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn list_sites(&self) -> Result<Vec<Site>> {
        #[cfg(any(test, feature = "test-seams"))]
        self.test_visit(TestPoint::BeforeListSites).await?;
        let rows = sqlx_core::query::query(
            "SELECT id, domain, subdomain, handler_type, handler_config, tls_enabled, status, created_at, updated_at FROM sites ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        #[cfg(any(test, feature = "test-seams"))]
        self.test_visit(TestPoint::AfterListSites).await?;
        Ok(rows.into_iter().map(map_site).collect())
    }

    pub async fn get_site(&self, subdomain: &str, domain: &str) -> Result<Option<Site>> {
        let keys = subdomain_keys(subdomain);
        let result = sqlx_core::query::query(
            "SELECT id, domain, subdomain, handler_type, handler_config, tls_enabled, status, created_at, updated_at FROM sites WHERE domain = $1 AND subdomain = ANY($2) ORDER BY CASE subdomain WHEN '' THEN 0 WHEN '@' THEN 1 ELSE 2 END LIMIT 1",
        )
        .bind(domain)
        .bind(&keys)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.map(map_site))
    }

    pub async fn create_site(
        &self,
        domain: &str,
        subdomain: &str,
        handler_type: &str,
        handler_config: serde_json::Value,
        tls_enabled: bool,
    ) -> Result<Site> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let subdomain = canonical_subdomain(subdomain);
        if self.get_site(&subdomain, domain).await?.is_some() {
            anyhow::bail!(
                "duplicate key value violates unique constraint \"sites_domain_canonical_sub\""
            );
        }

        sqlx_core::query::query(
            "INSERT INTO sites (id, domain, subdomain, handler_type, handler_config, tls_enabled, status, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, 'active', $7, $7)",
        )
        .bind(id)
        .bind(domain)
        .bind(&subdomain)
        .bind(handler_type)
        .bind(&handler_config)
        .bind(tls_enabled)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(Site {
            id,
            domain: domain.to_string(),
            subdomain: subdomain.to_string(),
            handler_type: handler_type.to_string(),
            handler_config,
            tls_enabled,
            status: "active".to_string(),
            created_at: now,
            updated_at: now,
        })
    }

    /// Hot partial update of a site row; None fields stay unchanged.
    pub async fn update_site(
        &self,
        domain: &str,
        subdomain: &str,
        handler_type: Option<&str>,
        handler_config: Option<&serde_json::Value>,
        tls_enabled: Option<bool>,
        status: Option<&str>,
    ) -> Result<Option<Site>> {
        if let Some(site) = self.get_site(subdomain, domain).await? {
            #[cfg(any(test, feature = "test-seams"))]
            self.test_visit(TestPoint::AfterSiteRead).await?;
            sqlx_core::query::query(
                r#"UPDATE sites SET handler_type=COALESCE($1, handler_type), handler_config=COALESCE($2, handler_config), tls_enabled=COALESCE($3, tls_enabled), status=COALESCE($4, status), updated_at=NOW()
                   WHERE domain=$5 AND subdomain=$6 RETURNING id"#,
            )
            .bind(handler_type).bind(handler_config).bind(tls_enabled).bind(status).bind(domain).bind(&site.subdomain)
            .fetch_optional(&self.pool).await?;
            #[cfg(any(test, feature = "test-seams"))]
            self.test_visit(TestPoint::BeforeSiteReread).await?;
            return self.get_site(subdomain, domain).await;
        }
        Ok(None)
    }

    pub async fn delete_site(&self, subdomain: &str, domain: &str) -> Result<bool> {
        let keys = subdomain_keys(subdomain);
        let result =
            sqlx_core::query::query("DELETE FROM sites WHERE domain = $1 AND subdomain = ANY($2)")
                .bind(domain)
                .bind(&keys)
                .execute(&self.pool)
                .await?;
        #[cfg(any(test, feature = "test-seams"))]
        self.test_visit(TestPoint::AfterSiteDelete).await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn log_audit(
        &self,
        action: &str,
        entity_type: &str,
        entity_id: Option<Uuid>,
        details: serde_json::Value,
    ) -> Result<()> {
        sqlx_core::query::query(
            "INSERT INTO audit_log (id, action, entity_type, entity_id, details, created_at) VALUES (gen_random_uuid(), $1, $2, $3, $4, NOW())",
        )
        .bind(action)
        .bind(entity_type)
        .bind(entity_id)
        .bind(&details)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_audit_logs(&self, limit: i64) -> Result<Vec<AuditLog>> {
        let rows = sqlx_core::query::query(
            "SELECT id, action, entity_type, entity_id, details, created_at FROM audit_log ORDER BY created_at DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(map_audit).collect())
    }

    pub async fn create_operation(
        &self,
        op_type: &str,
        request: serde_json::Value,
    ) -> Result<OperationRecord> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let empty = serde_json::json!({});
        let status = "planned";

        sqlx_core::query::query(
            "INSERT INTO operations (id, op_type, status, request, result, error, started_at, updated_at, completed_at) VALUES ($1, $2, $3, $4, $5, NULL, $6, $6, NULL)",
        )
        .bind(id)
        .bind(op_type)
        .bind(status)
        .bind(&request)
        .bind(&empty)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(OperationRecord {
            id,
            op_type: op_type.to_string(),
            status: status.to_string(),
            request,
            result: empty,
            error: None,
            started_at: now,
            updated_at: now,
            completed_at: None,
        })
    }

    pub async fn update_operation(
        &self,
        id: Uuid,
        status: &str,
        result: serde_json::Value,
        error: Option<String>,
        completed: bool,
    ) -> Result<()> {
        let completed_at: Option<DateTime<Utc>> = if completed { Some(Utc::now()) } else { None };
        sqlx_core::query::query(
            "UPDATE operations SET status = $2, result = $3, error = $4, updated_at = NOW(), completed_at = $5 WHERE id = $1",
        )
        .bind(id)
        .bind(status)
        .bind(result)
        .bind(error)
        .bind(completed_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_operation(&self, id: Uuid) -> Result<Option<OperationRecord>> {
        let row = sqlx_core::query::query(
            "SELECT id, op_type, status, request, result, error, started_at, updated_at, completed_at FROM operations WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(map_operation))
    }

    pub async fn list_operations(&self, limit: i64) -> Result<Vec<OperationRecord>> {
        let rows = sqlx_core::query::query(
            "SELECT id, op_type, status, request, result, error, started_at, updated_at, completed_at FROM operations ORDER BY started_at DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(map_operation).collect())
    }
}

#[cfg(feature = "game_forward")]
fn parse_protocol(s: String) -> beacon_forward::Protocol {
    if s.eq_ignore_ascii_case("udp") {
        beacon_forward::Protocol::Udp
    } else {
        beacon_forward::Protocol::Tcp
    }
}
#[cfg(feature = "game_forward")]
fn protocol_str(p: beacon_forward::Protocol) -> &'static str {
    match p {
        beacon_forward::Protocol::Tcp => "tcp",
        beacon_forward::Protocol::Udp => "udp",
    }
}
#[cfg(feature = "game_forward")]
fn parse_mode(s: String) -> beacon_forward::ForwardMode {
    if s.eq_ignore_ascii_case("model_only") {
        beacon_forward::ForwardMode::ModelOnly
    } else {
        beacon_forward::ForwardMode::Live
    }
}
#[cfg(feature = "game_forward")]
fn mode_str(m: beacon_forward::ForwardMode) -> &'static str {
    match m {
        beacon_forward::ForwardMode::Live => "live",
        beacon_forward::ForwardMode::ModelOnly => "model_only",
    }
}

fn map_site(row: sqlx_postgres::PgRow) -> Site {
    Site {
        id: row.get("id"),
        domain: row.get("domain"),
        subdomain: row.get("subdomain"),
        handler_type: row.get("handler_type"),
        handler_config: row.get("handler_config"),
        tls_enabled: row.get("tls_enabled"),
        status: row.get("status"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

fn map_audit(row: sqlx_postgres::PgRow) -> AuditLog {
    AuditLog {
        id: row.get("id"),
        action: row.get("action"),
        entity_type: row.get("entity_type"),
        entity_id: row.get("entity_id"),
        details: row.get("details"),
        created_at: row.get("created_at"),
    }
}

fn map_operation(row: sqlx_postgres::PgRow) -> OperationRecord {
    OperationRecord {
        id: row.get("id"),
        op_type: row.get("op_type"),
        status: row.get("status"),
        request: row.get("request"),
        result: row.get("result"),
        error: row.get("error"),
        started_at: row.get("started_at"),
        updated_at: row.get("updated_at"),
        completed_at: row.get("completed_at"),
    }
}

fn canonical_subdomain(subdomain: &str) -> String {
    let s = subdomain.trim();
    if s.is_empty() || s == "@" || s == "_" {
        String::new()
    } else {
        s.to_string()
    }
}

fn subdomain_keys(subdomain: &str) -> Vec<String> {
    let s = subdomain.trim();
    if s.is_empty() || s == "@" || s == "_" {
        vec!["".into(), "@".into(), "_".into()]
    } else {
        vec![s.to_string()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_subdomain_apex() {
        assert_eq!(canonical_subdomain(""), "");
        assert_eq!(canonical_subdomain("@"), "");
        assert_eq!(canonical_subdomain("_"), "");
        assert_eq!(canonical_subdomain(" app "), "app");
    }

    #[test]
    fn subdomain_keys_apex_aliases() {
        let k = subdomain_keys("@");
        assert!(k.contains(&"".into()) && k.contains(&"@".into()) && k.contains(&"_".into()));
        assert_eq!(subdomain_keys("app"), vec!["app".to_string()]);
        assert_eq!(subdomain_keys(""), subdomain_keys("_"));
    }
}

fn migration_statements() -> Vec<&'static str> {
    vec![
        "CREATE EXTENSION IF NOT EXISTS pgcrypto",
        r#"CREATE TABLE IF NOT EXISTS sites (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                domain TEXT NOT NULL,
                subdomain TEXT NOT NULL,
                handler_type TEXT NOT NULL,
                handler_config JSONB NOT NULL,
                tls_enabled BOOLEAN DEFAULT TRUE,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(domain, subdomain)
            )"#,
        r#"CREATE TABLE IF NOT EXISTS certificates (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                domain TEXT UNIQUE NOT NULL,
                cert_pem TEXT NOT NULL,
                key_pem TEXT NOT NULL,
                issuer TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )"#,
        r#"CREATE TABLE IF NOT EXISTS audit_log (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                action TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id UUID,
                details JSONB NOT NULL DEFAULT '{}',
                created_at TIMESTAMPTZ DEFAULT NOW()
            )"#,
        #[cfg(feature = "game_forward")]
        r#"CREATE TABLE IF NOT EXISTS game_forwards (
                id TEXT PRIMARY KEY,
                game_name TEXT NOT NULL,
                public_host TEXT NOT NULL DEFAULT '',
                public_port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                target_host TEXT NOT NULL,
                target_port INTEGER NOT NULL,
                forward_mode TEXT NOT NULL DEFAULT 'live',
                tunnel_path TEXT,
                owner TEXT NOT NULL DEFAULT 'beacon',
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )"#,
        r#"DELETE FROM sites a USING sites b
                WHERE a.domain = b.domain
                  AND a.subdomain IN ('@', '_')
                  AND b.subdomain = ''"#,
        r#"UPDATE sites SET subdomain = '' WHERE subdomain IN ('@', '_')"#,
        r#"CREATE UNIQUE INDEX IF NOT EXISTS sites_domain_canonical_sub
                ON sites (domain, (CASE WHEN btrim(subdomain) IN ('', '@', '_') THEN '' ELSE btrim(subdomain) END))"#,
        #[cfg(feature = "game_forward")]
        r#"CREATE UNIQUE INDEX IF NOT EXISTS game_forwards_port_proto
                ON game_forwards(public_port, protocol)"#,
        r#"CREATE TABLE IF NOT EXISTS operations (
                id UUID PRIMARY KEY,
                op_type TEXT NOT NULL,
                status TEXT NOT NULL,
                request JSONB NOT NULL DEFAULT '{}',
                result JSONB NOT NULL DEFAULT '{}',
                error TEXT,
                started_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL,
                completed_at TIMESTAMPTZ
            )"#,
    ]
}

#[cfg(all(test, not(feature = "game_forward")))]
#[test]
fn migrations_exclude_forward_tables() {
    assert!(!migration_statements()
        .iter()
        .any(|s| s.contains("game_forwards")));
}
#[cfg(all(test, feature = "game_forward"))]
#[test]
fn migrations_include_forward_tables() {
    assert!(migration_statements()
        .iter()
        .any(|s| s.contains("game_forwards")));
}
