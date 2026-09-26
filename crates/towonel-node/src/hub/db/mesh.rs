use std::collections::HashSet;
use std::net::Ipv4Addr;

use sea_orm::{
    ActiveValue, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect, TransactionTrait,
};
use towonel_common::identity::TenantId;
use towonel_common::mesh::{DeviceId, MESH_IPV4_MAX_HOST, mesh_ipv4};

use super::Db;
use super::entities::{mesh_auth_keys, mesh_device_codes, mesh_devices};

const LAST_SEEN_RESOLUTION_MS: i64 = 60_000;

pub struct NewMeshAuthKey<'a> {
    pub id: &'a str,
    pub tenant_id: &'a TenantId,
    pub key_hash: &'a [u8; 32],
    pub created_by_user_id: Option<&'a str>,
    pub tags: &'a [String],
    pub reusable: bool,
    pub expires_at_ms: i64,
    pub now_ms: i64,
}

#[derive(Debug, Clone)]
pub struct MeshAuthKeyRow {
    pub id: String,
    pub tenant_id: TenantId,
    pub created_by_user_id: Option<String>,
    pub tags: Vec<String>,
    pub reusable: bool,
    pub expires_at_ms: i64,
    pub used_at_ms: Option<i64>,
    pub created_at_ms: i64,
}

/// What authorizes an enrollment; consumed in the same transaction.
pub enum EnrollGrant<'a> {
    AuthKey { id: &'a str, reusable: bool },
    DeviceCode(&'a str),
}

pub struct NewMeshDeviceCode<'a> {
    pub user_code: &'a str,
    pub device_id: &'a DeviceId,
    pub name: &'a str,
    pub os: Option<&'a str>,
    pub requester_ip: Option<&'a str>,
    pub expires_at_ms: i64,
    pub now_ms: i64,
}

#[derive(Debug, Clone)]
pub struct MeshDeviceCodeRow {
    pub user_code: String,
    pub device_id: DeviceId,
    pub name: String,
    pub os: Option<String>,
    pub requester_ip: Option<String>,
    pub expires_at_ms: i64,
    pub created_at_ms: i64,
    pub approved_tenant_id: Option<TenantId>,
    pub approved_by_user_id: Option<String>,
}

pub struct NewMeshDevice<'a> {
    pub device_id: &'a DeviceId,
    pub tenant_id: &'a TenantId,
    /// Preferred name; suffixed `-2`, `-3`, … when taken in the tenant.
    pub name: &'a str,
    pub os: Option<&'a str>,
    pub user_id: Option<&'a str>,
    pub tags: &'a [String],
    pub key_expires_at_ms: Option<i64>,
    pub now_ms: i64,
}

#[derive(Debug, Clone)]
pub struct MeshDeviceRow {
    pub device_id: DeviceId,
    pub tenant_id: TenantId,
    pub name: String,
    pub os: Option<String>,
    pub ipv4: Ipv4Addr,
    pub user_id: Option<String>,
    pub tags: Vec<String>,
    pub key_expires_at_ms: Option<i64>,
    pub created_at_ms: i64,
    pub last_seen_at_ms: Option<i64>,
}

fn tenant_from_bytes(bytes: &[u8]) -> anyhow::Result<TenantId> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("tenant_id must be 32 bytes"))?;
    Ok(TenantId::from_bytes(&arr))
}

fn tags_from_json(v: serde_json::Value) -> anyhow::Result<Vec<String>> {
    Ok(serde_json::from_value(v)?)
}

impl TryFrom<mesh_auth_keys::Model> for MeshAuthKeyRow {
    type Error = anyhow::Error;

    fn try_from(m: mesh_auth_keys::Model) -> anyhow::Result<Self> {
        Ok(Self {
            id: m.id,
            tenant_id: tenant_from_bytes(&m.tenant_id)?,
            created_by_user_id: m.created_by_user_id,
            tags: tags_from_json(m.tags)?,
            reusable: m.reusable,
            expires_at_ms: m.expires_at_ms,
            used_at_ms: m.used_at_ms,
            created_at_ms: m.created_at_ms,
        })
    }
}

fn device_id_from_bytes(bytes: &[u8]) -> anyhow::Result<DeviceId> {
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("device_id must be 32 bytes"))
}

impl TryFrom<mesh_device_codes::Model> for MeshDeviceCodeRow {
    type Error = anyhow::Error;

    fn try_from(m: mesh_device_codes::Model) -> anyhow::Result<Self> {
        Ok(Self {
            user_code: m.user_code,
            device_id: device_id_from_bytes(&m.device_id)?,
            name: m.name,
            os: m.os,
            requester_ip: m.requester_ip,
            expires_at_ms: m.expires_at_ms,
            created_at_ms: m.created_at_ms,
            approved_tenant_id: m
                .approved_tenant_id
                .as_deref()
                .map(tenant_from_bytes)
                .transpose()?,
            approved_by_user_id: m.approved_by_user_id,
        })
    }
}

impl TryFrom<mesh_devices::Model> for MeshDeviceRow {
    type Error = anyhow::Error;

    fn try_from(m: mesh_devices::Model) -> anyhow::Result<Self> {
        let device_id = device_id_from_bytes(&m.device_id)?;
        let ipv4 = u32::try_from(m.overlay_ipv4)
            .map(Ipv4Addr::from)
            .map_err(|_| anyhow::anyhow!("overlay_ipv4 {} out of range", m.overlay_ipv4))?;
        Ok(Self {
            device_id,
            tenant_id: tenant_from_bytes(&m.tenant_id)?,
            name: m.name,
            os: m.os,
            ipv4,
            user_id: m.user_id,
            tags: tags_from_json(m.tags)?,
            key_expires_at_ms: m.key_expires_at_ms,
            created_at_ms: m.created_at_ms,
            last_seen_at_ms: m.last_seen_at_ms,
        })
    }
}

fn pick_ipv4(used: &HashSet<u32>) -> Option<Ipv4Addr> {
    (1..=MESH_IPV4_MAX_HOST)
        .filter_map(mesh_ipv4)
        .find(|ip| !used.contains(&u32::from(*ip)))
}

fn unique_name(base: &str, taken: &HashSet<String>) -> String {
    if !taken.contains(base) {
        return base.to_string();
    }
    // Pigeonhole: one of `taken.len() + 1` suffixes is always free.
    (2..=taken.len() + 2)
        .map(|n| format!("{base}-{n}"))
        .find(|candidate| !taken.contains(candidate))
        .unwrap_or_else(|| base.to_string())
}

impl Db {
    pub async fn insert_mesh_auth_key(&self, k: NewMeshAuthKey<'_>) -> anyhow::Result<()> {
        let model = mesh_auth_keys::ActiveModel {
            id: ActiveValue::Set(k.id.to_string()),
            tenant_id: ActiveValue::Set(k.tenant_id.as_bytes().to_vec()),
            key_hash: ActiveValue::Set(k.key_hash.to_vec()),
            created_by_user_id: ActiveValue::Set(k.created_by_user_id.map(str::to_string)),
            tags: ActiveValue::Set(serde_json::to_value(k.tags)?),
            reusable: ActiveValue::Set(k.reusable),
            expires_at_ms: ActiveValue::Set(k.expires_at_ms),
            used_at_ms: ActiveValue::Set(None),
            created_at_ms: ActiveValue::Set(k.now_ms),
        };
        mesh_auth_keys::Entity::insert(model)
            .exec(&self.conn)
            .await?;
        Ok(())
    }

    pub async fn find_mesh_auth_key_by_hash(
        &self,
        key_hash: &[u8; 32],
    ) -> anyhow::Result<Option<MeshAuthKeyRow>> {
        mesh_auth_keys::Entity::find()
            .filter(mesh_auth_keys::Column::KeyHash.eq(key_hash.to_vec()))
            .one(&self.conn)
            .await?
            .map(MeshAuthKeyRow::try_from)
            .transpose()
    }

    pub async fn list_mesh_auth_keys(
        &self,
        tenant_id: &TenantId,
    ) -> anyhow::Result<Vec<MeshAuthKeyRow>> {
        mesh_auth_keys::Entity::find()
            .filter(mesh_auth_keys::Column::TenantId.eq(tenant_id.as_bytes().to_vec()))
            .order_by_asc(mesh_auth_keys::Column::CreatedAtMs)
            .all(&self.conn)
            .await?
            .into_iter()
            .map(MeshAuthKeyRow::try_from)
            .collect()
    }

    pub async fn delete_mesh_auth_key(
        &self,
        tenant_id: &TenantId,
        id: &str,
    ) -> anyhow::Result<u64> {
        let res = mesh_auth_keys::Entity::delete_many()
            .filter(mesh_auth_keys::Column::TenantId.eq(tenant_id.as_bytes().to_vec()))
            .filter(mesh_auth_keys::Column::Id.eq(id))
            .exec(&self.conn)
            .await?;
        Ok(res.rows_affected)
    }

    /// `Ok(None)` when the grant was spent concurrently. A unique violation
    /// means a concurrent enrollment took the IP or name; retry.
    pub async fn enroll_mesh_device(
        &self,
        grant: &EnrollGrant<'_>,
        d: NewMeshDevice<'_>,
    ) -> anyhow::Result<Option<MeshDeviceRow>> {
        let txn = self.conn.begin().await?;

        if !consume_grant(&txn, grant, d.now_ms).await? {
            txn.rollback().await?;
            return Ok(None);
        }

        let tenant_bytes = d.tenant_id.as_bytes().to_vec();
        let existing: Vec<(i64, String)> = mesh_devices::Entity::find()
            .select_only()
            .column(mesh_devices::Column::OverlayIpv4)
            .column(mesh_devices::Column::Name)
            .filter(mesh_devices::Column::TenantId.eq(tenant_bytes.clone()))
            .into_tuple()
            .all(&txn)
            .await?;
        let used_ips: HashSet<u32> = existing
            .iter()
            .filter_map(|(ip, _)| u32::try_from(*ip).ok())
            .collect();
        let taken_names: HashSet<String> = existing.into_iter().map(|(_, n)| n).collect();

        let ipv4 = pick_ipv4(&used_ips)
            .ok_or_else(|| anyhow::anyhow!("mesh IPv4 pool exhausted for tenant"))?;
        let name = unique_name(d.name, &taken_names);

        let model = mesh_devices::ActiveModel {
            device_id: ActiveValue::Set(d.device_id.to_vec()),
            tenant_id: ActiveValue::Set(tenant_bytes),
            name: ActiveValue::Set(name),
            os: ActiveValue::Set(d.os.map(str::to_string)),
            overlay_ipv4: ActiveValue::Set(i64::from(u32::from(ipv4))),
            user_id: ActiveValue::Set(d.user_id.map(str::to_string)),
            tags: ActiveValue::Set(serde_json::to_value(d.tags)?),
            key_expires_at_ms: ActiveValue::Set(d.key_expires_at_ms),
            created_at_ms: ActiveValue::Set(d.now_ms),
            last_seen_at_ms: ActiveValue::Set(Some(d.now_ms)),
        };
        let inserted = mesh_devices::Entity::insert(model)
            .exec_with_returning(&txn)
            .await?;
        txn.commit().await?;
        MeshDeviceRow::try_from(inserted).map(Some)
    }

    /// Extend an enrolled device's key with an approved code. `Ok(false)` when
    /// the code was spent concurrently.
    pub async fn renew_mesh_device_key(
        &self,
        user_code: &str,
        device_id: &DeviceId,
        key_expires_at_ms: Option<i64>,
        now_ms: i64,
    ) -> anyhow::Result<bool> {
        let txn = self.conn.begin().await?;
        if !consume_grant(&txn, &EnrollGrant::DeviceCode(user_code), now_ms).await? {
            txn.rollback().await?;
            return Ok(false);
        }
        mesh_devices::Entity::update_many()
            .col_expr(
                mesh_devices::Column::KeyExpiresAtMs,
                sea_orm::sea_query::Expr::value(key_expires_at_ms),
            )
            .col_expr(
                mesh_devices::Column::LastSeenAtMs,
                sea_orm::sea_query::Expr::value(now_ms),
            )
            .filter(mesh_devices::Column::DeviceId.eq(device_id.to_vec()))
            .exec(&txn)
            .await?;
        txn.commit().await?;
        Ok(true)
    }

    /// Replaces any earlier code for the same device and sweeps expired ones.
    pub async fn insert_mesh_device_code(&self, c: NewMeshDeviceCode<'_>) -> anyhow::Result<()> {
        let txn = self.conn.begin().await?;
        mesh_device_codes::Entity::delete_many()
            .filter(
                mesh_device_codes::Column::DeviceId
                    .eq(c.device_id.to_vec())
                    .or(mesh_device_codes::Column::ExpiresAtMs.lte(c.now_ms)),
            )
            .exec(&txn)
            .await?;
        let model = mesh_device_codes::ActiveModel {
            user_code: ActiveValue::Set(c.user_code.to_string()),
            device_id: ActiveValue::Set(c.device_id.to_vec()),
            name: ActiveValue::Set(c.name.to_string()),
            os: ActiveValue::Set(c.os.map(str::to_string)),
            requester_ip: ActiveValue::Set(c.requester_ip.map(str::to_string)),
            expires_at_ms: ActiveValue::Set(c.expires_at_ms),
            created_at_ms: ActiveValue::Set(c.now_ms),
            approved_tenant_id: ActiveValue::Set(None),
            approved_by_user_id: ActiveValue::Set(None),
            approved_at_ms: ActiveValue::Set(None),
        };
        mesh_device_codes::Entity::insert(model).exec(&txn).await?;
        txn.commit().await?;
        Ok(())
    }

    pub async fn find_mesh_device_code(
        &self,
        user_code: &str,
    ) -> anyhow::Result<Option<MeshDeviceCodeRow>> {
        mesh_device_codes::Entity::find_by_id(user_code.to_string())
            .one(&self.conn)
            .await?
            .map(MeshDeviceCodeRow::try_from)
            .transpose()
    }

    pub async fn find_mesh_device_code_for_device(
        &self,
        device_id: &DeviceId,
    ) -> anyhow::Result<Option<MeshDeviceCodeRow>> {
        mesh_device_codes::Entity::find()
            .filter(mesh_device_codes::Column::DeviceId.eq(device_id.to_vec()))
            .one(&self.conn)
            .await?
            .map(MeshDeviceCodeRow::try_from)
            .transpose()
    }

    /// `Ok(false)` when the code is unknown, expired, or already approved.
    pub async fn approve_mesh_device_code(
        &self,
        user_code: &str,
        tenant_id: &TenantId,
        user_id: &str,
        now_ms: i64,
    ) -> anyhow::Result<bool> {
        let res = mesh_device_codes::Entity::update_many()
            .col_expr(
                mesh_device_codes::Column::ApprovedTenantId,
                sea_orm::sea_query::Expr::value(tenant_id.as_bytes().to_vec()),
            )
            .col_expr(
                mesh_device_codes::Column::ApprovedByUserId,
                sea_orm::sea_query::Expr::value(user_id),
            )
            .col_expr(
                mesh_device_codes::Column::ApprovedAtMs,
                sea_orm::sea_query::Expr::value(now_ms),
            )
            .filter(mesh_device_codes::Column::UserCode.eq(user_code))
            .filter(mesh_device_codes::Column::ApprovedAtMs.is_null())
            .filter(mesh_device_codes::Column::ExpiresAtMs.gt(now_ms))
            .exec(&self.conn)
            .await?;
        Ok(res.rows_affected == 1)
    }

    pub async fn get_mesh_device(
        &self,
        device_id: &DeviceId,
    ) -> anyhow::Result<Option<MeshDeviceRow>> {
        mesh_devices::Entity::find_by_id(device_id.to_vec())
            .one(&self.conn)
            .await?
            .map(MeshDeviceRow::try_from)
            .transpose()
    }

    pub async fn list_mesh_devices(
        &self,
        tenant_id: &TenantId,
    ) -> anyhow::Result<Vec<MeshDeviceRow>> {
        mesh_devices::Entity::find()
            .filter(mesh_devices::Column::TenantId.eq(tenant_id.as_bytes().to_vec()))
            .order_by_asc(mesh_devices::Column::OverlayIpv4)
            .all(&self.conn)
            .await?
            .into_iter()
            .map(MeshDeviceRow::try_from)
            .collect()
    }

    /// At most one write per device per minute.
    pub async fn touch_mesh_device(&self, device_id: &DeviceId, now_ms: i64) -> anyhow::Result<()> {
        mesh_devices::Entity::update_many()
            .col_expr(
                mesh_devices::Column::LastSeenAtMs,
                sea_orm::sea_query::Expr::value(now_ms),
            )
            .filter(mesh_devices::Column::DeviceId.eq(device_id.to_vec()))
            .filter(
                mesh_devices::Column::LastSeenAtMs
                    .is_null()
                    .or(mesh_devices::Column::LastSeenAtMs.lt(now_ms - LAST_SEEN_RESOLUTION_MS)),
            )
            .exec(&self.conn)
            .await?;
        Ok(())
    }

    pub async fn delete_mesh_device(
        &self,
        tenant_id: &TenantId,
        device_id: &DeviceId,
    ) -> anyhow::Result<u64> {
        let res = mesh_devices::Entity::delete_many()
            .filter(mesh_devices::Column::TenantId.eq(tenant_id.as_bytes().to_vec()))
            .filter(mesh_devices::Column::DeviceId.eq(device_id.to_vec()))
            .exec(&self.conn)
            .await?;
        Ok(res.rows_affected)
    }
}

async fn consume_grant(
    txn: &sea_orm::DatabaseTransaction,
    grant: &EnrollGrant<'_>,
    now_ms: i64,
) -> anyhow::Result<bool> {
    let affected = match grant {
        EnrollGrant::AuthKey { reusable: true, .. } => return Ok(true),
        EnrollGrant::AuthKey {
            id,
            reusable: false,
        } => {
            mesh_auth_keys::Entity::update_many()
                .col_expr(
                    mesh_auth_keys::Column::UsedAtMs,
                    sea_orm::sea_query::Expr::value(now_ms),
                )
                .filter(mesh_auth_keys::Column::Id.eq(*id))
                .filter(mesh_auth_keys::Column::UsedAtMs.is_null())
                .exec(txn)
                .await?
                .rows_affected
        }
        EnrollGrant::DeviceCode(code) => {
            mesh_device_codes::Entity::delete_many()
                .filter(mesh_device_codes::Column::UserCode.eq(*code))
                .filter(mesh_device_codes::Column::ApprovedAtMs.is_not_null())
                .exec(txn)
                .await?
                .rows_affected
        }
    };
    Ok(affected == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_ipv4_fills_lowest_gap() {
        let used: HashSet<u32> = [1, 2, 4]
            .into_iter()
            .map(|h| u32::from(mesh_ipv4(h).unwrap()))
            .collect();
        assert_eq!(pick_ipv4(&used), mesh_ipv4(3));
        assert_eq!(pick_ipv4(&HashSet::new()), mesh_ipv4(1));
    }

    #[test]
    fn unique_name_suffixes_on_collision() {
        let taken: HashSet<String> = ["nas".to_string(), "nas-2".to_string()].into();
        assert_eq!(unique_name("nas", &taken), "nas-3");
        assert_eq!(unique_name("laptop", &taken), "laptop");
    }
}
