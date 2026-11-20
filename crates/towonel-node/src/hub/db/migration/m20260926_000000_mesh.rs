use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    #[expect(
        clippy::too_many_lines,
        reason = "linear DDL — two tables + indexes in one migration"
    )]
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // `invites.tenant_id` is only UNIQUE on Postgres, so SQLite cascades
        // tenant deletion with triggers instead, like `port_reservations`.
        let backend = manager.get_database_backend();
        let postgres = backend == DatabaseBackend::Postgres;

        let mut devices = Table::create();
        devices
            .table(MeshDevices::Table)
            .col(
                ColumnDef::new(MeshDevices::DeviceId)
                    .binary()
                    .not_null()
                    .primary_key(),
            )
            .col(ColumnDef::new(MeshDevices::TenantId).binary().not_null())
            .col(ColumnDef::new(MeshDevices::Name).string().not_null())
            .col(ColumnDef::new(MeshDevices::Os).string().null())
            .col(
                ColumnDef::new(MeshDevices::OverlayIpv4)
                    .big_integer()
                    .not_null(),
            )
            .col(ColumnDef::new(MeshDevices::UserId).string().null())
            .col(ColumnDef::new(MeshDevices::Tags).json_binary().not_null())
            .col(
                ColumnDef::new(MeshDevices::KeyExpiresAtMs)
                    .big_integer()
                    .null(),
            )
            .col(
                ColumnDef::new(MeshDevices::CreatedAtMs)
                    .big_integer()
                    .not_null(),
            )
            .col(
                ColumnDef::new(MeshDevices::LastSeenAtMs)
                    .big_integer()
                    .null(),
            )
            .foreign_key(
                ForeignKey::create()
                    .from(MeshDevices::Table, MeshDevices::UserId)
                    .to(Users::Table, Users::Id)
                    .on_delete(ForeignKeyAction::Cascade),
            );
        if postgres {
            devices.foreign_key(
                ForeignKey::create()
                    .from(MeshDevices::Table, MeshDevices::TenantId)
                    .to(Invites::Table, Invites::TenantId)
                    .on_delete(ForeignKeyAction::Cascade),
            );
        }
        manager.create_table(devices).await?;
        manager
            .create_index(
                Index::create()
                    .name("uq_mesh_devices_tenant_ipv4")
                    .table(MeshDevices::Table)
                    .col(MeshDevices::TenantId)
                    .col(MeshDevices::OverlayIpv4)
                    .unique()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("uq_mesh_devices_tenant_name")
                    .table(MeshDevices::Table)
                    .col(MeshDevices::TenantId)
                    .col(MeshDevices::Name)
                    .unique()
                    .to_owned(),
            )
            .await?;

        let mut auth_keys = Table::create();
        auth_keys
            .table(MeshAuthKeys::Table)
            .col(
                ColumnDef::new(MeshAuthKeys::Id)
                    .string()
                    .not_null()
                    .primary_key(),
            )
            .col(ColumnDef::new(MeshAuthKeys::TenantId).binary().not_null())
            .col(
                ColumnDef::new(MeshAuthKeys::KeyHash)
                    .binary()
                    .not_null()
                    .unique_key(),
            )
            .col(
                ColumnDef::new(MeshAuthKeys::CreatedByUserId)
                    .string()
                    .null(),
            )
            .col(ColumnDef::new(MeshAuthKeys::Tags).json_binary().not_null())
            .col(ColumnDef::new(MeshAuthKeys::Reusable).boolean().not_null())
            .col(
                ColumnDef::new(MeshAuthKeys::ExpiresAtMs)
                    .big_integer()
                    .not_null(),
            )
            .col(ColumnDef::new(MeshAuthKeys::UsedAtMs).big_integer().null())
            .col(
                ColumnDef::new(MeshAuthKeys::CreatedAtMs)
                    .big_integer()
                    .not_null(),
            )
            .foreign_key(
                ForeignKey::create()
                    .from(MeshAuthKeys::Table, MeshAuthKeys::CreatedByUserId)
                    .to(Users::Table, Users::Id)
                    .on_delete(ForeignKeyAction::Cascade),
            );
        if postgres {
            auth_keys.foreign_key(
                ForeignKey::create()
                    .from(MeshAuthKeys::Table, MeshAuthKeys::TenantId)
                    .to(Invites::Table, Invites::TenantId)
                    .on_delete(ForeignKeyAction::Cascade),
            );
        }
        manager.create_table(auth_keys).await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_mesh_auth_keys_tenant_id")
                    .table(MeshAuthKeys::Table)
                    .col(MeshAuthKeys::TenantId)
                    .to_owned(),
            )
            .await?;

        if !postgres {
            let db = manager.get_connection();
            for table in ["mesh_devices", "mesh_auth_keys"] {
                db.execute_raw(Statement::from_string(
                    backend,
                    format!(
                        "CREATE TRIGGER delete_{table}_on_invite_delete \
                         AFTER DELETE ON invites \
                         BEGIN DELETE FROM {table} WHERE tenant_id = OLD.tenant_id; END"
                    ),
                ))
                .await?;
            }
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() != DatabaseBackend::Postgres {
            let db = manager.get_connection();
            for table in ["mesh_devices", "mesh_auth_keys"] {
                db.execute_raw(Statement::from_string(
                    manager.get_database_backend(),
                    format!("DROP TRIGGER IF EXISTS delete_{table}_on_invite_delete"),
                ))
                .await?;
            }
        }
        manager
            .drop_table(Table::drop().table(MeshAuthKeys::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(MeshDevices::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Invites {
    Table,
    TenantId,
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum MeshDevices {
    Table,
    DeviceId,
    TenantId,
    Name,
    Os,
    OverlayIpv4,
    UserId,
    Tags,
    KeyExpiresAtMs,
    CreatedAtMs,
    LastSeenAtMs,
}

#[derive(DeriveIden)]
enum MeshAuthKeys {
    Table,
    Id,
    TenantId,
    KeyHash,
    CreatedByUserId,
    Tags,
    Reusable,
    ExpiresAtMs,
    UsedAtMs,
    CreatedAtMs,
}
