use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        let mut table = Table::create();
        table
            .table(MeshPolicies::Table)
            .col(
                ColumnDef::new(MeshPolicies::TenantId)
                    .binary()
                    .not_null()
                    .primary_key(),
            )
            .col(
                ColumnDef::new(MeshPolicies::Policy)
                    .json_binary()
                    .not_null(),
            )
            .col(
                ColumnDef::new(MeshPolicies::Version)
                    .big_integer()
                    .not_null(),
            )
            .col(
                ColumnDef::new(MeshPolicies::UpdatedAtMs)
                    .big_integer()
                    .not_null(),
            )
            .col(ColumnDef::new(MeshPolicies::UpdatedBy).string().null());
        // Same cascade split as the other mesh tables.
        if backend == DatabaseBackend::Postgres {
            table.foreign_key(
                ForeignKey::create()
                    .from(MeshPolicies::Table, MeshPolicies::TenantId)
                    .to(Invites::Table, Invites::TenantId)
                    .on_delete(ForeignKeyAction::Cascade),
            );
        }
        manager.create_table(table).await?;
        if backend != DatabaseBackend::Postgres {
            manager
                .get_connection()
                .execute_raw(Statement::from_string(
                    backend,
                    "CREATE TRIGGER delete_mesh_policies_on_invite_delete AFTER DELETE ON invites \
                     BEGIN DELETE FROM mesh_policies WHERE tenant_id = OLD.tenant_id; END",
                ))
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() != DatabaseBackend::Postgres {
            manager
                .get_connection()
                .execute_raw(Statement::from_string(
                    manager.get_database_backend(),
                    "DROP TRIGGER IF EXISTS delete_mesh_policies_on_invite_delete",
                ))
                .await?;
        }
        manager
            .drop_table(Table::drop().table(MeshPolicies::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Invites {
    Table,
    TenantId,
}

#[derive(DeriveIden)]
enum MeshPolicies {
    Table,
    TenantId,
    Policy,
    Version,
    UpdatedAtMs,
    UpdatedBy,
}
