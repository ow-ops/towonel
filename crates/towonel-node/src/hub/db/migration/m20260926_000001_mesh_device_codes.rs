use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(MeshDeviceCodes::Table)
                    .col(
                        ColumnDef::new(MeshDeviceCodes::UserCode)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(MeshDeviceCodes::DeviceId)
                            .binary()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(MeshDeviceCodes::Name).string().not_null())
                    .col(ColumnDef::new(MeshDeviceCodes::Os).string().null())
                    .col(ColumnDef::new(MeshDeviceCodes::RequesterIp).string().null())
                    .col(
                        ColumnDef::new(MeshDeviceCodes::ExpiresAtMs)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(MeshDeviceCodes::CreatedAtMs)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(MeshDeviceCodes::ApprovedTenantId)
                            .binary()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(MeshDeviceCodes::ApprovedByUserId)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(MeshDeviceCodes::ApprovedAtMs)
                            .big_integer()
                            .null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(MeshDeviceCodes::Table, MeshDeviceCodes::ApprovedByUserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(MeshDeviceCodes::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum MeshDeviceCodes {
    Table,
    UserCode,
    DeviceId,
    Name,
    Os,
    RequesterIp,
    ExpiresAtMs,
    CreatedAtMs,
    ApprovedTenantId,
    ApprovedByUserId,
    ApprovedAtMs,
}
