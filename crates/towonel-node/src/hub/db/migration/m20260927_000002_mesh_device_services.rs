use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(MeshDevices::Table)
                    .add_column(ColumnDef::new(MeshDevices::Services).json_binary().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(MeshDevices::Table)
                    .drop_column(MeshDevices::Services)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum MeshDevices {
    Table,
    Services,
}
