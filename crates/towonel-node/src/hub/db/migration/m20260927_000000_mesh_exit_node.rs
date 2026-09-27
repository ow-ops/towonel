use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for column in [
            MeshDevices::ExitNodeAdvertised,
            MeshDevices::ExitNodeApproved,
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(MeshDevices::Table)
                        .add_column(ColumnDef::new(column).boolean().not_null().default(false))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for column in [
            MeshDevices::ExitNodeAdvertised,
            MeshDevices::ExitNodeApproved,
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(MeshDevices::Table)
                        .drop_column(column)
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}

#[derive(DeriveIden)]
enum MeshDevices {
    Table,
    ExitNodeAdvertised,
    ExitNodeApproved,
}
