use sea_orm::{ConnectionTrait, DatabaseBackend, Statement, TransactionTrait};
use sea_orm_migration::prelude::*;

/// A one-row counter the database bumps on every insert into `entries`, so
/// the hub can tell cheaply whether the log changed under its cache. A
/// trigger rather than hub code: it also counts inserts made by a hub that
/// predates it, as happens during a rolling upgrade.
#[derive(DeriveMigrationName)]
pub struct Migration;

const CREATE: &str = "CREATE TABLE entry_log (id SMALLINT PRIMARY KEY, version BIGINT NOT NULL)";
const SEED: &str = "INSERT INTO entry_log (id, version) SELECT 1, count(*) FROM entries";
const BUMP: &str = "UPDATE entry_log SET version = version + 1 WHERE id = 1";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        let statements = match backend {
            DatabaseBackend::Postgres => vec![
                // No insert may land between the count and the trigger.
                "LOCK TABLE entries IN SHARE ROW EXCLUSIVE MODE".to_string(),
                CREATE.to_string(),
                SEED.to_string(),
                format!(
                    "CREATE FUNCTION entry_log_bump() RETURNS trigger LANGUAGE plpgsql AS \
                     $$ BEGIN {BUMP}; RETURN NULL; END $$"
                ),
                "CREATE TRIGGER entries_bump_log AFTER INSERT ON entries \
                 FOR EACH ROW EXECUTE FUNCTION entry_log_bump()"
                    .to_string(),
            ],
            DatabaseBackend::Sqlite => vec![
                CREATE.to_string(),
                SEED.to_string(),
                format!(
                    "CREATE TRIGGER entries_bump_log AFTER INSERT ON entries BEGIN {BUMP}; END"
                ),
            ],
            _ => return Err(DbErr::Migration("unsupported backend".to_string())),
        };
        let txn = manager.get_connection().begin().await?;
        for sql in statements {
            txn.execute_raw(Statement::from_string(backend, sql))
                .await?;
        }
        txn.commit().await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        let statements: &[&str] = match backend {
            DatabaseBackend::Postgres => &[
                "DROP TRIGGER entries_bump_log ON entries",
                "DROP FUNCTION entry_log_bump()",
                "DROP TABLE entry_log",
            ],
            DatabaseBackend::Sqlite => &["DROP TRIGGER entries_bump_log", "DROP TABLE entry_log"],
            _ => return Err(DbErr::Migration("unsupported backend".to_string())),
        };
        let db = manager.get_connection();
        for sql in statements {
            db.execute_raw(Statement::from_string(backend, *sql))
                .await?;
        }
        Ok(())
    }
}
