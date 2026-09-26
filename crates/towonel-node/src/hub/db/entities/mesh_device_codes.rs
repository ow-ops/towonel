use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "mesh_device_codes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_code: String,
    #[sea_orm(unique)]
    pub device_id: Vec<u8>,
    pub name: String,
    pub os: Option<String>,
    pub requester_ip: Option<String>,
    pub expires_at_ms: i64,
    pub created_at_ms: i64,
    pub approved_tenant_id: Option<Vec<u8>>,
    pub approved_by_user_id: Option<String>,
    pub approved_at_ms: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
