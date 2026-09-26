use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "mesh_auth_keys")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub tenant_id: Vec<u8>,
    #[sea_orm(unique)]
    pub key_hash: Vec<u8>,
    pub created_by_user_id: Option<String>,
    pub tags: Json,
    pub reusable: bool,
    pub expires_at_ms: i64,
    pub used_at_ms: Option<i64>,
    pub created_at_ms: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
