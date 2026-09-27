use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "mesh_devices")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub device_id: Vec<u8>,
    pub tenant_id: Vec<u8>,
    pub name: String,
    pub os: Option<String>,
    pub overlay_ipv4: i64,
    pub user_id: Option<String>,
    pub tags: Json,
    pub key_expires_at_ms: Option<i64>,
    pub created_at_ms: i64,
    pub last_seen_at_ms: Option<i64>,
    pub endpoint: Option<Json>,
    pub exit_node_advertised: bool,
    pub exit_node_approved: bool,
    pub exit_node_unadvertised_at_ms: Option<i64>,
    pub services: Option<Json>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
