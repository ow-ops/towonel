#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Boxed because the node's run future is tens of KB.
    Box::pin(towonel_node::run()).await
}
