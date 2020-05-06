use async_trait::async_trait;

#[async_trait]
pub trait AsyncDB {
    async fn get(key:&[u8]) -> Option<Vec<u8>>;
    async fn put(key:&[u8]) -> Option<()>;
}