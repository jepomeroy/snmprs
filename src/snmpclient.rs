pub(crate) trait SnmpClient {
    fn get(&self, oid: &str) -> Result<String, String>;
    fn get_bulk(&self, oid: &str, count: u32) -> Result<Vec<String>, String>;
    fn get_next(&self, oid: &str) -> Result<String, String>;
    fn inform(&self, oid: &str, value: &str) -> Result<String, String>;
    fn report(&self, oid: &str, value: &str) -> Result<String, String>;
    fn set(&self, oid: &str, value: &str) -> Result<String, String>;
    fn trap(&self, oid: &str, value: &str) -> Result<String, String>;
}
