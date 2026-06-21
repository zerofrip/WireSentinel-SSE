use uuid::Uuid;

use shared_types::SecurityEventRecord;

use crate::SecurityDataLake;

/// Query engine over the security data lake.
pub struct SecurityQueryEngine<'a> {
    lake: &'a SecurityDataLake,
}

impl<'a> SecurityQueryEngine<'a> {
    pub fn new(lake: &'a SecurityDataLake) -> Self {
        Self { lake }
    }

    pub fn by_kind(&self, kind: &str) -> Vec<SecurityEventRecord> {
        self.lake
            .all()
            .into_iter()
            .filter(|e| e.event_kind == kind)
            .collect()
    }

    pub fn by_tenant(&self, tenant_id: Uuid) -> Vec<SecurityEventRecord> {
        self.lake
            .all()
            .into_iter()
            .filter(|e| e.tenant_id == tenant_id)
            .collect()
    }

    pub fn count_by_kind(&self, kind: &str) -> usize {
        self.by_kind(kind).len()
    }
}
