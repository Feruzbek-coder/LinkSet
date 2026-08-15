use crate::{error::AppResult, models::Activity};
use rusqlite::{params, Connection};
use std::{path::Path, sync::Mutex};

pub struct Database(pub Mutex<Connection>);

impl Database {
    pub fn open(path: &Path) -> AppResult<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
          CREATE TABLE IF NOT EXISTS activity_logs(id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, action TEXT NOT NULL, status TEXT NOT NULL, detail TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
          CREATE TABLE IF NOT EXISTS diagnostic_history(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, result_json TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
          CREATE TABLE IF NOT EXISTS ai_usage(id INTEGER PRIMARY KEY, user_id TEXT, request_id TEXT NOT NULL, model TEXT NOT NULL, input_tokens INTEGER NOT NULL, output_tokens INTEGER NOT NULL, estimated_cost REAL NOT NULL, timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
          CREATE TABLE IF NOT EXISTS score_history(id INTEGER PRIMARY KEY, health_score INTEGER NOT NULL, security_score INTEGER NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);")?;
        Ok(Self(Mutex::new(conn)))
    }

    pub fn log(&self, action: &str, status: &str, detail: &str) -> AppResult<()> {
        self.0.lock().unwrap().execute(
            "INSERT INTO activity_logs(action,status,detail) VALUES(?1,?2,?3)",
            params![action, status, detail],
        )?;
        Ok(())
    }

    pub fn activities(&self, limit: u32) -> AppResult<Vec<Activity>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,timestamp,action,status,detail FROM activity_logs ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map([limit.min(200)], |r| {
                Ok(Activity {
                    id: r.get(0)?,
                    timestamp: r.get(1)?,
                    action: r.get(2)?,
                    status: r.get(3)?,
                    detail: r.get(4)?,
                })
            })?
            .filter_map(Result::ok)
            .collect();
        Ok(rows)
    }

    pub fn save_diagnostic(&self, kind: &str, result: &serde_json::Value) -> AppResult<()> {
        self.0.lock().unwrap().execute(
            "INSERT INTO diagnostic_history(kind,result_json) VALUES(?1,?2)",
            params![kind, result.to_string()],
        )?;
        Ok(())
    }

    pub fn record_ai_usage(
        &self,
        request_id: &str,
        model: &str,
        input_tokens: u64,
        output_tokens: u64,
    ) -> AppResult<()> {
        self.0.lock().unwrap().execute(
            "INSERT INTO ai_usage(user_id,request_id,model,input_tokens,output_tokens,estimated_cost) VALUES('local',?1,?2,?3,?4,0)",
            params![request_id, model, input_tokens, output_tokens],
        )?;
        Ok(())
    }

    pub fn ai_usage_summary(&self) -> AppResult<(u64, u64)> {
        let conn = self.0.lock().unwrap();
        conn.query_row(
            "SELECT COALESCE(SUM(input_tokens),0),COALESCE(SUM(output_tokens),0) FROM ai_usage WHERE timestamp >= datetime('now','start of month')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn persists_activity_diagnostics_and_usage() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(&dir.path().join("test.db")).unwrap();
        db.log("test", "success", "detail").unwrap();
        db.save_diagnostic("PC_SLOW", &json!({"score":90})).unwrap();
        db.record_ai_usage("r1", "test-model", 10, 4).unwrap();
        assert_eq!(db.activities(10).unwrap().len(), 1);
        assert_eq!(db.ai_usage_summary().unwrap(), (10, 4));
    }
}
