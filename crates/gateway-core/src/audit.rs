use std::{io, path::Path};

use async_trait::async_trait;
use tokio::{fs::File, io::AsyncWriteExt, sync::Mutex};

use crate::{AuditEvent, AuditSink, GatewayError};

/// An append-only, JSON-lines-per-event `AuditSink`. Every event is written as one line
/// (`AuditEvent` already carries no PHI: no tool arguments or results), flushed and fsynced
/// before `record` returns, so a crash immediately after a successful call cannot silently lose
/// the event. Concurrent writers serialize through an async mutex around the single open file
/// handle rather than reopening the file per event.
///
/// This is a genuine default for small/self-hosted deployments, not a stand-in: the file is
/// real, durable, append-only output a compliance reviewer can inspect directly. A deployment
/// that needs centralized log shipping or a queryable store can implement `AuditSink` against
/// one instead without any gateway-core change, since every caller depends on the trait, not
/// this type.
pub struct FileAuditSink {
    file: Mutex<File>,
}

impl FileAuditSink {
    /// Opens (creating if absent) the audit log at `path` for appending.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error if the file cannot be opened for append.
    pub async fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }
}

#[async_trait]
impl AuditSink for FileAuditSink {
    async fn record(&self, event: AuditEvent) -> Result<(), GatewayError> {
        let mut line = serde_json::to_string(&event).map_err(|_| GatewayError::AuditUnavailable)?;
        line.push('\n');
        let mut file = self.file.lock().await;
        file.write_all(line.as_bytes())
            .await
            .map_err(|_| GatewayError::AuditUnavailable)?;
        file.flush()
            .await
            .map_err(|_| GatewayError::AuditUnavailable)?;
        file.sync_data()
            .await
            .map_err(|_| GatewayError::AuditUnavailable)?;
        Ok(())
    }
}
