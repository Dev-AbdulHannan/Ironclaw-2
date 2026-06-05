//! Event buffer with in-memory ring and disk spool overflow.

use ironclaw_core::event::Event;
use std::collections::VecDeque;
use std::path::PathBuf;
use tokio::fs::{self, File};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

/// Manages buffering of events before they are shipped.
pub struct EventBuffer {
    memory_buffer: Mutex<VecDeque<Event>>,
    capacity: usize,
    spool_dir: PathBuf,
    disk_spool_enabled: bool,
}

impl EventBuffer {
    pub async fn new(
        capacity: usize,
        spool_dir: PathBuf,
        disk_spool_enabled: bool,
    ) -> anyhow::Result<Self> {
        if disk_spool_enabled {
            fs::create_dir_all(&spool_dir).await?;
        }
        Ok(Self {
            memory_buffer: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
            spool_dir,
            disk_spool_enabled,
        })
    }

    /// Push an event to the buffer. Overflows to disk if memory is full.
    pub async fn push(&self, event: Event) -> anyhow::Result<()> {
        let mut mem = self.memory_buffer.lock().await;
        if mem.len() >= self.capacity {
            if self.disk_spool_enabled {
                self.spool_to_disk(&event).await?;
            } else {
                log::warn!(
                    "[buffer] memory full ({} events) and disk spool disabled — dropping oldest",
                    mem.len()
                );
                mem.pop_front();
                mem.push_back(event);
            }
        } else {
            mem.push_back(event);
        }
        Ok(())
    }

    /// Drain up to `batch_size` events for shipping.
    /// Reads from disk spool first (to maintain order and clear backlog), then memory.
    pub async fn drain_batch(&self, batch_size: usize) -> anyhow::Result<Vec<Event>> {
        let mut batch = Vec::new();

        // 1. Try reading from disk spool first
        if self.disk_spool_enabled {
            self.load_from_disk(&mut batch, batch_size).await?;
        }

        // 2. Fill the rest from memory
        let mut mem = self.memory_buffer.lock().await;
        while batch.len() < batch_size {
            if let Some(event) = mem.pop_front() {
                batch.push(event);
            } else {
                break;
            }
        }

        Ok(batch)
    }

    /// Return events to the buffer (e.g. if shipping failed).
    pub async fn push_batch_back(&self, events: Vec<Event>) -> anyhow::Result<()> {
        let mut mem = self.memory_buffer.lock().await;
        for event in events.into_iter().rev() {
            if mem.len() < self.capacity {
                mem.push_front(event);
            } else if self.disk_spool_enabled {
                self.spool_to_disk(&event).await?;
            }
        }
        Ok(())
    }

    pub async fn memory_depth(&self) -> usize {
        self.memory_buffer.lock().await.len()
    }

    async fn spool_to_disk(&self, event: &Event) -> anyhow::Result<()> {
        let file_path = self.spool_dir.join("current.spool");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(file_path)
            .await?;
        let json = serde_json::to_string(event)?;
        file.write_all(format!("{}\n", json).as_bytes()).await?;
        Ok(())
    }

    async fn load_from_disk(
        &self,
        batch: &mut Vec<Event>,
        batch_size: usize,
    ) -> anyhow::Result<()> {
        let file_path = self.spool_dir.join("current.spool");
        if !file_path.exists() {
            return Ok(());
        }

        let file = File::open(&file_path).await?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        let mut remaining_lines = Vec::new();
        while let Ok(Some(line)) = lines.next_line().await {
            if batch.len() < batch_size {
                if let Ok(event) = serde_json::from_str(&line) {
                    batch.push(event);
                }
            } else {
                remaining_lines.push(line);
            }
        }

        // Rewrite file with remaining lines
        if remaining_lines.is_empty() {
            fs::remove_file(&file_path).await?;
        } else {
            let tmp_path = self.spool_dir.join("current.spool.tmp");
            let mut tmp_file = File::create(&tmp_path).await?;
            for line in remaining_lines {
                tmp_file.write_all(format!("{}\n", line).as_bytes()).await?;
            }
            fs::rename(tmp_path, file_path).await?;
        }

        Ok(())
    }
}
