//! Event batching and compression before shipping.
//!
//! The backend expects a zstd-compressed JSON array: [{...},{...}]
//! The zstd frame must include the content size in the header
//! (required by Python's zstd.decompress() on the backend).

use ironclaw_core::event::Event;

pub struct Batcher;

impl Batcher {
    pub fn compress_batch(events: &[Event]) -> anyhow::Result<Vec<u8>> {
        // Serialize as a JSON array — backend requires [{...},{...}] not NDJSON
        let json_array = serde_json::to_vec(events)?;

        // Compress with content size in the frame header (required by backend's zstd.decompress)
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 3)?;
        encoder.set_pledged_src_size(Some(json_array.len() as u64))?;
        encoder.include_contentsize(true)?;
        use std::io::Write;
        encoder.write_all(&json_array)?;
        let compressed = encoder.finish()?;
        Ok(compressed)
    }
}
