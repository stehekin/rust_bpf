use std::collections::VecDeque;
use async_channel::{Receiver, bounded, Sender};
use anyhow::{bail, Context, Result};
use crate::bpf::types_conv::lw_blob_with_data;

const CHANNEL_CAPACITY: usize = 256;

pub(crate) fn blob_id_to_seq(blob_id: u64) -> (usize, u64) {
    (((blob_id & 0xFFFF000000000000) >> 48) as usize, blob_id & 0x0000FFFFFFFFFFFF)
}

pub(crate) fn seq_to_blob_id(cpu: usize, sequence: u64) -> u64 {
    let cpu = cpu as u64;
    (sequence & 0x0000FFFFFFFFFFFF) | (cpu << 48)
}

pub(crate) struct BlobReceiver {
    cpu_id: usize,
    receiver: Receiver<lw_blob_with_data>,
    sentry: Option<lw_blob_with_data>,
}

impl BlobReceiver {
    pub(crate) fn new(cpu_id: usize, receiver: Receiver<lw_blob_with_data>) -> Self {
        BlobReceiver {
            cpu_id,
            receiver,
            sentry: None,
        }
    }

    fn help_retrieve(&mut self, seq: u64) -> Option<lw_blob_with_data> {
        if let Some(blob) = &self.sentry {
            let (_, s) = blob_id_to_seq(blob.header.blob_id);
            if s == seq {
                self.sentry.take()
            } else if s > seq {
                None
            } else {
                self.sentry = None;
                None
            }
        } else {
            None
        }
    }
    pub(crate) async fn retrieve(&mut self, blob_id: u64) -> Result<Option<lw_blob_with_data>> {
        let (cpu, seq) = blob_id_to_seq(blob_id);
        if cpu != self.cpu_id {
            bail!("incorrect cpu id");
        }
        loop {
            if self.sentry.is_none() {
                self.sentry = Some(self.receiver.recv().await?);
            }

            let blob = self.help_retrieve(seq);
            if blob.is_none() {
                if self.sentry.is_some() {
                    return Ok(None)
                }
            } else {
                return Ok(blob)
            }
        }
    }
}

// `merge_blobs` combines the data of blobs. It returns
// * Ok is all data are copied successfully;
// * Error if data are copied partially;
pub(crate) async fn merge_blobs(blob_id: u64, buffer: &mut Vec<u8>, retriever: &mut BlobReceiver) -> Result<()> {
    let mut blob_id = blob_id;
    loop {
        if blob_id == 0 {
            return Ok(())
        }

        if let Some(blob) = retriever.retrieve(blob_id).await.context("error retrieving blob")? {
            buffer.extend_from_slice(&blob.data[..blob.header.data_size as usize]);
            blob_id = blob.header.blob_next;
        } else {
            bail!("required blob is missing")
        }
    }
}