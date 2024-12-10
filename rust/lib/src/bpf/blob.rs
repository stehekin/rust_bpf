use std::collections::VecDeque;
use async_channel::{Receiver, bounded, Sender};
use anyhow::{bail, Result};
use crate::bpf::types_conv::lw_blob_with_data;

const CHANNEL_CAPACITY: usize = 256;

pub(crate) fn blob_id_to_seq(blob_id: u64) -> (usize, u64) {
    (((blob_id & 0xFFFF000000000000) >> 48) as usize, blob_id & 0x0000FFFFFFFFFFFF)
}

pub(crate) fn seq_to_blob_id(cpu: usize, sequence: u64) -> u64 {
    let cpu = cpu as u64;
    (sequence & 0x0000FFFFFFFFFFFF) | (cpu << 48)
}

pub(crate) struct BlobReader {
    cpu_id: usize,
    receiver: Receiver<lw_blob_with_data>,
    sentry: Option<lw_blob_with_data>,
}

impl BlobReader {
    pub(crate) fn new(cpu_id: usize, receiver: Receiver<lw_blob_with_data>) -> Self {
        BlobReader {
            cpu_id,
            receiver,
            sentry: None,
        }
    }

    fn help_get(&mut self, seq: u64) -> Option<lw_blob_with_data> {
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
    pub(crate) async fn get(&mut self, blob_id: u64) -> Result<Option<lw_blob_with_data>> {
        let (cpu, seq) = blob_id_to_seq(blob_id);
        if cpu != self.cpu_id {
            bail!("incorrect cpu id");
        }
        loop {
            if self.sentry.is_none() {
                self.sentry = Some(self.receiver.recv().await?);
            }

            let blob = self.help_get(seq);
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

pub(crate) struct BlobManager {
    receivers: Vec<BlobReader>,
    senders: Vec<Sender<lw_blob_with_data>>,
}

impl Default for BlobManager {
    fn default() -> Self {
        let cpus = num_cpus::get();

        let mut bm = Self {
            receivers: Vec::with_capacity(cpus),
            senders: Vec::with_capacity(cpus),
        };

        for i in 0..cpus {
            let (sender, receiver) = async_channel::bounded(CHANNEL_CAPACITY);
            bm.receivers.push(BlobReader::new(i, receiver));
            bm.senders.push(sender);
        }

        bm
    }
}

impl BlobManager {
    pub(crate) async fn add(&mut self, blob: lw_blob_with_data) -> () {
        let (cpu, sequence) = blob_id_to_seq(blob.header.blob_id);
        let sender = &self.senders[cpu];
        sender.send(blob).await?
    }

    // `get` finds the blob with the given blob_id in the blob_queues.
    // During the search, blobs that sent earlier than the given blob in the same CPU queue are discarded.
    // It works as in the user space signals emitted from a same CPU are handled in order.
    pub(crate) fn get(&mut self, blob_id: u64) ->Option<lw_blob_with_data> {
        let (cpu, sequence) = blob_id_to_seq(blob_id);
        let queue = &self.blob_queues[cpu];

        while let Some(found) = queue.pop_front() {
            if found.header.blob_id == blob_id {
                return Some(found);
            } else if found.header.blob_id > blob_id {
                queue.push_front(found);
                break;
            }
        }
        None
    }
}