use async_channel::{Receiver, Sender};
use anyhow::{bail, Context, Result};
use crate::bpf::types::lw_blob;

const CHANNEL_CAPACITY: usize = 256;

// `merge_blobs` combines the data of blobs. It returns
// * Ok is all data are copied successfully;
// * Error if data are copied partially;
pub(crate) async fn merge_blobs(blob_id: u64, buffer: &mut Vec<u8>, retriever: &mut BlobReceiver) -> Result<()> {
    let mut blob_id = blob_id;
    loop {
        let (_, seq) = blob_id_to_seq(blob_id);
        if seq == 0 {
            return Ok(());
        }

        if let Some(blob) = retriever.retrieve(blob_id).await.context("error retrieving blob")? {
            buffer.extend_from_slice(&blob.data[..blob.header.effective_data_size as usize]);
            blob_id = blob.header.blob_next;
            print!(">>>next blob_id: {0}\n", blob_id);
        } else {
            bail!("required blob with id {0} is missing", blob_id)
        }
    }
}

#[inline]
pub(crate) fn blob_id_to_seq(blob_id: u64) -> (usize, u64) {
    (((blob_id & 0xFFFF000000000000) >> 48) as usize, blob_id & 0x0000FFFFFFFFFFFF)
}

#[inline]
pub(crate) fn seq_to_blob_id(cpu: usize, sequence: u64) -> u64 {
    let cpu = cpu as u64;
    (sequence & 0x0000FFFFFFFFFFFF) | (cpu << 48)
}

pub(crate) struct BlobReceiver {
    cpu_id: usize,
    receiver: Receiver<lw_blob>,
    sentry: Option<lw_blob>,
}

impl BlobReceiver {
    pub(crate) fn new(cpu_id: usize, receiver: Receiver<lw_blob>) -> Self {
        BlobReceiver {
            cpu_id,
            receiver,
            sentry: None,
        }
    }

    fn help_retrieve(&mut self, seq: u64) -> Option<lw_blob> {
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
    pub(crate) async fn retrieve(&mut self, blob_id: u64) -> Result<Option<lw_blob>> {
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

pub(crate) struct BlobReceiverGroup {
    receivers: Vec<BlobReceiver>,
}

impl BlobReceiverGroup {
    pub(crate) fn new(receivers: Vec<BlobReceiver>) -> Self {
        Self { receivers }
    }
    pub(crate) async fn merge_blobs(&mut self, blob_id: u64, buffer: &mut Vec<u8>) -> Result<()> {
        if blob_id == 0 {
            return Ok(());
        }
        let (cpu, _) = blob_id_to_seq(blob_id);
        if let Some(r) = self.receivers.get_mut(cpu) {
            merge_blobs(blob_id, buffer, r).await
        } else {
            bail!("invalid cpu id {0}", cpu)
        }
    }
}

pub(crate) struct BlobSenderGroup {
    senders: Vec<Sender<lw_blob>>,
}

impl BlobSenderGroup {
    pub(crate) fn new(senders: Vec<Sender<lw_blob>>) -> Self {
        Self { senders }
    }

    pub(crate) async fn send(&self, lw_blob_with_data: lw_blob) -> Result<()> {
        let (cpu, _) = blob_id_to_seq(lw_blob_with_data.header.blob_id);
        if let Some(s) = self.senders.get(cpu) {
            s.send(lw_blob_with_data).await.context("error sending blob data")
        } else {
            bail!("invalid cpu id {0}", cpu)
        }
    }

    pub(crate) fn send_blocking(&self, lw_blob_with_data: lw_blob) -> Result<()> {
        let (cpu, _) = blob_id_to_seq(lw_blob_with_data.header.blob_id);
        if let Some(s) = self.senders.get(cpu) {
            s.send_blocking(lw_blob_with_data).context("error sending blob data")
        } else {
            bail!("invalid cpu id {0}", cpu)
        }
    }
}

pub(crate) fn blob_channel_groups() -> (BlobSenderGroup, BlobReceiverGroup) {
    let cpu_num = num_cpus::get();
    let mut receivers = Vec::new();
    let mut senders = Vec::new();

    for cpu in 0..cpu_num {
        let (s, r) = async_channel::bounded(CHANNEL_CAPACITY);
        receivers.push(BlobReceiver::new(cpu, r));
        senders.push(s)
    }

    (BlobSenderGroup::new(senders), BlobReceiverGroup::new(receivers))
}