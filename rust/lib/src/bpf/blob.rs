use crate::bpf::types::lw_blob;
use log::{error, warn};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

pub(crate) struct MergedBlob(pub u64, pub Vec<u8>);

#[inline]
pub(crate) fn blob_id_to_seq(blob_id: u64) -> (usize, u64) {
    (
        ((blob_id & 0xFFFF000000000000) >> 48) as usize,
        blob_id & 0x0000FFFFFFFFFFFF,
    )
}

#[inline]
pub(crate) fn seq_to_blob_id(cpu: usize, sequence: u64) -> u64 {
    let cpu = cpu as u64;
    (sequence & 0x0000FFFFFFFFFFFF) | (cpu << 48)
}

pub(crate) async fn merge_blob(
    cpu_id: usize,
    mut blob_id_receiver: UnboundedReceiver<u64>,
    mut blob_receiver: UnboundedReceiver<lw_blob>,
    merged_blob_sender: UnboundedSender<MergedBlob>,
) {
    let mut sentry: Option<lw_blob> = None;

    print!("merge blob starting...\n");

    while let Some(blob_id) = blob_id_receiver.recv().await {
        if blob_id == 0 {
            continue;
        }

        let mut merged = vec![];
        let (cpu, mut expected_seq) = blob_id_to_seq(blob_id);
        if cpu != cpu_id {
            error!("user requested invalid blob id ({blob_id}) on cpu {cpu_id}");
            continue;
        }

        loop {
            let sentry_blob = match &sentry {
                None => {
                    match blob_receiver.recv().await {
                        None => {
                            return;
                        }
                        Some(blob) => {
                            sentry = Some(blob);
                        }
                    }
                    continue;
                }
                Some(blob) => blob,
            };

            let (sentry_cpu, sentry_seq) = blob_id_to_seq(sentry_blob.header.blob_id);

            if sentry_cpu != cpu_id {
                warn!("telemetry with wrong cpu id on cpu {cpu_id}");
                sentry = None;
                continue;
            }

            if sentry_seq < expected_seq {
                // drop the blob;
                sentry = None;
            } else {
                if sentry_seq == expected_seq {
                    merged.extend_from_slice(
                        &sentry_blob.data[..sentry_blob.header.effective_data_size as usize],
                    );
                    (_, expected_seq) = blob_id_to_seq(sentry_blob.header.blob_next);
                    sentry = None;
                }

                if sentry_seq > expected_seq {
                    if let Err(_) = merged_blob_sender.send(MergedBlob(blob_id, merged)) {
                        return;
                    }
                    break;
                }
            }
        }
    }
    print!("merge blob exiting\n");
}

pub(crate) struct BlobSendersReceivers {
    pub blob_id_senders: Vec<UnboundedSender<u64>>,
    pub blob_senders: Vec<UnboundedSender<lw_blob>>,
    pub merged_blob_receivers: Option<Vec<UnboundedReceiver<MergedBlob>>>,
}

impl BlobSendersReceivers {
    fn append(
        &mut self,
        blob_id_sender: UnboundedSender<u64>,
        blob_sender: UnboundedSender<lw_blob>,
        merged_blob_receiver: UnboundedReceiver<MergedBlob>,
    ) {
        self.blob_id_senders.push(blob_id_sender);
        self.blob_senders.push(blob_sender);
        self.merged_blob_receivers
            .as_mut()
            .unwrap()
            .push(merged_blob_receiver);
    }
}

pub(crate) fn spawn_blob_mergers() -> BlobSendersReceivers {
    let mut senders_receivers = BlobSendersReceivers {
        blob_senders: vec![],
        blob_id_senders: vec![],
        merged_blob_receivers: Some(vec![]),
    };

    for cpu_id in 0..num_cpus::get() {
        let (blob_id_sender, blob_id_receiver) = unbounded_channel();
        let (blob_sender, blob_receiver) = unbounded_channel();
        let (merged_blob_sender, merged_blob_receiver) = unbounded_channel();

        senders_receivers.append(blob_id_sender, blob_sender, merged_blob_receiver);

        tokio::spawn(merge_blob(
            cpu_id,
            blob_id_receiver,
            blob_receiver,
            merged_blob_sender,
        ));
    }

    senders_receivers
}
