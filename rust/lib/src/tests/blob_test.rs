use tokio::task::JoinHandle;

use crate::bpf::blob::{seq_to_blob_id, spawn_blob_mergers};
use crate::bpf::types::lw_blob;
use rand::Rng;
use tokio::sync::mpsc::UnboundedSender;

fn fake_blob(cpu: usize, sequence: u64, next: u64, data: Option<&[u8]>) -> lw_blob {
    let mut blob = lw_blob::default();
    blob.header.blob_id = seq_to_blob_id(cpu, sequence);
    blob.header.blob_next = seq_to_blob_id(cpu, next);

    if let Some(data) = data {
        blob.header.effective_data_size = data.len() as u16;
        blob.data[0..data.len()].copy_from_slice(data);
    }

    blob
}

fn spawn_blob_id_sender(blob_id_sender: UnboundedSender<u64>, blob_id: u64) -> JoinHandle<()> {
    tokio::spawn(async move {
        blob_id_sender
            .send(blob_id)
            .expect("failed to send blob_id")
    })
}

// `test_blob_reader` picks a random blob from a blob sequence.
#[tokio::test]
async fn test_blob_reader() {
    let cpu_id = rand::rng().random_range(0..num_cpus::get());
    let max_seq = 1024;
    let blob_id = seq_to_blob_id(cpu_id, rand::rng().random_range(0..max_seq));

    let mut senders_receivers = spawn_blob_mergers();

    let sr = senders_receivers
        .get_mut(cpu_id)
        .expect("channle not defined for cpu");

    spawn_blob_id_sender(sr.blob_id_sender.clone(), blob_id);

    let _blob_sender = sr.blob_sender.clone();
    tokio::spawn(async move {
        for seq in 0..max_seq {
            _blob_sender
                .send(fake_blob(cpu_id, seq, 0, None))
                .expect("failed to send blobs");
        }
    });

    let blob = &mut sr.merged_blob_receiver.recv().await.expect("");

    drop(senders_receivers);
    assert_eq!(blob.0, blob_id);
}

// `test_blob_reader` merges blobs with id 2, 9, 11.
#[tokio::test]
async fn test_blob_reader_merge() {
    let cpu_id = 0;
    // seq must < 9.
    let seq = 2;
    let blob_id = seq_to_blob_id(cpu_id, seq);
    let data = "012345678".as_bytes();

    let mut senders_receivers = spawn_blob_mergers();

    let sr = senders_receivers
        .get_mut(cpu_id)
        .expect("channle not defined for cpu");

    spawn_blob_id_sender(sr.blob_id_sender.clone(), blob_id);

    let _blob_sender = sr.blob_sender.clone();
    tokio::spawn(async move {
        _blob_sender
            .send(fake_blob(cpu_id, seq, 9, Some(&data[0..1])))
            .expect("error sending blob");
        _blob_sender
            .send(fake_blob(cpu_id, 9, 11, Some(&data[1..6])))
            .expect("error sending blob");
        _blob_sender
            .send(fake_blob(cpu_id, 11, 0, Some(&data[6..data.len()])))
            .expect("error sending blob");
    });

    let blob = &mut sr.merged_blob_receiver.recv().await.expect("");

    drop(senders_receivers);
    assert_eq!(blob.1.as_slice(), data);
}

// `test_blob_reader` merges blobs with id 2, 9, 11. But blob 9 is missing so a partial blob is returned.
#[tokio::test]
async fn test_blob_reader_merge_with_missing_blobs() {
    let cpu_id = 1;
    // seq must < 9;
    let seq = 2;
    let blob_id = seq_to_blob_id(cpu_id, seq);
    let data = "012345678".as_bytes();

    let mut senders_receivers = spawn_blob_mergers();

    let sr = senders_receivers
        .get_mut(cpu_id)
        .expect("channle not defined for cpu");

    spawn_blob_id_sender(sr.blob_id_sender.clone(), blob_id);

    let _blob_sender = sr.blob_sender.clone();
    tokio::spawn(async move {
        _blob_sender
            .send(fake_blob(cpu_id, seq, 9, Some(&data[0..1])))
            .expect("error sending blob");
        _blob_sender
            .send(fake_blob(cpu_id, 11, 0, Some(&data[6..data.len()])))
            .expect("error sending blob");
    });

    let blob = &mut sr.merged_blob_receiver.recv().await.expect("");

    drop(senders_receivers);
    assert_eq!(blob.1.as_slice(), &data[0..1]);
}

// `test_blob_reader_merge_interleaved_blocks` tests the merge of interleaved blobs.
#[tokio::test(flavor = "multi_thread")]
async fn test_blob_reader_merge_interleaved_blocks() {
    let cpu_id = 1;
    // seq must < 9;
    let seq = 2;
    let wrong_seq = 7;
    let blob_id = seq_to_blob_id(cpu_id, seq);
    let data = "012345678".as_bytes();

    let mut senders_receivers = spawn_blob_mergers();

    let sr = senders_receivers
        .get_mut(cpu_id)
        .expect("channle not defined for cpu");

    spawn_blob_id_sender(sr.blob_id_sender.clone(), blob_id);

    let _blob_sender = sr.blob_sender.clone();
    tokio::spawn(async move {
        //  Sequences:
        //  data_1:  2,   9, 11
        //  data_2:     7
        //  data_2 is be discarded by when merging blob_1 as 7 < 9.
        _blob_sender
            .send(fake_blob(cpu_id, seq, 9, Some(&data[0..1])))
            .expect("error sending blob");
        _blob_sender
            .send(fake_blob(cpu_id, wrong_seq, 0, Some(&data[0..1])))
            .expect("error sending blob");
        _blob_sender
            .send(fake_blob(cpu_id, 9, 11, Some(&data[1..6])))
            .expect("error sending blob");
        _blob_sender
            .send(fake_blob(cpu_id, 11, 0, Some(&data[6..data.len()])))
            .expect("error sending blob");
    });

    let blob = &mut sr.merged_blob_receiver.recv().await.expect("");

    drop(senders_receivers);
    assert_eq!(blob.1.as_slice(), data);
}
