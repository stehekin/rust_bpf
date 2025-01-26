use crate::bpf::blob::{merge_blob, seq_to_blob_id, MergedBlob};
use crate::bpf::types::lw_blob;
use anyhow::Context;
use rand::Rng;
use tokio::sync::mpsc::unbounded_channel;
use tokio::task;

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

#[tokio::test]
async fn test_blob_reader() {
    let (blob_id_sender, blob_id_receiver) = unbounded_channel();
    let (blob_sender, blob_receiver) = unbounded_channel();
    let (merged_blob_sender, mut merged_blob_receiver) = unbounded_channel();

    let cpu_id = rand::rng().random_range(0..1024);
    let max_seq = 1024;
    let blob_id = seq_to_blob_id(cpu_id, rand::rng().random_range(0..max_seq));

    tokio::spawn(merge_blob(
        cpu_id,
        blob_id_receiver,
        blob_receiver,
        merged_blob_sender.clone(),
    ));

    let _blob_sender = blob_sender.clone();
    tokio::spawn(async move {
        for seq in 0..max_seq {
            _blob_sender
                .send(fake_blob(cpu_id, seq, 0, None))
                .expect("failed to send blobs");
        }
    });

    let _blob_id_sender = blob_id_sender.clone();
    tokio::spawn(async move {
        _blob_id_sender
            .send(blob_id)
            .expect("failed to send blob_id");
    });

    let blob = merged_blob_receiver.recv().await.expect("");
    assert_eq!(blob.0, blob_id);
}

/*
#[tokio::test(flavor = "multi_thread")]
async fn test_blob_reader_merge() {
    let (sender, receiver) = async_channel::unbounded();
    let cpu = 1;
    let seq = 2;
    let data = "012345678".as_bytes();

    let mut reader = BlobReceiver::new(cpu, receiver);

    let r = tokio::spawn(async move {
        let mut merged = vec![];
        merge_blobs(seq_to_blob_id(cpu, seq), &mut merged, &mut reader)
            .await
            .expect("error merging blobs");
        merged
    });

    let w = tokio::spawn(async move {
        sender
            .send(fake_blob(cpu, seq, 9, Some(&data[0..1])))
            .await
            .expect("error sending blob");
        sender
            .send(fake_blob(cpu, 9, 11, Some(&data[1..6])))
            .await
            .expect("error sending blob");
        sender
            .send(fake_blob(cpu, 11, 0, Some(&data[6..data.len()])))
            .await
            .expect("error sending blob");
    });

    w.await.expect("error channel writing");
    let merged = r.await.expect("error merging blobs");

    assert_eq!(merged.as_slice(), data);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_blob_reader_merge_with_missing_blobs() {
    let (sender, receiver) = async_channel::unbounded();
    let cpu = 1;
    let seq = 2;
    let data = "012345678".as_bytes();

    let mut reader = BlobReceiver::new(cpu, receiver);

    let r = tokio::spawn(async move {
        let mut merged = vec![];
        let r = merge_blobs(seq_to_blob_id(cpu, seq), &mut merged, &mut reader).await;
        (merged, r)
    });

    let w = tokio::spawn(async move {
        sender
            .send(fake_blob(cpu, seq, 9, Some(&data[0..1])))
            .await
            .expect("error sending blob");
        sender
            .send(fake_blob(cpu, 11, 0, Some(&data[6..data.len()])))
            .await
            .expect("error sending blob");
    });

    w.await.expect("error channel writing");
    let (merged, result) = r.await.expect("error merging blobs");

    assert!(result.is_err());
    assert_eq!(merged.as_slice(), &data[0..1]);
}

#[tokio::test(flavor = "multi_thread")]
// Interleaved blocks should never happen in the real life. But it is a good test case for the `merge_blobs`.
async fn test_blob_reader_merge_interleaved_blocks() {
    let (sender, receiver) = async_channel::unbounded();
    let cpu = 1;
    let seq_1 = 2;
    let seq_2 = 7;
    let data = "012345678".as_bytes();

    let mut reader = BlobReceiver::new(cpu, receiver);

    let r = tokio::spawn(async move {
        let mut merged_1 = vec![];
        let mut merged_2 = vec![];
        merge_blobs(seq_to_blob_id(cpu, seq_1), &mut merged_1, &mut reader)
            .await
            .expect("error merging blobs");
        let result_2 = merge_blobs(seq_to_blob_id(cpu, seq_2), &mut merged_2, &mut reader).await;
        (merged_1, result_2)
    });

    let w = tokio::spawn(async move {
        //  Sequences:
        //  data_1:  2,   9, 11
        //  data_2:     7
        //  data_2 is be discarded by when merging blob_1 as 7 < 9.
        sender
            .send(fake_blob(cpu, seq_1, 9, Some(&data[0..1])))
            .await
            .expect("error sending blob");
        sender
            .send(fake_blob(cpu, seq_2, 0, Some(&data[0..1])))
            .await
            .expect("error sending blob");
        sender
            .send(fake_blob(cpu, 9, 11, Some(&data[1..6])))
            .await
            .expect("error sending blob");
        sender
            .send(fake_blob(cpu, 11, 0, Some(&data[6..data.len()])))
            .await
            .expect("error sending blob");
    });

    w.await.expect("error channel writing");
    let (merged_1, result_2) = r.await.expect("error merging blobs");

    assert_eq!(merged_1.as_slice(), data);
    assert!(result_2.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_blob_channel_groups_single_cpu() {
    let cpu_num = 2; //num_cpus::get();
    let data = "012345678".as_bytes();
    let seq = 2;

    let (sender, mut receiver) = blob_channel_groups();

    let r = tokio::spawn(async move {
        for cpu in 0..cpu_num {
            let mut merged = vec![];
            receiver
                .merge_blobs(seq_to_blob_id(cpu, seq), &mut merged)
                .await
                .expect("error merging blobs");
            assert_eq!(merged, data);
        }
    });

    let w = tokio::spawn(async move {
        for cpu in 0..cpu_num {
            sender
                .send(fake_blob(cpu, seq, 9, Some(&data[0..1])))
                .await
                .expect("error sending blob");
            sender
                .send(fake_blob(cpu, 9, 11, Some(&data[1..6])))
                .await
                .expect("error sending blob");
            sender
                .send(fake_blob(cpu, 11, 0, Some(&data[6..data.len()])))
                .await
                .expect("error sending blob");
        }
    });

    w.await.expect("error channel writing");
    r.await.expect("error merging all blobs");
}
*/
