use std::time;
use rand::Rng;
use tokio::time::sleep;
use crate::bpf::blob::{BlobReceiver, merge_blobs, seq_to_blob_id, blob_channel_groups};
use crate::bpf::types_conv::lw_blob_with_data;


fn fake_blob(cpu: usize, sequence: u64, next: u64, data: Option<&[u8]>) -> lw_blob_with_data {
    let mut blob = lw_blob_with_data::default();
    blob.header.blob_id = seq_to_blob_id(cpu, sequence);
    blob.header.blob_next = seq_to_blob_id(cpu, next);

    if let Some(data) = data {
        blob.header.data_size = data.len() as u16;
        blob.data[0..data.len()].copy_from_slice(data);
    }

    blob
}

#[tokio::test]
async fn test_blob_reader() {
    let (sender, receiver) = async_channel::unbounded();
    let cpu_id = 3;
    let max_seq = 1024;
    let blob_id = seq_to_blob_id(cpu_id, rand::thread_rng().gen_range(0..max_seq));

    let r= tokio::spawn(async move {
        let mut reader = BlobReceiver::new(cpu_id, receiver);
        reader.retrieve(blob_id).await.expect("error channel reading")
    });

    sleep(time::Duration::from_secs(2));

    let w = tokio::spawn(async move {
        for seq in 0..max_seq {
            sender.send(fake_blob(3, seq, 0, None)).await.expect("error sending blob");
        }
    });

    w.await.expect("error channel writing");
    assert_eq!(r.await.expect("error channel reading").unwrap().header.blob_id, blob_id);
}

#[tokio::test]
async fn test_blob_reader_merge() {
    let (sender, receiver) = async_channel::unbounded();
    let cpu = 1;
    let seq = 2;
    let data = "012345678".as_bytes();

    let mut reader = BlobReceiver::new(cpu, receiver);

    let r= tokio::spawn(async move {
        let mut merged = vec![];
        merge_blobs(seq_to_blob_id(cpu, seq), &mut merged, &mut reader).await.expect("error merging blobs");
        merged
    });

    sleep(time::Duration::from_secs(2));

    let w = tokio::spawn(async move {
        sender.send(fake_blob(cpu, seq, 9, Some(&data[0..1]))).await.expect("error sending blob");
        sender.send(fake_blob(cpu, 9, 11, Some(&data[1..6]))).await.expect("error sending blob");
        sender.send(fake_blob(cpu, 11, 0, Some(&data[6..data.len()]))).await.expect("error sending blob");
    });

    w.await.expect("error channel writing");
    let merged = r.await.expect("error merging blobs");

    assert_eq!(merged.as_slice(), data);
}

#[tokio::test]
async fn test_blob_reader_merge_with_missing_blobs() {
    let (sender, receiver) = async_channel::unbounded();
    let cpu = 1;
    let seq = 2;
    let data = "012345678".as_bytes();

    let mut reader = BlobReceiver::new(cpu, receiver);

    let r= tokio::spawn(async move {
        let mut merged = vec![];
        let r = merge_blobs(seq_to_blob_id(cpu, seq), &mut merged, &mut reader).await;
        (merged, r)
    });

    sleep(time::Duration::from_secs(2));

    let w = tokio::spawn(async move {
        sender.send(fake_blob(cpu, seq, 9, Some(&data[0..1]))).await.expect("error sending blob");
        sender.send(fake_blob(cpu, 11, 0, Some(&data[6..data.len()]))).await.expect("error sending blob");
    });

    w.await.expect("error channel writing");
    let (merged, result) = r.await.expect("error merging blobs");

    assert!(result.is_err());
    assert_eq!(merged.as_slice(), &data[0..1]);
}



#[tokio::test]
// Interleaved blocks should never happen in the real life. But it is a good test case for the `merge_blobs`.
async fn test_blob_reader_merge_interleaved_blocks() {
    let (sender, receiver) = async_channel::unbounded();
    let cpu = 1;
    let seq_1 = 2;
    let seq_2 = 7;
    let data = "012345678".as_bytes();

    let mut reader = BlobReceiver::new(cpu, receiver);

    let r= tokio::spawn(async move {
        let mut merged_1 = vec![];
        let mut merged_2 = vec![];
        merge_blobs(seq_to_blob_id(cpu, seq_1), &mut merged_1, &mut reader).await.expect("error merging blobs");
        let result_2 = merge_blobs(seq_to_blob_id(cpu, seq_2), &mut merged_2, &mut reader).await;
        (merged_1, result_2)
    });

    sleep(time::Duration::from_secs(2));

    let w = tokio::spawn(async move {
        //  Sequences:
        //  data_1:  2,   9, 11
        //  data_2:     7
        //  data_2 is be discarded by when merging blob_1 as 7 < 9.
        sender.send(fake_blob(cpu, seq_1, 9, Some(&data[0..1]))).await.expect("error sending blob");
        sender.send(fake_blob(cpu, seq_2, 0, Some(&data[0..1]))).await.expect("error sending blob");
        sender.send(fake_blob(cpu, 9, 11, Some(&data[1..6]))).await.expect("error sending blob");
        sender.send(fake_blob(cpu, 11, 0, Some(&data[6..data.len()]))).await.expect("error sending blob");
    });

    w.await.expect("error channel writing");
    let (merged_1, result_2) = r.await.expect("error merging blobs");

    assert_eq!(merged_1.as_slice(), data);
    assert!(result_2.is_err());
}

#[tokio::test]
async fn test_blob_channel_groups_single_cpu() {
    let cpu_num = 2; //num_cpus::get();
    let data = "012345678".as_bytes();
    let seq = 2;

    let (sender, mut receiver) = blob_channel_groups();

    let r = tokio::spawn(async move {
        for cpu in 0..cpu_num {
            let mut merged = vec![];
            receiver.merge_blobs(seq_to_blob_id(cpu, seq), &mut merged).await.expect("error merging blobs");
            assert_eq!(merged, data);
        }
    });

    sleep(time::Duration::from_secs(2));

    let w = tokio::spawn(async move {
        for cpu in 0..cpu_num {
            sender.send(fake_blob(cpu, seq, 9, Some(&data[0..1]))).await.expect("error sending blob");
            sender.send(fake_blob(cpu, 9, 11, Some(&data[1..6]))).await.expect("error sending blob");
            sender.send(fake_blob(cpu, 11, 0, Some(&data[6..data.len()]))).await.expect("error sending blob");
        }
    });

    w.await.expect("error channel writing");
    r.await.expect("error merging all blobs");
}
