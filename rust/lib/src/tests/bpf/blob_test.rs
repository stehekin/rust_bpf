use std::time;
use rand::Rng;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use crate::bpf::blob::{BlobReceiver, merge_blobs, seq_to_blob_id};
use crate::bpf::types_conv::lw_blob_with_data;


fn fake_blob(cpu: usize, sequence: u64, next: u64, data: Option<&[u8]>) -> lw_blob_with_data {
    let mut blob = lw_blob_with_data::default();
    blob.header.blob_id = seq_to_blob_id(cpu, sequence);
    blob.header.blob_next = seq_to_blob_id(cpu, sequence);

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
            sender.send(fake_blob(3, seq, 0, None)).await;
        }
    });

    w.await.expect("error channel writing");
    assert_eq!(r.await.expect("error channel reading").unwrap().header.blob_id, blob_id);
}

#[tokio::test]
async fn test_blob_reader_merge() {
    let (sender, receiver) = async_channel::unbounded();
    let cpu = 3;
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
        sender.send(fake_blob(cpu, seq, 9, Some(&data[0..1])));
        sender.send(fake_blob(cpu, 9, 11, Some(&data[1..6])));
        sender.send(fake_blob(cpu, 11, 0, Some(&data[6..data.len()])));
    });

    w.await.expect("error channel writing");
    let merged = r.await.expect("error merging blobs");

    assert_eq!(merged.as_slice(), data);
}