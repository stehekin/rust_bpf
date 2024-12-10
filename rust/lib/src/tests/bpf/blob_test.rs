use std::time;
use rand::Rng;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use crate::bpf::blob::{BlobReader, seq_to_blob_id};
use crate::bpf::types_conv::lw_blob_with_data;

// `fake_blob` returns a blob with given blob id. Other properties of the given blob are undetermined.
fn fake_blob(cpu: usize, sequence: u64) -> lw_blob_with_data {
    let mut blob = lw_blob_with_data::default();
    blob.header.blob_id = seq_to_blob_id(cpu, sequence);
    blob
}

#[tokio::test]
async fn test_blob_reader() {
    let (sender, receiver) = async_channel::unbounded();
    let cpu_id = 3;
    let max_seq = 1024;
    let blob_id = seq_to_blob_id(cpu_id, rand::thread_rng().gen_range(0..max_seq));

    let r= tokio::spawn(async move {
        let mut reader = BlobReader::new(cpu_id, receiver);
        reader.retrieve(blob_id).await.expect("")
    });

    sleep(time::Duration::from_secs(5));

    let w = tokio::spawn(async move {
        for seq in 0..max_seq {
            sender.send(fake_blob(3, seq)).await;
        }
    });

    w.await.expect("channel write error");
    assert_eq!(r.await.expect("channel read error").unwrap().header.blob_id, blob_id);
}