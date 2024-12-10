use rand::Rng;
use crate::bpf::blob::{BlobManager, BlobReader, seq_to_blob_id};
use crate::bpf::types_conv::lw_blob_with_data;

// `fake_blob` returns a blob with given blob id. Other properties of the given blob are undetermined.
fn fake_blob(cpu: usize, sequence: u64) -> lw_blob_with_data {
    let mut blob = lw_blob_with_data::default();
    blob.header.blob_id = seq_to_blob_id(cpu, sequence);
    blob
}

#[tokio::test]
async fn test_blob_reader_get() {
    let (sender, receiver) = async_channel::unbounded();
    let cpu_id = 3;
    let max_seq = 1024;
    for seq in 0..max_seq {
        sender.send(fake_blob(3, seq)).await.expect("blob sending failure");
    }

    let r = tokio::spawn(|| {
        let blob_id = seq_to_blob_id(cpu_id, rand::thread_rng().gen_range(0..max_seq));

        let mut reader = BlobReader::new(cpu_id, receiver);
        let blob = reader.get(blob_id).await.expect("blob receiving failure");
    });
    
}

#[test]
fn test_blob_manager() {
    let cpus = num_cpus::get();
    let mut bm = BlobManager::default();
    for cpu in 0..cpus {
        for seq in 0..100 - cpu {
            bm.add(fake_blob(cpu, seq as u64));
        }
    }

    for cpu in 0..cpus {
        for seq in 0..100 - cpu {
            let blob_id = seq_to_blob_id(cpu, seq as u64);
            assert!(bm.get(blob_id).is_some());
            assert!(bm.get(blob_id).is_none());
        }
    }
}