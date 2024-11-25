use crate::bpf::blob::BlobManager;
use crate::bpf::types_conv::lw_blob_with_data;

// `fake_blob` returns a blob with given blob id. Other properties of the given blob are undetermined.
fn fake_blob(cpu: usize, sequence: u64) -> lw_blob_with_data {
    let mut blob = lw_blob_with_data::default();
    blob.header.blob_id = BlobManager::blob_id_of(cpu, sequence);
    blob
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
            let blob_id = BlobManager::blob_id_of(cpu, seq as u64);
            assert!(bm.get(blob_id).is_some());
            assert!(bm.get(blob_id).is_none());
        }
    }
}