use std::collections::VecDeque;
use crate::bpf::types_conv::lw_blob_with_data;

pub struct BlobManager {
    blob_queues: Vec<VecDeque<lw_blob_with_data>>,
}

impl Default for BlobManager {
    fn default() -> Self {
        let mut bm = Self {
            blob_queues: vec![],
        };
        for _ in 0..num_cpus::get() {
            bm.blob_queues.push(VecDeque::new());
        }
        bm
    }    
}

impl BlobManager {
    pub fn add(&mut self, blob: lw_blob_with_data) {
        let (cpu, sequence) = Self::from_blob_id(blob.header.blob_id);
        let mut blob_queue = &mut self.blob_queues[cpu];
        blob_queue.push_back(blob);
    }

    // `get` finds the blob with the given blob_id in the blob_queues.
    // During the search, blobs that sent earlier than the given blob in the same CPU queue are discarded.
    // It works as in the user space signals emitted from a same CPU are handled in order.
    pub fn get(&mut self, blob_id: u64) ->Option<lw_blob_with_data> {
        let (cpu, sequence) = Self::from_blob_id(blob_id);
        let queue = &mut self.blob_queues[cpu];

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

    pub fn from_blob_id(blob_id: u64) -> (usize, u64) {
        (((blob_id & 0xFFFF000000000000) >> 48) as usize, blob_id & 0x0000FFFFFFFFFFFF)
    }

    pub fn blob_id_of(cpu: usize, sequence: u64) -> u64 {
        let cpu = cpu as u64;
        (sequence & 0x0000FFFFFFFFFFFF) | (cpu << 48)
    }
}