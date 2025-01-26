use super::types::BLOB_SIZE;
use crate::bpf::types::{lw_blob, lw_blob_header, lw_sigal_header, lw_signal_task, lw_task};
use plain::Plain;
use std::mem::size_of;

// BLOB_SIZE - sizeof(lw_blob_header)
const BLOB_DATA_SIZE: usize = BLOB_SIZE as usize - size_of::<lw_blob_header>();

unsafe impl Plain for lw_blob_header {}
unsafe impl Plain for lw_blob {}
unsafe impl Plain for lw_task {}
unsafe impl Plain for lw_sigal_header {}
unsafe impl Plain for lw_signal_task {}

pub(crate) fn copy_from_bytes<T: Default + Plain>(buf: &[u8]) -> T {
    let mut result = T::default();
    plain::copy_from_bytes(&mut result, buf).expect("corrupted data");
    result
}

impl lw_blob {
    pub fn copy_from_bytes(buf: &[u8]) -> lw_blob {
        let mut result = lw_blob {
            header: copy_from_bytes(buf),
            data: [0; BLOB_DATA_SIZE],
        };
        plain::copy_from_bytes(
            &mut result.data[..BLOB_DATA_SIZE],
            &buf[size_of::<lw_blob_header>()..],
        )
        .expect("corrupted data");
        result
    }
}
