use std::mem::size_of;
use plain::Plain;
use crate::bpf::types::{lw_blob, lw_sigal_header, lw_signal_task, lw_task};

const BLOB_SIZE_MAX: usize = 1024;
#[repr(C)]
pub struct lw_blob_with_data {
    pub header: lw_blob,
    // The maximum size of `lw_blob` is 1024 in the ebpf, which includes `header`.
    pub data: [u8; BLOB_SIZE_MAX],
}

impl Default for lw_blob_with_data {
    fn default() -> Self {
        lw_blob_with_data {
            header: lw_blob::default(),
            data: [0; BLOB_SIZE_MAX],
        }
    }
}

unsafe impl Plain for lw_blob {}
unsafe impl Plain for lw_task {}
unsafe impl Plain for lw_sigal_header {}
unsafe impl Plain for lw_signal_task {}

pub(crate) fn copy_from_bytes<T: Default + Plain>(buf: &[u8]) -> T {
    let mut result = T::default();
    plain::copy_from_bytes(&mut result, buf).expect("corrupted data");
    result
}

impl lw_blob_with_data {
    pub fn copy_from_bytes(buf: &[u8]) -> lw_blob_with_data {
        let mut result = lw_blob_with_data {
            header: copy_from_bytes(buf),
            data: [0; BLOB_SIZE_MAX],
        };
        let size = result.header.data_size as usize;
        plain::copy_from_bytes(&mut result.data[..size], &buf[size_of::<lw_blob>()..])
            .expect("corrupted data");
        result
    }
}
