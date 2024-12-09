use std::mem::size_of;
use plain::Plain;
use crate::bpf::types::lw_blob;

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
impl lw_blob {
    fn from_bytes(buf: &[u8]) -> &lw_blob {
        plain::from_bytes(buf).expect("corrupted data")
    }

    fn from_mut_bytes(buf: &mut [u8]) -> &mut lw_blob {
        plain::from_mut_bytes(buf).expect("corrupted data")
    }

    fn copy_from_bytes(buf: &[u8]) -> lw_blob {
        let mut result = lw_blob::default();
        plain::copy_from_bytes(&mut result, buf).expect("corrupted data");
        result
    }
}

impl lw_blob_with_data {
    pub fn copy_from_bytes(buf: &[u8]) -> lw_blob_with_data {
        let mut result = lw_blob_with_data {
            header: lw_blob::copy_from_bytes(buf),
            data: [0; BLOB_SIZE_MAX],
        };
        let size = result.header.data_size as usize;
        plain::copy_from_bytes(&mut result.data[..size], &buf[size_of::<lw_blob>()..])
            .expect("corrupted data");
        result
    }
}
