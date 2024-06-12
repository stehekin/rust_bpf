use crate::bpf::file_open::ProbeSkel;
use std::fs::metadata;
use std::os::linux::fs::MetadataExt;
use anyhow::{bail, Error, Result};
use libbpf_rs::MapFlags;

pub trait ProbeSkelExt {
    fn monitor_file(&self, file_name: &str) -> Result<()>;
}
impl<'a> ProbeSkelExt for ProbeSkel<'a> {
    fn monitor_file(&self, file_name: &str) -> Result<()> {
        let metadata = metadata(file_name)?;
        let key = super::types::fo_inode {
            s_dev: super::utils::convert_dev_t(metadata.st_dev()),
            i_ino: metadata.st_ino(),
        };
        let key = unsafe { super::utils::any_as_u8_slice(&key) };
        let value = 0 as u64;
        let value = unsafe { super::utils::any_as_u8_slice(&value) };
        self.maps().fo_inode_map()
            .update(key, value, MapFlags::ANY)
            .map_err(Error::msg)
    }
}