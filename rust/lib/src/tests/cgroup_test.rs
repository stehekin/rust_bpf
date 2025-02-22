use crate::bpf::bpf_loader::load_cgroup_iter;

use std::{io::Read, mem::MaybeUninit, os::fd::AsFd};

#[test]
fn test_cgroup_iter() {
    let mut cgiter_open_object = MaybeUninit::uninit();
    let f = std::fs::File::open("/sys/fs/cgroup/user.slice").expect("file doesn't exist");
    let mut iter = load_cgroup_iter(&mut cgiter_open_object, f.as_fd())
        .expect("error loading probe cgroup iter");
    let mut data = vec![];
    iter.read_to_end(&mut data);
    print!(">>>>> {0}\n", String::from_utf8_lossy(data.as_slice()));
}
