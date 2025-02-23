use crate::bpf::bpf_loader::load_cgroup_iter;

use std::{io::Read, mem::MaybeUninit, os::fd::AsFd};

#[test]
fn test_cgroup_iter() {
    let mut cgiter_open_object = MaybeUninit::uninit();
    let mut iter = load_cgroup_iter(
        &mut cgiter_open_object,
        1,
        libbpf_sys::BPF_CGROUP_ITER_DESCENDANTS_PRE,
    )
    .expect("error loading probe cgroup iter");
    let mut data = vec![0; 512];
    // Don't use read functions other than `read`. Those functions call std::fs::read on the iter multiple times, which causes `operation not supported` error.
    // Instead, providing a buffer large enough to call `read` once.
    // Here 512 / 8 = 64. For BPF_CGROUP_ITER_ANCESTORS_UP, we can tolerate 64 layers, which should be enough.
    iter.read(&mut data).expect("mamade");
    print!(">>>>> {:?}\n", data);
}
