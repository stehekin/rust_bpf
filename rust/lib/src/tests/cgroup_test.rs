use crate::bpf::bpf_loader::load_cgroup_iter;

use std::{mem::MaybeUninit, os::fd::AsFd};

#[test]
fn test_cgroup_iter() {
    let mut ci_open_object = MaybeUninit::uninit();
    let f = std::fs::File::open("/sys/fs/cgroup/user.slice").expect("file doesn't exist");
    load_cgroup_iter(&mut ci_open_object, f.as_fd())
        .expect("error loading probe sched_process_exec");
}
