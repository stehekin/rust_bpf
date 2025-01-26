use crate::bpf::sched_process_exec;
use crate::bpf::sched_process_exec::ProbeSkel;
use crate::bpf::types;
use crate::bpf::types::{lw_blob, lw_sigal_header, lw_signal_task};
use crate::bpf::types_conv::copy_from_bytes;

use anyhow::Result;
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    RingBufferBuilder,
};

use std::mem::MaybeUninit;

fn setup_bpf(open_object: &mut MaybeUninit<libbpf_rs::OpenObject>) -> Result<ProbeSkel> {
    let builder = sched_process_exec::ProbeSkelBuilder::default();
    let open_skel = builder
        .open(open_object)
        .expect("error opening sched_process_exec");
    let mut skel = open_skel.load().expect("error loading sched_process_exec");
    skel.attach().expect("error attaching sched_process_exec");

    Ok(skel)
}

fn setup_channels() {
    for cpu_id in 0..num_cpus::get() {}
}

#[tokio::test]
async fn test_process_regular() {}
