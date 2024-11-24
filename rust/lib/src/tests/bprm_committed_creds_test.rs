use std::mem::MaybeUninit;
use std::time::Duration;
use anyhow::Result;
use crate::bpf::bprm_committed_creds as bprm;
use crate::bpf::bprm_committed_creds::ProbeSkel;

use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    MapHandle, MapType, RingBuffer, RingBufferBuilder,
};
use libbpf_sys::{ring_buffer__new, ring_buffer__poll};


#[test]
fn test_bprm_committed_creds() {
    let mut open_object = MaybeUninit::uninit();
    let skel = load_bpf(&mut open_object).unwrap();
    let mut rbb = RingBufferBuilder::new();
    rbb.add(&skel.maps._blob_ringbuf_, move |data| -> i32 {
        println!("data received\n");
        return 0;
    }).unwrap();

    let rb = rbb.build().unwrap();

    while rb.poll(Duration::from_secs(1)).is_ok() {
        println!("got data\n");
    }
}

fn load_bpf(open_object: &mut MaybeUninit<libbpf_rs::OpenObject>) -> Result<ProbeSkel> {
    let builder = bprm::ProbeSkelBuilder::default();

    let mut open_skel = builder.open(open_object)?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    Ok(skel)
}