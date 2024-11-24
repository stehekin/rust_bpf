use std::mem::MaybeUninit;
use std::time::Duration;
use anyhow::Result;
use crate::bpf::bprm_committed_creds as bprm;
use crate::bpf::bprm_committed_creds::ProbeSkel;

use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    MapHandle, MapType, RingBuffer, RingBufferBuilder,
};
use crate::bpf::types_conv::lw_blob_with_data;


#[test]
fn test_bprm_committed_creds() {
    let mut open_object = MaybeUninit::uninit();
    let skel = load_bpf(&mut open_object).unwrap();
    let mut rbb = RingBufferBuilder::new();
    rbb.add(&skel.maps._blob_ringbuf_, move |data| -> i32 {
        let data = lw_blob_with_data::copy_from_bytes(data);
        println!("header {0:?}", data.header);
        println!("cpu: {0}, sequence: {1}", (data.header.blob_id & 0xFFFF000000000000)>>48, data.header.blob_id & 0x0000FFFFFFFFFFFF);
        println!("value  {0:?}", std::str::from_utf8(&data.data[..data.header.data_size as usize - 1]).expect("wrong"));
        return 0;
    }).unwrap();

    let rb = rbb.build().unwrap();

    let mut count = 0;
    while rb.poll(Duration::from_secs(1)).is_ok() {
        count += 1;
        if count > 10 {
            break;
        }
    }
}

fn load_bpf(open_object: &mut MaybeUninit<libbpf_rs::OpenObject>) -> Result<ProbeSkel> {
    let builder = bprm::ProbeSkelBuilder::default();

    let mut open_skel = builder.open(open_object)?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    Ok(skel)
}