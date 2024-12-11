use std::mem::MaybeUninit;
use anyhow::Result;

use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    MapHandle, MapType, RingBuffer, RingBufferBuilder,
};
use crate::bpf::types_conv::lw_blob_with_data;


#[test]
fn test_bprm_committed_creds() {
    // let mut open_object = MaybeUninit::uninit();
    // let skel = load_bpf(&mut open_object).unwrap();
    // let mut rbb = RingBufferBuilder::new();
    // let mut exit = Rc::new(RefCell::new(false));
    // let exit1 = exit.clone();
    // rbb.add(&skel.maps._blob_ringbuf_,   move |data| -> i32 {
    //     let data = lw_blob_with_data::copy_from_bytes(data);
    //     println!("header {0:?}", data.header);
    //     println!("cpu: {0}, sequence: {1}", (data.header.blob_id & 0xFFFF000000000000)>>48, data.header.blob_id & 0x0000FFFFFFFFFFFF);
    //     println!("value  {0:?}", std::str::from_utf8(&data.data[..data.header.data_size as usize]).expect("wrong"));
    //     if data.header.data_size > 200 {
    //         *exit1.borrow_mut() = true;
    //     }
    //     return 0;
    // }).unwrap();
    //
    // let rb = rbb.build().unwrap();
    //
    // while rb.poll(Duration::from_secs(1)).is_ok() {
    //     if *exit.borrow() {
    //         break
    //     }
    // }
}

// fn load_bpf(open_object: &mut MaybeUninit<libbpf_rs::OpenObject>) -> Result<ProbeSkel> {
//     let builder = bprm::ProbeSkelBuilder::default();
//
//     let mut open_skel = builder.open(open_object)?;
//     let mut skel = open_skel.load()?;
//     skel.attach()?;
//
//     Ok(skel)
// }