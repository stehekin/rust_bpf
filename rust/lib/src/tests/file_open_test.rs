// use std::mem::MaybeUninit;
// use anyhow::Result;
// use libbpf_rs::{skel::{OpenSkel, Skel, SkelBuilder}};
//
// use crate::bpf::file_open;
// use crate::bpf::file_open::ProbeSkel;

#[test]
fn test_file_open() {
  // let mut open_object = MaybeUninit::uninit();
  // let skel = load_bpf(&mut open_object).unwrap();
  // skel.monitor_file("/tmp/test").unwrap();
  // std::thread::sleep(Duration::from_secs(3600));
}

// fn load_bpf(open_object: &mut MaybeUninit<libbpf_rs::OpenObject>) -> Result<ProbeSkel> {
//   let builder = file_open::ProbeSkelBuilder::default();
//
//   let open_skel = builder.open(open_object)?;
//   let mut skel = open_skel.load()?;
//   skel.attach()?;
//
//   Ok(skel)
// }