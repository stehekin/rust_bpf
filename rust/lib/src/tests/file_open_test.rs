use crate::bpf::file_open;
use libbpf_rs::{
  skel::{OpenSkel, Skel, SkelBuilder},
  MapHandle, MapType, RingBuffer, RingBufferBuilder,
};

#[test]
fn test_file_open() {
  let builder = file_open::ProbeSkelBuilder::default();
  let mut open_skel = builder.open().unwrap();
  let mut skel = open_skel.load().unwrap();
  skel.attach().unwrap();
}