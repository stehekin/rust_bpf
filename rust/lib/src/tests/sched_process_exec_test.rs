use anyhow::Result;
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder}, RingBufferBuilder,
};
use std::cell::RefCell;
use std::mem::MaybeUninit;
use std::rc::Rc;
use std::thread::sleep;
use std::time::Duration;


use crate::bpf::blob::{blob_channel_groups};
use crate::bpf::sched_process_exec;
use crate::bpf::sched_process_exec::ProbeSkel;
use crate::bpf::types_conv::{lw_blob_with_data, copy_from_bytes};
use crate::bpf::types;
use crate::bpf::types::{lw_sigal_header, lw_signal_task};
#[test]
fn test_file_open() {
    let mut open_object = MaybeUninit::uninit();
    let skel = load_bpf(&mut open_object).unwrap();

    let (sender, mut receiver) = blob_channel_groups();

    let mut rbb = RingBufferBuilder::new();
    let mut exit = Rc::new(RefCell::new(false));
    let exit1 = exit.clone();

    rbb.add(&skel.maps._blob_ringbuf_,   move |data| -> i32 {
        // let data = lw_blob_with_data::copy_from_bytes(data);
        // sender.send(data);
        return 0;
    }).unwrap();

    rbb.add(&skel.maps._signal_ringbuf_,   move |data| -> i32 {
        print!("here!!");
        let header:lw_sigal_header = copy_from_bytes(data);
        if header.signal_type == types::lw_signal_type_LW_SIGNAL_TASK as u8 {
            let task:lw_signal_task = copy_from_bytes(data);
            unsafe {
                print!("-->task pid: {0} pid_vir {1}  filename: {2} interp: {3}\n", task.body.pid.pid, task.body.pid.pid_vnr, String::from_utf8_lossy(task.body.exec.filename.str_.as_slice()), String::from_utf8_lossy(task.body.exec.interp.str_.as_slice()));
            }
        }
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
    let builder = sched_process_exec::ProbeSkelBuilder::default();

    let mut open_skel = builder.open(open_object)?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    Ok(skel)
}