use super::resources::scripts;
use super::utils::run_script_with_name;

use crate::bpf::sched_process_exec;
use crate::bpf::sched_process_exec::ProbeSkel;
use crate::bpf::types;
use crate::bpf::types::{lw_signal_header, lw_signal_task};
use crate::bpf::types_conv::copy_from_bytes;

use anyhow::Result;
use libbpf_rs::RingBuffer;
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    RingBufferBuilder,
};

use std::mem::MaybeUninit;
use std::time::Duration;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio::task::JoinHandle;

const REGULAR_SUFFIX: &str = ".lw_regular";
const EXIT_SUFFIX: &str = ".lw_exit";

fn setup_bpf(open_object: &mut MaybeUninit<libbpf_rs::OpenObject>) -> Result<ProbeSkel> {
    let builder = sched_process_exec::ProbeSkelBuilder::default();
    let open_skel = builder.open(open_object)?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    Ok(skel)
}

fn has_suffix(name: &[u8], suffix: &[u8]) -> bool {
    if let Some(position) = name.windows(suffix.len()).position(|win| win == suffix) {
        return position + suffix.len() == name.len() || name[position + suffix.len()] == 0;
    }
    false
}

fn run_scripts(scripts: Vec<(&'static str, &'static str, &'static str)>) -> JoinHandle<()> {
    tokio::spawn(async move {
        for s in scripts {
            run_script_with_name(s.0, s.1, s.2)
                .await
                .expect("error running script");
        }
    })
}

fn polling_ringbuffer(
    rb: RingBuffer<'static>,
    mut receiver: UnboundedReceiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            rb.poll(Duration::from_secs(1))
                .expect("error polling ringbuffer");
            match receiver.try_recv() {
                Err(TryRecvError::Empty) => {}
                Err(_) => {
                    panic!("unexpected channel receving error!");
                }
                Ok(_) => {
                    break;
                }
            }
        }
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn test_process_regular() {
    let (sender, receiver) = unbounded_channel::<bool>();

    let mut open_object = MaybeUninit::uninit();
    let skel = setup_bpf(&mut open_object).expect("error loading sched_process_exec bpf");

    let mut rbb = RingBufferBuilder::new();
    rbb.add(&skel.maps.signal_ringbuf, move |data| -> i32 {
        let header = copy_from_bytes::<lw_signal_header>(data);
        if header.signal_type != types::lw_signal_type_LW_SIGNAL_TASK as u8 {
            return 0;
        }

        let task = copy_from_bytes::<lw_signal_task>(data);
        unsafe {
            let filename = task.body.exec.filename.str_;
            if has_suffix(filename.as_slice(), REGULAR_SUFFIX.as_bytes()) {
                assert!(has_suffix(
                    task.body.exec.interp.str_.as_slice(),
                    "/bin/sh".as_bytes()
                ));
            }
            if has_suffix(filename.as_slice(), EXIT_SUFFIX.as_bytes()) {
                sender.send(true).expect("");
            }
        }
        return 0;
    })
    .expect("error adding ringbuf handler");

    run_scripts(vec![
        ("date", REGULAR_SUFFIX, scripts::SCRIPT),
        ("exit", EXIT_SUFFIX, scripts::SCRIPT),
    ]);

    let rb = rbb.build().expect("error build ringbuff");
    polling_ringbuffer(rb, receiver).await.expect("");
}
