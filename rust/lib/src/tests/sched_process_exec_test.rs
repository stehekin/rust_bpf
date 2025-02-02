use super::resources::scripts;
use super::utils::{random_prefix, run_script_with_name};

use crate::bpf::blob::{blob_id_to_seq, spawn_blob_mergers, MergedBlob};
use crate::bpf::bpf_loader::{load_sched_process_exec, setup_ringbufs};
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
use serial_test::serial;
use std::cell::RefCell;
use std::ffi::OsStr;
use std::mem::MaybeUninit;
use std::rc::Rc;
use std::time::Duration;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio::task::JoinHandle;

const REGULAR_SUFFIX: &str = ".lw_regular";
const UNSHARE_SUFFIX: &str = ".lw_unshare";
const EXIT_SUFFIX: &str = ".lw_exit";

const SIGNAL_RINGBUF_PATH: &str = "/sys/fs/bpf/lw_signal_ringbuf_test";
const BLOB_RINGBUF_PATH: &str = "/sys/fs/bpf/lw_blob_ringbuf_test";

fn has_suffix(name: &[u8], suffix: &[u8]) -> bool {
    if let Some(position) = name.windows(suffix.len()).position(|win| win == suffix) {
        return position + suffix.len() == name.len() || name[position + suffix.len()] == 0;
    }
    false
}

fn run_scripts(scripts: Vec<(String, String, &'static str)>) -> JoinHandle<()> {
    tokio::spawn(async move {
        for s in scripts {
            run_script_with_name(s.0.as_str(), s.1.as_str(), s.2)
                .await
                .expect("error running script");
        }
    })
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_process_regular() {
    let signal_ringbuf_path = OsStr::new(SIGNAL_RINGBUF_PATH);
    let blob_ringbuf_path = OsStr::new(BLOB_RINGBUF_PATH);

    let mut open_object = MaybeUninit::uninit();
    let mut signal_receivers =
        setup_ringbufs(&mut open_object, signal_ringbuf_path, blob_ringbuf_path)
            .expect("error setting up ringbufs");

    let mut spe_open_object = MaybeUninit::uninit();
    let spe_skel =
        load_sched_process_exec(&mut spe_open_object, signal_ringbuf_path, blob_ringbuf_path)
            .expect("error loading probe sched_process_exec");

    let test_result = tokio::spawn(async move {
        let mut result = false;
        loop {
            if let Some(task) = signal_receivers.task_receiver.recv().await {
                unsafe {
                    if has_suffix(&task.body.exec.filename.str_[..], REGULAR_SUFFIX.as_bytes()) {
                        result = true;
                    }
                    if has_suffix(&task.body.exec.filename.str_[..], EXIT_SUFFIX.as_bytes()) {
                        return result;
                    }
                }
            }
        }
    });

    run_scripts(vec![
        ("regular".into(), REGULAR_SUFFIX.into(), scripts::SCRIPT),
        ("exit".into(), EXIT_SUFFIX.into(), scripts::SCRIPT),
    ]);

    // exiting the test.
    let test_result = test_result.await.expect("error awaiting test result");
    drop(spe_skel);
    signal_receivers
        .exit_sender
        .send(0)
        .expect("error stopping ringbuf polling");
    std::fs::remove_file(SIGNAL_RINGBUF_PATH).expect("error deleting signal ringbuf map");
    std::fs::remove_file(BLOB_RINGBUF_PATH).expect("error deleting blob ringbuf map");
    assert!(test_result);
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_process_child_namespaces() {
    let signal_ringbuf_path = OsStr::new(SIGNAL_RINGBUF_PATH);
    let blob_ringbuf_path = OsStr::new(BLOB_RINGBUF_PATH);

    let mut open_object = MaybeUninit::uninit();
    let mut signal_receivers =
        setup_ringbufs(&mut open_object, signal_ringbuf_path, blob_ringbuf_path)
            .expect("error setting up ringbufs");

    let mut spe_open_object = MaybeUninit::uninit();
    let spe_skel =
        load_sched_process_exec(&mut spe_open_object, signal_ringbuf_path, blob_ringbuf_path)
            .expect("error loading probe sched_process_exec");

    let test_result = tokio::spawn(async move {
        let mut parent = 0;
        let mut grand_parent = 0;
        let mut result = true;
        loop {
            if let Some(task) = signal_receivers.task_receiver.recv().await {
                unsafe {
                    let filename = task.body.exec.filename.str_;

                    if has_suffix(filename.as_slice(), UNSHARE_SUFFIX.as_bytes()) {
                        grand_parent = task.body.pid.pid;
                    } else if has_suffix(filename.as_slice(), "unshare".as_bytes()) {
                        parent = task.body.pid.pid;
                        result = result && task.body.parent.pid == grand_parent;
                    }

                    if task.body.pid.pid_vnr == 1 {
                        result = result && task.body.parent.pid == parent;
                        result = result && has_suffix(filename.as_slice(), "date".as_bytes());
                    }

                    if has_suffix(filename.as_slice(), EXIT_SUFFIX.as_bytes()) {
                        return result;
                    }
                }
            }
        }
    });

    run_scripts(vec![
        ("date".into(), UNSHARE_SUFFIX.into(), scripts::UNSHARE),
        ("exit".into(), EXIT_SUFFIX.into(), scripts::SCRIPT),
    ]);

    // exiting the test.
    let test_result = test_result.await.expect("error awaiting test result");
    drop(spe_skel);
    signal_receivers
        .exit_sender
        .send(0)
        .expect("error stopping ringbuf polling");
    std::fs::remove_file(SIGNAL_RINGBUF_PATH).expect("error deleting signal ringbuf map");
    std::fs::remove_file(BLOB_RINGBUF_PATH).expect("error deleting blob ringbuf map");
    assert!(test_result);
}

/*
#[tokio::test(flavor = "multi_thread")]
async fn test_process_long_filename() {
    let (sender, receiver) = unbounded_channel::<bool>();

    let mut srs = spawn_blob_mergers();
    spawn_merged_blob_receivers(srs.merged_blob_receivers.take().unwrap());

    let mut open_object = MaybeUninit::uninit();
    let skel = setup_bpf(&mut open_object).expect("error loading sched_process_exec bpf");

    let mut rbb = RingBufferBuilder::new();

    let blob_senders = srs.blob_senders.clone();
    rbb.add(&skel.maps.blob_ringbuf, move |data| -> i32 {
        let data = copy_from_bytes::<types::lw_blob>(data);
        let (cpu_id, _) = blob_id_to_seq(data.header.blob_id);
        blob_senders
            .get(cpu_id)
            .unwrap()
            .send(data)
            .expect("error sending blob");
        0
    })
    .expect("error adding blob ringbuf handler");

    let blob_id_senders = srs.blob_id_senders.clone();
    rbb.add(&skel.maps.signal_ringbuf, move |data| -> i32 {
        let header = copy_from_bytes::<lw_signal_header>(data);
        if header.signal_type != types::lw_signal_type_LW_SIGNAL_TASK as u8 {
            return 0;
        }

        let task = copy_from_bytes::<lw_signal_task>(data);
        unsafe {
            let filename = task.body.exec.filename;
            if filename.blob.flag == 0 {
                let blob_id = filename.blob.blob_id;
                let (cpu_id, _) = blob_id_to_seq(blob_id);
                blob_id_senders
                    .get(cpu_id)
                    .unwrap()
                    .send(blob_id)
                    .expect("error sending blob id");
            } else if has_suffix(filename.str_.as_slice(), EXIT_SUFFIX.as_bytes()) {
                sender.send(true).expect("");
            }
        }
        return 0;
    })
    .expect("error adding signal ringbuf handler");

    let filename = random_prefix(128);
    run_scripts(vec![
        (filename, REGULAR_SUFFIX.into(), scripts::SCRIPT),
        ("exit".into(), EXIT_SUFFIX.into(), scripts::SCRIPT),
    ]);

    let rb = rbb.build().expect("error build ringbuff");
    polling_ringbuffer(rb, receiver).await.expect("");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_process_args() {
    let (sender, receiver) = unbounded_channel::<bool>();

    let mut srs = spawn_blob_mergers();
    spawn_merged_blob_receivers(srs.merged_blob_receivers.take().unwrap());

    let mut open_object = MaybeUninit::uninit();
    let skel = setup_bpf(&mut open_object).expect("error loading sched_process_exec bpf");

    let mut rbb = RingBufferBuilder::new();

    let blob_senders = srs.blob_senders.clone();
    rbb.add(&skel.maps.blob_ringbuf, move |data| -> i32 {
        let data = copy_from_bytes::<types::lw_blob>(data);
        let (cpu_id, _) = blob_id_to_seq(data.header.blob_id);
        blob_senders
            .get(cpu_id)
            .unwrap()
            .send(data)
            .expect("error sending blob");
        0
    })
    .expect("error adding blob ringbuf handler");

    let blob_id_senders = srs.blob_id_senders.clone();
    rbb.add(&skel.maps.signal_ringbuf, move |data| -> i32 {
        let header = copy_from_bytes::<lw_signal_header>(data);
        if header.signal_type != types::lw_signal_type_LW_SIGNAL_TASK as u8 {
            return 0;
        }

        let task = copy_from_bytes::<lw_signal_task>(data);
        let blob_id = task.body.exec.args;
        if blob_id != 0 {
            let (cpu_id, _) = blob_id_to_seq(blob_id);
            blob_id_senders
                .get(cpu_id)
                .unwrap()
                .send(blob_id)
                .expect("error sending blob id");
        }

        unsafe {
            let filename = task.body.exec.filename;
            if has_suffix(filename.str_.as_slice(), EXIT_SUFFIX.as_bytes()) {
                sender.send(true).expect("");
            }
        }
        return 0;
    })
    .expect("error adding signal ringbuf handler");

    run_scripts(vec![
        ("args".into(), REGULAR_SUFFIX.into(), scripts::SCRIPT),
        ("exit".into(), EXIT_SUFFIX.into(), scripts::SCRIPT),
    ]);

    let rb = rbb.build().expect("error build ringbuff");
    polling_ringbuffer(rb, receiver).await.expect("");
}
*/
