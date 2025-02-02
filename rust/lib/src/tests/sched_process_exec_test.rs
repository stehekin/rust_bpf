use super::resources::scripts;
use super::utils::{random_prefix, run_script_with_name};

use crate::bpf::blob::{blob_id_to_seq, MergedBlob};
use crate::bpf::bpf_loader::{load_sched_process_exec, setup_ringbufs};

use serial_test::serial;
use std::ffi::OsStr;
use std::mem::MaybeUninit;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::task::JoinHandle;

const REGULAR_SUFFIX: &str = ".lw_regular";
const UNSHARE_SUFFIX: &str = ".lw_unshare";
const EXIT_SUFFIX: &str = ".lw_exit";
const DATE_SUFFIX: &str = "/usr/bin/date";
const DATE_ARGS: &str = "--date=@1394006400";

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

async fn merged_blob_with_id(
    merged_blob_receiver: &mut UnboundedReceiver<MergedBlob>,
    blob_id: u64,
) -> Vec<u8> {
    loop {
        let mb = merged_blob_receiver
            .recv()
            .await
            .expect("error receiving merged blobs");
        if mb.0 == blob_id {
            return mb.1;
        } else if mb.0 > blob_id {
            panic!("cannot find the expected blob")
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_process_regular() {
    let signal_ringbuf_path = OsStr::new(SIGNAL_RINGBUF_PATH);
    let blob_ringbuf_path = OsStr::new(BLOB_RINGBUF_PATH);

    let mut open_object = MaybeUninit::uninit();
    let (mut signal_receivers, exit_fn) =
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
                    let filename = task.body.exec.filename.str_;

                    if has_suffix(&filename[..], REGULAR_SUFFIX.as_bytes()) {
                        result = true;
                    }
                    if has_suffix(&filename[..], EXIT_SUFFIX.as_bytes()) {
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
    exit_fn().expect("");
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
    let (mut signal_receivers, exit_fn) =
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
    exit_fn().expect("");
    std::fs::remove_file(SIGNAL_RINGBUF_PATH).expect("error deleting signal ringbuf map");
    std::fs::remove_file(BLOB_RINGBUF_PATH).expect("error deleting blob ringbuf map");
    assert!(test_result);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_process_long_filename() {
    let signal_ringbuf_path = OsStr::new(SIGNAL_RINGBUF_PATH);
    let blob_ringbuf_path = OsStr::new(BLOB_RINGBUF_PATH);

    let mut open_object = MaybeUninit::uninit();
    let (mut signal_receivers, exit_fn) =
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
                    let filename = task.body.exec.filename;
                    if filename.blob.flag == 0 {
                        let blob_id = filename.blob.blob_id;
                        let (cpu_id, _) = blob_id_to_seq(blob_id);
                        let filename = merged_blob_with_id(
                            signal_receivers
                                .merged_blob_receivers
                                .get_mut(cpu_id)
                                .unwrap(),
                            blob_id,
                        )
                        .await;
                        result = has_suffix(filename.as_slice(), REGULAR_SUFFIX.as_bytes());
                    }
                    if has_suffix(&filename.str_[..], EXIT_SUFFIX.as_bytes()) {
                        return result;
                    }
                }
            }
        }
    });

    let filename = random_prefix(128);
    run_scripts(vec![
        (filename, REGULAR_SUFFIX.into(), scripts::SCRIPT),
        ("exit".into(), EXIT_SUFFIX.into(), scripts::SCRIPT),
    ]);

    // exiting the test.
    let test_result = test_result.await.expect("error awaiting test result");
    drop(spe_skel);
    exit_fn().expect("");
    std::fs::remove_file(SIGNAL_RINGBUF_PATH).expect("error deleting signal ringbuf map");
    std::fs::remove_file(BLOB_RINGBUF_PATH).expect("error deleting blob ringbuf map");
    assert!(test_result);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_process_args() {
    let signal_ringbuf_path = OsStr::new(SIGNAL_RINGBUF_PATH);
    let blob_ringbuf_path = OsStr::new(BLOB_RINGBUF_PATH);

    let mut open_object = MaybeUninit::uninit();
    let (mut signal_receivers, exit_fn) =
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
                let filename = task.body.exec.filename;
                unsafe {
                    if has_suffix(&filename.str_[..], DATE_SUFFIX.as_bytes()) {
                        if task.body.exec.env != 0 {
                            let blob_id = task.body.exec.args;
                            let (cpu_id, _) = blob_id_to_seq(blob_id);
                            let args = merged_blob_with_id(
                                signal_receivers
                                    .merged_blob_receivers
                                    .get_mut(cpu_id)
                                    .unwrap(),
                                blob_id,
                            )
                            .await;
                            result = has_suffix(args.as_slice(), DATE_ARGS.as_bytes())
                        }
                    }

                    if has_suffix(&filename.str_[..], EXIT_SUFFIX.as_bytes()) {
                        return result;
                    }
                }
            }
        }
    });

    run_scripts(vec![
        ("date".into(), REGULAR_SUFFIX.into(), scripts::SCRIPT),
        ("exit".into(), EXIT_SUFFIX.into(), scripts::SCRIPT),
    ]);

    // exiting the test.
    let test_result = test_result.await.expect("error awaiting test result");
    drop(spe_skel);
    exit_fn().expect("");
    std::fs::remove_file(SIGNAL_RINGBUF_PATH).expect("error deleting signal ringbuf map");
    std::fs::remove_file(BLOB_RINGBUF_PATH).expect("error deleting blob ringbuf map");
    assert!(test_result);
}
