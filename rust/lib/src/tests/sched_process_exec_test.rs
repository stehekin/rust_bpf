/*
use anyhow::Result;
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    RingBufferBuilder,
};
use std::cell::RefCell;
use std::mem::MaybeUninit;
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::bpf::blob::blob_channel_groups;
use crate::bpf::sched_process_exec;
use crate::bpf::sched_process_exec::ProbeSkel;
use crate::bpf::types;
use crate::bpf::types::{lw_blob, lw_sigal_header, lw_signal_task};
use crate::bpf::types_conv::copy_from_bytes;

// Tests in this file can only be run sequentially.
// Run it using `cargo test -- --nocapture --test-threads=1`.
fn has_suffix(name: &[u8], suffix: &[u8]) -> bool {
    if let Some(position) = name
        .windows(suffix.len())
        .position(|window| window == suffix)
    {
        position + suffix.len() == name.len() || name[position + suffix.len()] == 0
    } else {
        false
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_process_regular() {
    let mut open_object = MaybeUninit::uninit();
    let skel = load_bpf(&mut open_object).unwrap();
    let mut rbb = RingBufferBuilder::new();
    let exit = Rc::new(RefCell::new(false));
    let exit1 = exit.clone();

    rbb.add(&skel.maps.signal_ringbuf, move |data| -> i32 {
        let header: lw_sigal_header = copy_from_bytes(data);
        if header.signal_type == types::lw_signal_type_LW_SIGNAL_TASK as u8 {
            let task: lw_signal_task = copy_from_bytes(data);
            unsafe {
                assert_ne!(task.body.pid.pid, 0);
                assert_ne!(task.body.pid.pid_ns, 0);

                if has_suffix(
                    task.body.exec.filename.str_.as_slice(),
                    ".lw_regular".as_bytes(),
                ) {
                    assert!(has_suffix(
                        task.body.exec.interp.str_.as_slice(),
                        "/bin/sh".as_bytes()
                    ));
                    assert_ne!(task.body.pid.pid, 1);
                    assert_eq!(
                        task.body.pid.pid, task.body.pid.pid_vnr,
                        "{0} != {1}",
                        task.body.pid.pid, task.body.pid.pid_vnr
                    );
                    assert_ne!(task.body.exec.filename.blob.flag, 0);
                }

                if !*exit1.borrow() {
                    *exit1.borrow_mut() = has_suffix(
                        task.body.exec.filename.str_.as_slice(),
                        ".lw_exit".as_bytes(),
                    );
                }
            }
        }
        return 0;
    })
    .unwrap();

    let run_processes = tokio::spawn(async move {
        super::utils::run_script_with_name(
            "regular",
            ".lw_regular",
            super::resources::scripts::SCRIPT,
        )
        .await
        .expect("error running regular");
        super::utils::run_script_with_name("exit", ".lw_exit", super::resources::scripts::SCRIPT)
            .await
            .expect("error running exit script");
    });

    let rb = rbb.build().unwrap();
    let now = Instant::now();
    let deadline = Duration::from_secs(15);
    loop {
        rb.poll(Duration::from_secs(1))
            .expect("ringbuffer polling error");
        if *exit.borrow() || now.elapsed().ge(&deadline) {
            break;
        }
    }

    run_processes.await.expect("error running processes")
}

#[tokio::test(flavor = "multi_thread")]
async fn test_process_long_filename() {
    let mut open_object = MaybeUninit::uninit();
    let skel = load_bpf(&mut open_object).unwrap();
    let (sender, mut receiver) = blob_channel_groups();
    let mut rbb = RingBufferBuilder::new();
    let exit = Rc::new(RefCell::new(false));
    let exit1 = exit.clone();

    rbb.add(&skel.maps.blob_ringbuf, move |data| -> i32 {
        let data = lw_blob::copy_from_bytes(data);
        let _ = sender.send_blocking(data);
        0
    })
    .unwrap();

    let (blob_id_sender, blob_id_reciever) = async_channel::unbounded();

    rbb.add(&skel.maps.signal_ringbuf, move |data| -> i32 {
        let header: lw_sigal_header = copy_from_bytes(data);
        if header.signal_type == types::lw_signal_type_LW_SIGNAL_TASK as u8 {
            let task: lw_signal_task = copy_from_bytes(data);
            unsafe {
                assert_ne!(task.body.pid.pid, 0);
                assert_ne!(task.body.pid.pid_ns, 0);

                if task.body.exec.filename.blob.flag == 0 {
                    assert!(has_suffix(
                        task.body.exec.interp.str_.as_slice(),
                        "/bin/sh".as_bytes()
                    ));
                    assert_ne!(task.body.pid.pid, 1);
                    assert_eq!(
                        task.body.pid.pid, task.body.pid.pid_vnr,
                        "{0} != {1}",
                        task.body.pid.pid, task.body.pid.pid_vnr
                    );
                    assert_eq!(
                        task.body.exec.filename.blob.flag, 0,
                        "{0} != 0",
                        task.body.exec.filename.blob.flag
                    );
                    blob_id_sender
                        .send_blocking(task.body.exec.filename.blob.blob_id)
                        .expect("error sending blob_id");
                }

                if !*exit1.borrow() {
                    *exit1.borrow_mut() = has_suffix(
                        task.body.exec.filename.str_.as_slice(),
                        ".lw_exit".as_bytes(),
                    );
                }
            }
        }
        0
    })
    .unwrap();

    let merge_task = tokio::spawn(async move {
        let mut buffer = vec![];
        let blob_id = blob_id_reciever
            .recv()
            .await
            .expect("error receiving blob_id");
        print!("<<{0}>>", blob_id);
        receiver
            .merge_blobs(blob_id, &mut buffer)
            .await
            .expect("error merging blobs");
        print!("{0}\n", String::from_utf8_lossy(buffer.as_slice()));
        assert!(has_suffix(
            String::from_utf8_lossy(buffer.as_slice()).as_bytes(),
            ".lw_longname_128".as_bytes()
        ));
    });

    let run_processes = tokio::spawn(async move {
        super::utils::run_script(128, ".lw_longname_128", super::resources::scripts::SCRIPT)
            .await
            .expect("error running long named script");
        super::utils::run_script_with_name("exit", ".lw_exit", super::resources::scripts::SCRIPT)
            .await
            .expect("error running exit script");
    });

    let rb = rbb.build().unwrap();
    let now = Instant::now();
    let deadline = Duration::from_secs(15);
    loop {
        rb.poll(Duration::from_secs(1))
            .expect("ringbuffer polling error");
        if *exit.borrow() || now.elapsed().ge(&deadline) {
            break;
        }
    }

    run_processes.await.expect("error running processes");
    merge_task.await.expect("error merging blobs");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_process_unshare() {
    let mut open_object = MaybeUninit::uninit();
    let skel = load_bpf(&mut open_object).unwrap();
    let mut rbb = RingBufferBuilder::new();
    let exit = Rc::new(RefCell::new(false));
    let exit1 = exit.clone();

    let grand_parent: Rc<RefCell<u32>> = Rc::new(RefCell::new(0));
    let parent: Rc<RefCell<u32>> = Rc::new(RefCell::new(0));

    rbb.add(&skel.maps.signal_ringbuf, move |data| -> i32 {
        let header: lw_sigal_header = copy_from_bytes(data);
        if header.signal_type == types::lw_signal_type_LW_SIGNAL_TASK as u8 {
            let task: lw_signal_task = copy_from_bytes(data);
            unsafe {
                assert_ne!(task.body.pid.pid, 0);
                assert_ne!(task.body.pid.pid_ns, 0);

                if has_suffix(
                    task.body.exec.filename.str_.as_slice(),
                    ".lw_unshare".as_bytes(),
                ) {
                    assert!(has_suffix(
                        task.body.exec.interp.str_.as_slice(),
                        "/bin/sh".as_bytes()
                    ));
                    *grand_parent.borrow_mut() = task.body.pid.pid;
                } else if has_suffix(
                    task.body.exec.filename.str_.as_slice(),
                    "unshare".as_bytes(),
                ) {
                    *parent.borrow_mut() = task.body.pid.pid;
                    assert_eq!(task.body.parent.pid, *grand_parent.borrow());
                }

                if task.body.pid.pid_vnr == 1 {
                    assert_eq!(task.body.parent.pid, *parent.borrow());
                    assert!(has_suffix(
                        task.body.exec.filename.str_.as_slice(),
                        "date".as_bytes()
                    ))
                }

                if !*exit1.borrow() {
                    *exit1.borrow_mut() = has_suffix(
                        task.body.exec.filename.str_.as_slice(),
                        ".lw_exit".as_bytes(),
                    );
                }
            }
        }
        return 0;
    })
    .unwrap();

    let run_processes = tokio::spawn(async move {
        super::utils::run_script_with_name(
            "regular",
            ".lw_unshare",
            super::resources::scripts::UNSHARE,
        )
        .await
        .expect("error running unshare");
        super::utils::run_script_with_name("exit", ".lw_exit", super::resources::scripts::SCRIPT)
            .await
            .expect("error running exit script");
    });

    let rb = rbb.build().unwrap();
    let now = Instant::now();
    let deadline = Duration::from_secs(15);
    loop {
        rb.poll(Duration::from_secs(1))
            .expect("ringbuffer polling error");
        if *exit.borrow() || now.elapsed().ge(&deadline) {
            break;
        }
    }

    run_processes.await.expect("error running processes")
}

#[tokio::test(flavor = "multi_thread")]
async fn test_process_args() {
    let mut open_object = MaybeUninit::uninit();
    let skel = load_bpf(&mut open_object).unwrap();
    let (sender, mut receiver) = blob_channel_groups();
    let mut rbb = RingBufferBuilder::new();
    let exit = Rc::new(RefCell::new(false));
    let exit1 = exit.clone();

    rbb.add(&skel.maps.blob_ringbuf, move |data| -> i32 {
        let data = lw_blob::copy_from_bytes(data);
        let _ = sender.send_blocking(data);
        0
    })
    .unwrap();

    let (blob_id_sender, blob_id_receiver) = async_channel::unbounded();

    rbb.add(&skel.maps.signal_ringbuf, move |data| -> i32 {
        let header: lw_sigal_header = copy_from_bytes(data);
        if header.signal_type == types::lw_signal_type_LW_SIGNAL_TASK as u8 {
            let task: lw_signal_task = copy_from_bytes(data);
            unsafe {
                assert_ne!(task.body.pid.pid, 0);
                assert_ne!(task.body.pid.pid_ns, 0);

                if has_suffix(
                    task.body.exec.filename.str_.as_slice(),
                    ".lw_regular".as_bytes(),
                ) {
                    blob_id_sender
                        .send_blocking(task.body.exec.env)
                        .expect("error sending args blob_id");
                }
                if !*exit1.borrow() {
                    *exit1.borrow_mut() = has_suffix(
                        task.body.exec.filename.str_.as_slice(),
                        ".lw_exit".as_bytes(),
                    )
                }
            }
        }
        0
    })
    .unwrap();

    let merge_task = tokio::spawn(async move {
        let mut buffer = vec![];
        let blob_id = blob_id_receiver
            .recv()
            .await
            .expect("error receiving blob_id");
        receiver
            .merge_blobs(blob_id, &mut buffer)
            .await
            .expect("error merging blobs");
        // unsafe {
        //     print!(">>> {0} <<< \n", String::from_utf8_unchecked(buffer));
        // }
    });

    let run_processes = tokio::spawn(async move {
        super::utils::run_script_with_name(
            "regular",
            ".lw_regular",
            super::resources::scripts::SCRIPT,
        )
        .await
        .expect("error running regular");
        super::utils::run_script_with_name("exit", ".lw_exit", super::resources::scripts::SCRIPT)
            .await
            .expect("error running exit script");
    });

    let rb = rbb.build().unwrap();
    let now = Instant::now();
    let deadline = Duration::from_secs(5);
    loop {
        rb.poll(Duration::from_secs(1))
            .expect("ringbuffer polling error");
        if *exit.borrow() || now.elapsed().ge(&deadline) {
            break;
        }
    }

    run_processes.await.expect("error running processes");
    merge_task.await.expect("error merging blobs");
}

fn load_bpf(open_object: &mut MaybeUninit<libbpf_rs::OpenObject>) -> Result<ProbeSkel> {
    let builder = sched_process_exec::ProbeSkelBuilder::default();

    let open_skel = builder.open(open_object)?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    Ok(skel)
}
*/
