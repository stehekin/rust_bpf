use crate::bpf::blob::{blob_id_to_seq, spawn_blob_mergers, MergedBlob};
use crate::bpf::cgroup;
use crate::bpf::dummy;
use crate::bpf::sched_process_exec;
use crate::bpf::types;
use crate::bpf::types::{lw_signal_header, lw_signal_task};
use crate::bpf::types_conv::copy_from_bytes;

use anyhow::{bail, Result};
use libbpf_rs::AsRawLibbpf;
use libbpf_rs::Link;
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    Iter, RingBufferBuilder,
};
use libbpf_sys::{bpf_iter_attach_opts, bpf_iter_link_info, BPF_CGROUP_ITER_ANCESTORS_UP};

use std::mem;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::BorrowedFd;
use std::ptr::NonNull;
use std::time::Duration;
use std::{ffi::OsStr, mem::MaybeUninit};
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    oneshot,
};

pub(crate) struct SignalContext {
    pub merged_blob_receivers: Vec<UnboundedReceiver<MergedBlob>>,
    pub task_receiver: UnboundedReceiver<lw_signal_task>,
}

fn lw_task_handler(
    task: lw_signal_task,
    blob_id_senders: &Vec<UnboundedSender<u64>>,
    task_sender: &UnboundedSender<lw_signal_task>,
) -> i32 {
    let filename = task.body.exec.filename;
    let mut blob_ids = vec![];

    unsafe {
        if filename.blob.flag == 0 {
            blob_ids.push(filename.blob.blob_id);
        }
    }

    if task.body.exec.args != 0 {
        blob_ids.push(task.body.exec.args);
    }

    if task.body.exec.env != 0 {
        blob_ids.push(task.body.exec.env);
    }

    blob_ids.sort();

    for blob_id in blob_ids {
        if blob_id == 0 {
            continue;
        }
        let (cpu_id, _) = blob_id_to_seq(blob_id);
        match blob_id_senders.get(cpu_id).unwrap().send(blob_id) {
            Err(_) => {
                return -1;
            }
            _ => {}
        }
    }

    match task_sender.send(task) {
        Err(_) => -1,
        _ => 0,
    }
}

fn context_exit_fn(exit_sender: oneshot::Sender<bool>) -> impl FnOnce() -> Result<()> {
    move || {
        exit_sender
            .send(true)
            .map_err(|_| anyhow::Error::msg("error closing ringbuf context"))
    }
}

pub(crate) fn setup_ringbufs(
    open_object: &mut MaybeUninit<libbpf_rs::OpenObject>,
    signal_ringbuf_path: &OsStr,
    blob_ringbuf_path: &OsStr,
) -> Result<(SignalContext, impl FnOnce() -> Result<()>)> {
    let builder = dummy::ProbeSkelBuilder::default();
    let open_skel = builder.open(open_object)?;
    let mut skel = open_skel.load()?;
    skel.maps.signal_ringbuf.pin(signal_ringbuf_path)?;
    skel.maps.blob_ringbuf.pin(blob_ringbuf_path)?;

    let mut srs = spawn_blob_mergers();

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
    })?;

    let blob_id_senders = srs.blob_id_senders.clone();
    let (task_sender, task_receiver) = unbounded_channel();
    rbb.add(&skel.maps.signal_ringbuf, move |data| -> i32 {
        let header = copy_from_bytes::<lw_signal_header>(data);
        match header.signal_type as u32 {
            types::lw_signal_type_LW_SIGNAL_TASK => {
                let task = copy_from_bytes::<lw_signal_task>(data);
                return lw_task_handler(task, &blob_id_senders, &task_sender);
            }
            _ => {}
        }
        return 0;
    })?;

    let rb = rbb.build()?;
    let (exit_sender, mut exit_receive) = oneshot::channel::<bool>();
    tokio::spawn(async move {
        loop {
            match rb.poll(Duration::from_secs(1)) {
                Err(_) => {
                    break;
                }
                _ => {}
            }

            if let Ok(v) = exit_receive.try_recv() {
                break;
            }
        }
    });

    Ok((
        SignalContext {
            merged_blob_receivers: srs.merged_blob_receivers.unwrap(),
            task_receiver,
        },
        context_exit_fn(exit_sender),
    ))
}

pub(crate) fn load_sched_process_exec<'a>(
    open_object: &'a mut MaybeUninit<libbpf_rs::OpenObject>,
    signal_ringbuf_path: &OsStr,
    blob_ringbuf_path: &OsStr,
) -> Result<sched_process_exec::ProbeSkel<'a>> {
    let builder = sched_process_exec::ProbeSkelBuilder::default();
    let mut open_skel = builder.open(open_object)?;

    open_skel
        .maps
        .signal_ringbuf
        .reuse_pinned_map(signal_ringbuf_path)?;
    open_skel
        .maps
        .blob_ringbuf
        .reuse_pinned_map(blob_ringbuf_path)?;

    let mut skel = open_skel.load()?;
    skel.attach()?;

    Ok(skel)
}

/// Check the returned pointer of a `libbpf` call, extracting any
/// reported errors and converting them.
fn validate_bpf_ret<T>(ptr: *mut T) -> Result<NonNull<T>> {
    // SAFETY: `libbpf_get_error` is always safe to call.
    match unsafe { libbpf_sys::libbpf_get_error(ptr as *const _) } {
        0 => {
            debug_assert!(!ptr.is_null());
            // SAFETY: libbpf guarantees that if NULL is returned an
            //         error it set, so we will always end up with a
            //         valid pointer when `libbpf_get_error` returned 0.
            let ptr = unsafe { NonNull::new_unchecked(ptr) };
            Ok(ptr)
        }
        err => Err(anyhow::Error::new(std::io::Error::from_raw_os_error(
            -err as i32,
        ))),
    }
}

// https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/prog_tests/cgroup_hierarchical_stats.c
fn attach_iter_cgroup(
    prog: &libbpf_rs::Program,
    cgroup_fd: BorrowedFd<'_>,
    order: u32,
) -> Result<Link> {
    let mut linkinfo = libbpf_sys::bpf_iter_link_info::default();
    // linkinfo.cgroup.cgroup_fd = cgroup_fd.as_raw_fd() as _;
    //
    linkinfo.cgroup.cgroup_id = 4833;
    linkinfo.cgroup.order = order;

    let attach_opt = libbpf_sys::bpf_iter_attach_opts {
        link_info: &mut linkinfo as *mut libbpf_sys::bpf_iter_link_info,
        link_info_len: size_of::<libbpf_sys::bpf_iter_link_info>() as _,
        sz: size_of::<libbpf_sys::bpf_iter_attach_opts>() as _,
        ..Default::default()
    };

    let ptr = unsafe {
        libbpf_sys::bpf_program__attach_iter(
            prog.as_libbpf_object().as_ptr(),
            &attach_opt as *const libbpf_sys::bpf_iter_attach_opts,
        )
    };

    let ptr = validate_bpf_ret(ptr).expect("failed to attach iterator");
    // SAFETY: the pointer came from libbpf and has been checked for errors.
    let link = unsafe { libbpf_rs::Link::from_ptr(ptr) };
    Ok(link)
}

pub(crate) fn load_cgroup_iter<'a>(
    open_object: &'a mut MaybeUninit<libbpf_rs::OpenObject>,
    fd: BorrowedFd<'_>,
) -> Result<Iter> {
    let builder = cgroup::ProbeSkelBuilder::default();
    let open_skel = builder.open(open_object)?;
    let skel = open_skel.load()?;

    let mut link = attach_iter_cgroup(&skel.progs.cgroup_iter, fd, BPF_CGROUP_ITER_ANCESTORS_UP)?;
    // link.pin("/sys/fs/bpf/cgroup_iter")?;
    let iter = Iter::new(&link)?;
    Ok(iter)
}
