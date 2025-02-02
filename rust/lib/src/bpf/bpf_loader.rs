use crate::bpf::blob::{blob_id_to_seq, spawn_blob_mergers, MergedBlob};
use crate::bpf::dummy;
use crate::bpf::sched_process_exec;
use crate::bpf::sched_process_exec::ProbeSkel;
use crate::bpf::types;
use crate::bpf::types::{lw_signal_header, lw_signal_task};
use crate::bpf::types_conv::copy_from_bytes;

use anyhow::Result;
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    RingBufferBuilder,
};
use std::time::Duration;
use std::{ffi::OsStr, mem::MaybeUninit};
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    oneshot,
};

pub(crate) struct SignalReceivers {
    pub merged_blob_receivers: Vec<UnboundedReceiver<MergedBlob>>,
    pub task_receiver: UnboundedReceiver<lw_signal_task>,
    pub exit_sender: oneshot::Sender<i8>,
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

pub(crate) fn setup_ringbufs(
    open_object: &mut MaybeUninit<libbpf_rs::OpenObject>,
    signal_ringbuf_path: &OsStr,
    blob_ringbuf_path: &OsStr,
) -> Result<SignalReceivers> {
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
    let (exit_sender, mut exit_receive) = oneshot::channel::<i8>();
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

    Ok(SignalReceivers {
        merged_blob_receivers: srs.merged_blob_receivers.unwrap(),
        task_receiver,
        exit_sender,
    })
}

pub(crate) fn load_sched_process_exec<'a>(
    open_object: &'a mut MaybeUninit<libbpf_rs::OpenObject>,
    signal_ringbuf_path: &OsStr,
    blob_ringbuf_path: &OsStr,
) -> Result<ProbeSkel<'a>> {
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
