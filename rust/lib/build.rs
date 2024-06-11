use libbpf_cargo::SkeletonBuilder;

fn main() {
    let c_bpf_dir = "../../c/src";
    build_bpf(c_bpf_dir);
}

fn build_bpf(c_bpf_dir: &str) {
    let include = format!("-I{c_bpf_dir}");
    let args = vec![
      "-D__TARGET_ARCH_x86",
      "-D__BPF_TRACING__",
      "-DCORE",
      "-I/usr/include/bpf",
      include.as_str(),
    ];
    let source = format!("{0}/file_open/probe.bpf.c", c_bpf_dir);
    let target = "src/bpf/file_open.rs";

    let mut builder = SkeletonBuilder::new();
    builder
        .clang_args(args)
        .source(source)
        .build_and_generate(target)
        .expect("cannot build bpf");
}
