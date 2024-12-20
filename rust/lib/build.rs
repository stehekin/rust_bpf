use libbpf_cargo::SkeletonBuilder;

fn main() {
    let c_bpf_dir = "../../c/src";
    build_bpf(c_bpf_dir);
    bindgen();
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

    let bpfs = vec![
        "sched_process_exec",
    ];

    for bpf in bpfs {
        let source = format!("{0}/{1}/probe.bpf.c", c_bpf_dir, bpf);
        let target = format!("src/bpf/{0}.rs", bpf);

        let mut builder = SkeletonBuilder::new();
        builder
            .clang_args(args.clone())
            .source(source)
            .build_and_generate(target)
            .expect("cannot build bpf");
    }
}

fn bindgen() {
    let types = "../../c/src/common/types.h";
    let bindings = bindgen::Builder::default()
        .header(types)
        .derive_debug(true)
        .derive_default(true)
        .raw_line("#![allow(non_camel_case_types)]")
        .raw_line("#![allow(non_upper_case_globals)]")
        .raw_line("#![allow(non_snake_case)]")
        .raw_line("#![allow(dead_code)]")
        .allowlist_file(types)
        .generate()
        .expect("unable to generate bindings");
    bindings.write_to_file("src/bpf/types.rs").expect("bindgen failure")
}
