/* automatically generated by rust-bindgen 0.69.4 */

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct fo_inode {
    pub s_dev: u64,
    pub i_ino: u64,
}
#[test]
fn bindgen_test_layout_fo_inode() {
    const UNINIT: ::std::mem::MaybeUninit<fo_inode> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<fo_inode>(),
        16usize,
        concat!("Size of: ", stringify!(fo_inode))
    );
    assert_eq!(
        ::std::mem::align_of::<fo_inode>(),
        8usize,
        concat!("Alignment of ", stringify!(fo_inode))
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).s_dev) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(fo_inode),
            "::",
            stringify!(s_dev)
        )
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).i_ino) as usize - ptr as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(fo_inode),
            "::",
            stringify!(i_ino)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct fo_monitor_name {
    pub path: [u8; 256usize],
    pub path_meta: [u8; 32usize],
    pub padding: [u8; 32usize],
}
#[test]
fn bindgen_test_layout_fo_monitor_name() {
    const UNINIT: ::std::mem::MaybeUninit<fo_monitor_name> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<fo_monitor_name>(),
        320usize,
        concat!("Size of: ", stringify!(fo_monitor_name))
    );
    assert_eq!(
        ::std::mem::align_of::<fo_monitor_name>(),
        1usize,
        concat!("Alignment of ", stringify!(fo_monitor_name))
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).path) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(fo_monitor_name),
            "::",
            stringify!(path)
        )
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).path_meta) as usize - ptr as usize },
        256usize,
        concat!(
            "Offset of field: ",
            stringify!(fo_monitor_name),
            "::",
            stringify!(path_meta)
        )
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).padding) as usize - ptr as usize },
        288usize,
        concat!(
            "Offset of field: ",
            stringify!(fo_monitor_name),
            "::",
            stringify!(padding)
        )
    );
}
