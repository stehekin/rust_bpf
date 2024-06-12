use anyhow::Result;
pub fn convert_dev_t(st_dev: u64) -> u64 {
    return ((st_dev & 0xFF00) << 12) | (st_dev & 0x00FF)
}

pub unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::core::slice::from_raw_parts(
        (p as *const T) as *const u8,
        ::core::mem::size_of::<T>(),
    )
}
#[test]
fn test_superbloc_dev_t() {
    assert_eq!(convert_dev_t(65025), 266338305);
}