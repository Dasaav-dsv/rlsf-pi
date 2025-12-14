use quickcheck_macros::quickcheck;
use std::{mem::MaybeUninit, prelude::v1::*};

use super::*;

#[repr(align(64))]
struct Align<T>(T);

/// Dump the output of `iter_blocks` in a separate module so that it can be
/// filtered separately with `env_logger`
mod blocks_checker {
    use super::*;
    #[cfg(feature = "unstable")]
    use std::ptr::NonNull;

    pub unsafe fn trace_blocks<const FLLEN: usize, const SLLEN: usize>(
        pool_ptr: *mut u8,
        pool_len: Option<usize>,
        tlsf: &Tlsf<'_, impl BinInteger, impl BinInteger, FLLEN, SLLEN>,
    ) {
        #[cfg(feature = "unstable")]
        {
            let pool_len = if let Some(pool_len) = pool_len {
                pool_len
            } else {
                return;
            };
            let pool_ptr = nonnull_slice_from_raw_parts(NonNull::new(pool_ptr).unwrap(), pool_len);

            // Unconditionally enumerate all blocks to see that it doesn't crash
            let blocks: Vec<_> = tlsf.iter_blocks(pool_ptr).collect();

            log::trace!("blocks = {:?}", blocks);
        }

        #[cfg(not(feature = "unstable"))]
        let _ = (pool_ptr, pool_len, tlsf);
    }
}

macro_rules! gen_test {
    ($mod:ident, $($tt:tt)*) => {
        mod $mod {
            use super::*;
            type TheTlsf<'a> = Tlsf<'a, $($tt)*>;

            #[test]
            fn minimal() {
                let _ = env_logger::builder().is_test(true).try_init();

                let mut pool = [MaybeUninit::uninit(); 65536];
                let tlsf: &mut TheTlsf = Tlsf::new_in(&mut pool).unwrap();

                log::trace!("tlsf = {:?}", tlsf);

                let ptr = tlsf.allocate(Layout::from_size_align(1, 1).unwrap());
                log::trace!("ptr = {:?}", ptr);
                if let Some(ptr) = ptr {
                    unsafe { tlsf.deallocate(ptr, 1) };
                }
            }

            #[test]
            fn adaa() {
                let _ = env_logger::builder().is_test(true).try_init();

                let mut pool = [MaybeUninit::uninit(); 65536];
                let tlsf: &mut TheTlsf = Tlsf::new_in(&mut pool).unwrap();

                log::trace!("tlsf = {:?}", tlsf);

                let ptr = tlsf.allocate(Layout::from_size_align(0, 1).unwrap());
                log::trace!("ptr = {:?}", ptr);
                if let Some(ptr) = ptr {
                    unsafe { tlsf.deallocate(ptr, 1) };
                }

                let ptr = tlsf.allocate(Layout::from_size_align(0, 1).unwrap());
                log::trace!("ptr = {:?}", ptr);

                let ptr = tlsf.allocate(Layout::from_size_align(0, 1).unwrap());
                log::trace!("ptr = {:?}", ptr);
            }

            #[test]
            fn aadd() {
                let _ = env_logger::builder().is_test(true).try_init();

                let mut pool = Align([MaybeUninit::uninit(); 65536]);
                let tlsf: &mut TheTlsf = Tlsf::new_in(&mut pool.0).unwrap();

                log::trace!("tlsf = {:?}", tlsf);

                let ptr1 = tlsf.allocate(Layout::from_size_align(0, 1).unwrap());
                log::trace!("ptr1 = {:?}", ptr1);

                let ptr2 = tlsf.allocate(Layout::from_size_align(0, 1).unwrap());
                log::trace!("ptr2 = {:?}", ptr2);

                if let (Some(ptr1), Some(ptr2)) = (ptr1, ptr2) {
                    unsafe { tlsf.deallocate(ptr1, 1) };
                    unsafe { tlsf.deallocate(ptr2, 1) };
                }
            }

            #[test]
            fn ara() {
                let _ = env_logger::builder().is_test(true).try_init();

                let mut pool = Align([MaybeUninit::uninit(); 65536]);
                let tlsf: &mut TheTlsf = Tlsf::new_in(&mut pool.0).unwrap();

                log::trace!("tlsf = {:?}", tlsf);

                let ptr = tlsf.allocate(Layout::from_size_align(17, 1).unwrap());
                log::trace!("ptr = {:?}", ptr);

                if let Some(ptr) = ptr {
                    unsafe { tlsf.reallocate(ptr, Layout::from_size_align(0, 1).unwrap()) };
                    log::trace!("ptr = {:?}", ptr);
                }

                let ptr = tlsf.allocate(Layout::from_size_align(0, 1).unwrap());
                log::trace!("ptr = {:?}", ptr);
            }

            #[test]
            fn max_pool_size() {
                if let Some(mps) = TheTlsf::MAX_POOL_SIZE {
                    // `MAX_POOL_SIZE - super::GRANULARITY` should
                    // be the maximum allowed block size.
                    assert!(TheTlsf::map_floor(mps - super::GRANULARITY).is_some());
                    assert_eq!(TheTlsf::map_floor(mps), None);
                }
            }

            #[quickcheck]
            fn map_ceil_and_unmap(size: usize, shift: u32) -> quickcheck::TestResult {
                let size = size.rotate_left(shift % usize::BITS)
                    .wrapping_mul(super::GRANULARITY);
                if size == 0 {
                    return quickcheck::TestResult::discard();
                }
                let list_min_size = TheTlsf::map_ceil_and_unmap(size);
                log::debug!("map_ceil_and_unmap({}) = {:?}", size, list_min_size);
                if let Some(list_min_size) = list_min_size {
                    assert!(list_min_size >= size);

                    // `list_min_size` must be the lower bound of some list
                    let (fl, sl) = TheTlsf::map_floor(list_min_size).unwrap();
                    log::debug!("map_floor({}) = {:?}", list_min_size, (fl, sl));

                    // Since `list_min_size` is the lower bound of some list,
                    // `map_floor(list_min_size)` and `map_ceil(list_min_size)`
                    // should both return this list
                    assert_eq!(TheTlsf::map_floor(list_min_size), TheTlsf::map_ceil(list_min_size));

                    // `map_ceil_and_unmap(size)` must be the lower bound of the
                    // list returned by `map_ceil(size)`
                    assert_eq!(TheTlsf::map_floor(list_min_size), TheTlsf::map_ceil(size));
                } else {
                    // Find an explanation for `map_ceil_and_unmap` returning
                    // `None`
                    if let Some((fl, _sl)) = TheTlsf::map_ceil(size) {
                        // The lower bound of `(fl, sl)` is not representable
                        // in `usize` - this should be why
                        assert!(fl as u32 + super::GRANULARITY_LOG2 >= usize::BITS);
                    } else {
                        // `map_ceil_and_unmap` is `map_ceil` + infallible
                        // reverse mapping, and the suboperation `map_ceil`
                        // failed
                    }
                }

                quickcheck::TestResult::passed()
            }

            #[quickcheck]
            fn map_ceil_and_unmap_huge(shift: u32) -> quickcheck::TestResult {
                let size = usize::MAX <<
                    (shift % (usize::BITS - super::GRANULARITY_LOG2)
                        + super::GRANULARITY_LOG2);

                if size == 0 || TheTlsf::map_ceil(size).is_some() {
                    return quickcheck::TestResult::discard();
                }

                // If `map_ceil` returns `None`, `map_ceil_and_unmap` must
                // return `None`, too.
                assert_eq!(TheTlsf::map_ceil_and_unmap(size), None);
                quickcheck::TestResult::passed()
            }
        }
    };
}

gen_test!(tlsf_u8_u8_1_1, u8, u8, 1, 1);
gen_test!(tlsf_u8_u8_1_2, u8, u8, 1, 2);
gen_test!(tlsf_u8_u8_1_4, u8, u8, 1, 4);
gen_test!(tlsf_u8_u8_1_8, u8, u8, 1, 8);
gen_test!(tlsf_u8_u8_3_4, u8, u8, 3, 4);
gen_test!(tlsf_u8_u8_5_4, u8, u8, 5, 4);
gen_test!(tlsf_u8_u8_8_1, u8, u8, 8, 1);
gen_test!(tlsf_u8_u8_8_8, u8, u8, 8, 8);
gen_test!(tlsf_u16_u8_3_4, u16, u8, 3, 4);
gen_test!(tlsf_u16_u8_11_4, u16, u8, 11, 4);
gen_test!(tlsf_u16_u8_16_4, u16, u8, 16, 4);
gen_test!(tlsf_u16_u16_3_16, u16, u16, 3, 16);
gen_test!(tlsf_u16_u16_11_16, u16, u16, 11, 16);
gen_test!(tlsf_u16_u16_16_16, u16, u16, 16, 16);
gen_test!(tlsf_u16_u32_3_16, u16, u32, 3, 16);
gen_test!(tlsf_u16_u32_11_16, u16, u32, 11, 16);
gen_test!(tlsf_u16_u32_16_16, u16, u32, 16, 16);
gen_test!(tlsf_u16_u32_3_32, u16, u32, 3, 32);
gen_test!(tlsf_u16_u32_11_32, u16, u32, 11, 32);
gen_test!(tlsf_u16_u32_16_32, u16, u32, 16, 32);
gen_test!(tlsf_u32_u32_20_32, u32, u32, 20, 32);
gen_test!(tlsf_u32_u32_27_32, u32, u32, 27, 32);
gen_test!(tlsf_u32_u32_28_32, u32, u32, 28, 32);
gen_test!(tlsf_u32_u32_29_32, u32, u32, 29, 32);
gen_test!(tlsf_u32_u32_32_32, u32, u32, 32, 32);
gen_test!(tlsf_u64_u8_58_8, u64, u64, 58, 8);
gen_test!(tlsf_u64_u8_59_8, u64, u64, 59, 8);
gen_test!(tlsf_u64_u8_60_8, u64, u64, 60, 8);
gen_test!(tlsf_u64_u8_61_8, u64, u64, 61, 8);
gen_test!(tlsf_u64_u8_64_8, u64, u64, 64, 8);
