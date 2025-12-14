use core::{fmt, hash::Hash, marker::PhantomData, num::NonZeroUsize, ptr::NonNull};

/// Non null pointer encoded as a byte offset inside an allocation to make it
/// position independent.
///
/// Benefits from niche optimization.
#[repr(C)]
pub struct RelPtr<T> {
    inner: NonZeroUsize,
    marker: PhantomData<NonNull<T>>,
}

// Ensure niche optimization:
const _: () = assert!(size_of::<Option<RelPtr<()>>>() == size_of::<usize>());

impl<T> RelPtr<T> {
    /// Create a new [`RelPtr`] from a pair of pointers to and inside an allocation.
    ///
    /// # Safety
    ///
    /// Both pointers must belong to the same allocation. See [`NonNull::byte_offset_from`].
    #[inline]
    pub const unsafe fn new(ptr: NonNull<T>, origin: NonNull<()>) -> Self {
        // SAFETY: upheld by caller.
        let offset = unsafe { ptr.cast::<()>().byte_offset_from_unsigned(origin) };
        // SAFETY: `!offset` cannot be zero, because `offset` cannot be equal to `usize::MAX`.
        // Even if the offset could be greater than `isize::MAX` (< `usize::MAX`), it cannot be
        // `usize::MAX` because the origin pointer is not null.
        let inner = unsafe { NonZeroUsize::new_unchecked(!offset) };

        Self {
            inner,
            marker: PhantomData,
        }
    }

    /// Recover the pointer passed to [`RelPtr::new`] given its origin.
    ///
    /// # Safety
    ///
    /// `origin` must be the same as the one passed to [`RelPtr::new`].
    #[inline]
    pub const unsafe fn get(self, origin: NonNull<()>) -> NonNull<T> {
        // SAFETY: upheld by caller.
        unsafe { origin.byte_add(!self.inner.get()).cast::<T>() }
    }

    #[inline]
    pub const fn cast<U>(self) -> RelPtr<U> {
        RelPtr {
            inner: self.inner,
            marker: PhantomData,
        }
    }
}

impl<T> Clone for RelPtr<T> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: self.inner,
            marker: self.marker,
        }
    }
}

impl<T> Copy for RelPtr<T> {}

impl<T> fmt::Debug for RelPtr<T> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl<T> Hash for RelPtr<T> {
    #[inline]
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.inner.hash(state);
    }
}

impl<T> PartialEq for RelPtr<T> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.inner.eq(&other.inner)
    }
}
