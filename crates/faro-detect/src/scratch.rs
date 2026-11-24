//! Zeroize-on-drop scratch buffers for anything derived from frame pixels.
//!
//! Why not just `Zeroizing<Vec<T>>`? Two reasons:
//!
//! 1. A `Scratch` is always allocated at its final length and never grows,
//!    so there is no reallocation that could leave an unzeroized copy of
//!    pixel-derived data in freed heap memory. The type simply offers no
//!    method that could reallocate.
//! 2. In unit tests, every scratch buffer registers itself with the
//!    instrumented allocator in `privacy_tests::audit`, which checks that
//!    the memory really is all zeroes at the moment it is freed (§10).

use std::ops::{Deref, DerefMut};
use zeroize::{DefaultIsZeroes, Zeroize, Zeroizing};

/// A fixed-length, zeroize-on-drop buffer.
pub(crate) struct Scratch<T: DefaultIsZeroes>(Vec<T>);

impl<T: DefaultIsZeroes> Scratch<T> {
    /// Allocate `len` default-valued (zero) elements.
    pub(crate) fn zeroed(len: usize) -> Self {
        let v = vec![T::default(); len];
        #[cfg(test)]
        if len > 0 {
            crate::privacy_tests::audit::watch(
                v.as_ptr().cast::<u8>(),
                std::mem::size_of_val(&v[..]),
            );
        }
        Scratch(v)
    }

    /// Hand the buffer to a caller outside this crate while keeping the
    /// zeroize-on-drop guarantee.
    pub(crate) fn into_zeroizing(mut self) -> Zeroizing<Vec<T>> {
        Zeroizing::new(std::mem::take(&mut self.0))
    }
}

impl<T: DefaultIsZeroes> Deref for Scratch<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.0
    }
}

impl<T: DefaultIsZeroes> DerefMut for Scratch<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.0
    }
}

impl<T: DefaultIsZeroes> Drop for Scratch<T> {
    fn drop(&mut self) {
        // `Vec::zeroize` overwrites the elements and any spare capacity with
        // volatile writes before the allocation is released.
        self.0.zeroize();
    }
}

impl<T: DefaultIsZeroes> std::fmt::Debug for Scratch<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print pixel-derived contents.
        write!(f, "Scratch(<{} elements redacted>)", self.0.len())
    }
}
