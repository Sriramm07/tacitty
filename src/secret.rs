//! Secret-holding byte buffers: zeroized on drop, best-effort `mlock`ed,
//! and impossible to print by accident.

use std::fmt;
use std::ops::Deref;

use zeroize::{Zeroize, Zeroizing};

use crate::sys;

/// A growable byte buffer that wipes itself on drop and on every reallocation.
///
/// `mlock` is applied best-effort to each allocation (page granular; pages are
/// never unlocked so that neighbouring allocations sharing a page stay locked).
/// When `RLIMIT_MEMLOCK` is exhausted locking silently degrades.
pub struct SecretBuf {
    inner: Zeroizing<Vec<u8>>,
}

impl SecretBuf {
    pub fn new() -> Self {
        Self::with_capacity(128)
    }

    pub fn with_capacity(cap: usize) -> Self {
        let v: Vec<u8> = Vec::with_capacity(cap.max(1));
        sys::mlock(v.as_ptr(), v.capacity());
        SecretBuf {
            inner: Zeroizing::new(v),
        }
    }

    pub fn from_slice(s: &[u8]) -> Self {
        let mut b = Self::with_capacity(s.len());
        b.extend_from_slice(s);
        b
    }

    /// Take ownership of an existing Vec (its bytes are wiped when dropped).
    pub fn from_vec(v: Vec<u8>) -> Self {
        sys::mlock(v.as_ptr(), v.capacity());
        SecretBuf {
            inner: Zeroizing::new(v),
        }
    }

    fn reserve_one(&mut self, extra: usize) {
        if self.inner.capacity() - self.inner.len() >= extra {
            return;
        }
        // Grow by hand so the old allocation is wiped (Vec::reserve would
        // free it without zeroing).
        let mut grown: Vec<u8> = Vec::with_capacity((self.inner.len() + extra).max(16) * 2);
        grown.extend_from_slice(&self.inner);
        sys::mlock(grown.as_ptr(), grown.capacity());
        self.inner = Zeroizing::new(grown); // old value dropped => zeroized
    }

    pub fn push(&mut self, b: u8) {
        self.reserve_one(1);
        self.inner.push(b);
    }

    pub fn extend_from_slice(&mut self, s: &[u8]) {
        self.reserve_one(s.len());
        self.inner.extend_from_slice(s);
    }

    pub fn pop(&mut self) -> Option<u8> {
        let b = self.inner.pop();
        // wipe the vacated byte
        let len = self.inner.len();
        // Wipe the vacated byte by re-extending within existing capacity.
        if b.is_some() {
            self.inner.resize(len + 1, 0);
            self.inner.truncate(len);
        }
        b
    }

    /// Wipe contents (capacity is kept).
    pub fn clear(&mut self) {
        self.inner.zeroize();
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Default for SecretBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for SecretBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.inner
    }
}

impl PartialEq for SecretBuf {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for SecretBuf {}

impl PartialEq<[u8]> for SecretBuf {
    fn eq(&self, other: &[u8]) -> bool {
        self.as_slice() == other
    }
}

impl PartialEq<&[u8]> for SecretBuf {
    fn eq(&self, other: &&[u8]) -> bool {
        self.as_slice() == *other
    }
}

/// Lets serializers (e.g. `serde_json::to_writer`) write straight into a
/// self-wiping buffer, so encoded secrets never sit in an ordinary `Vec`.
impl std::io::Write for SecretBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBuf(<{} bytes redacted>)", self.len())
    }
}

impl Clone for SecretBuf {
    fn clone(&self) -> Self {
        Self::from_slice(self.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_pop_clear() {
        let mut b = SecretBuf::with_capacity(2);
        for i in 0..100u8 {
            b.push(i);
        }
        assert_eq!(b.len(), 100);
        assert_eq!(b.pop(), Some(99));
        b.clear();
        assert!(b.is_empty());
    }

    #[test]
    fn debug_is_redacted() {
        let b = SecretBuf::from_slice(b"hunter2");
        let s = format!("{:?}", b);
        assert!(!s.contains("hunter2"));
    }
}
