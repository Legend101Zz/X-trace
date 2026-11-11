//! Safe SDK calls and the private-storage fallback test seam.

use std::{fs::File, path::Path};

pub(crate) fn listing_names_compatible(metadata: &std::fs::Metadata) -> bool {
    xtrace_macos_acl::listing_names_compatible(metadata, crate::policy::valid_owner_name)
}

pub(crate) fn no_extended_acl(path: &Path, descriptor: Option<&File>) -> bool {
    #[cfg(test)]
    if FORCE_ERROR.with(std::cell::Cell::get) {
        return false;
    }
    xtrace_macos_acl::no_extended_acl(path, descriptor)
}

#[cfg(test)]
thread_local! {
    static FORCE_ERROR: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Force the native query to fail on this thread, keeping fallback tests independent of SDK
/// or filesystem failures. Restores the previous setting even if a test assertion unwinds.
#[cfg(test)]
pub(crate) struct NativeError(bool);

#[cfg(test)]
impl NativeError {
    pub(crate) fn inject() -> Self {
        Self(FORCE_ERROR.with(|force| force.replace(true)))
    }
}

#[cfg(test)]
impl Drop for NativeError {
    fn drop(&mut self) {
        FORCE_ERROR.with(|force| force.set(self.0));
    }
}
