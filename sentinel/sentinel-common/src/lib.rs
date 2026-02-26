#![no_std]

pub const MAX_FILENAME_LEN: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OpenEvent {
    pub pid: u32,
    pub filename_len: u32,
    pub filename: [u8; MAX_FILENAME_LEN],
}

impl OpenEvent {
    /// Zero-initialize all fields to prevent kernel stack memory leakage.
    pub const fn zeroed() -> Self {
        Self {
            pid: 0,
            filename_len: 0,
            filename: [0u8; MAX_FILENAME_LEN],
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for OpenEvent {}
