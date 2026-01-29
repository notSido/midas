//! Windows API emulation

pub mod kernel32;
pub mod ntdll;
pub mod stubs;

pub use kernel32::*;
pub use ntdll::*;
pub use stubs::*;
