//! Windows API emulation

pub mod kernel32;
pub mod ntdll;
pub mod stubs;
pub mod registry;

pub use kernel32::*;
pub use ntdll::*;
pub use stubs::*;
pub use registry::ApiRegistry;
