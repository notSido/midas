//! Themida 3.x unpacker for Linux
//! 
//! This library provides functionality to unpack Themida-protected PE64 executables
//! using Unicorn CPU emulation on Linux systems.

pub mod pe;
pub mod emu;
pub mod win64;
pub mod themida;
pub mod utils;

use thiserror::Error;

/// Result type for the unpacker
pub type Result<T> = std::result::Result<T, UnpackError>;

/// Errors that can occur during unpacking
#[derive(Error, Debug)]
pub enum UnpackError {
    #[error("PE parsing error: {0}")]
    PeError(String),
    
    #[error("Emulation error: {0}")]
    EmulationError(String),
    
    #[error("Memory error: {0}")]
    MemoryError(String),
    
    #[error("API hook error: {0}")]
    ApiError(String),
    
    #[error("Themida detection failed: {0}")]
    DetectionError(String),
    
    #[error("OEP not found")]
    OepNotFound,
    
    #[error("IAT reconstruction failed: {0}")]
    IatError(String),
    
    #[error("Dump failed: {0}")]
    DumpError(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Unicorn error: {0}")]
    Unicorn(String),
    
    #[error("Not a 64-bit PE")]
    Not64Bit,
    
    #[error("Unsupported Themida version")]
    UnsupportedVersion,
}

impl From<unicorn_engine::unicorn_const::uc_error> for UnpackError {
    fn from(err: unicorn_engine::unicorn_const::uc_error) -> Self {
        UnpackError::Unicorn(format!("{:?}", err))
    }
}
