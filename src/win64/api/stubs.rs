//! Generic API stubs

use crate::Result;
use unicorn_engine::{Unicorn, RegisterX86};

/// Generic API stub that just returns success
pub fn generic_success_stub(emu: &mut Unicorn<'_, ()>, name: &str) -> Result<()> {
    log::debug!("API stub (success): {}", name);
    emu.reg_write(RegisterX86::RAX, 1)?;
    Ok(())
}

/// Generic API stub that returns null/failure
pub fn generic_null_stub(emu: &mut Unicorn<'_, ()>, name: &str) -> Result<()> {
    log::debug!("API stub (null): {}", name);
    emu.reg_write(RegisterX86::RAX, 0)?;
    Ok(())
}
