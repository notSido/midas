# Development Notes

## Current Status

### Phase 1: Foundation ✅ COMPLETED

Successfully implemented:
- Complete project structure with proper module organization
- PE64 parser using goblin
- Unicorn engine wrapper with register/memory operations
- Windows 64-bit structures (PEB, TEB, LDR_DATA)
- API emulation framework for kernel32 and ntdll
- OEP detection logic
- IAT reconstruction framework
- Pattern matching utilities
- Disassembly helpers using iced-x86
- CLI interface with clap
- Comprehensive README

### Known Issues

#### 1. Unicorn Build Issue on macOS

```
error: failed to run custom build command for `unicorn-engine-sys v2.1.5`
fatal error: 'sys/time.h' file not found
```

**Cause**: The unicorn-engine crate has build issues on macOS due to missing system headers or incorrect SDK paths.

**Solutions**:
1. **Test on Linux** (recommended): This project is designed for Linux/Debian containers anyway
2. **Use prebuilt Unicorn**: Install Unicorn via Homebrew and link against it
3. **Fix SDK path**: Export proper SDKROOT path
4. **Use Docker**: Build inside a Linux container

**For Linux/Debian testing**:
```bash
# In Debian container
apt-get update
apt-get install -y build-essential libclang-dev cmake
cargo build --release
```

#### 2. Incomplete Implementation

The current code is **foundational only**. Missing:
- Full emulation loop with instruction hooks
- Memory write tracking
- API address interception
- OEP detection integration
- IAT reconstruction from traced calls
- PE rebuilding with proper headers

### Next Steps

1. **Fix Build Environment**
   - Test on actual Linux/Debian system
   - Or setup Docker build environment

2. **Complete Emulation Loop**
   ```rust
   // Pseudo-code
   loop {
       // Execute one instruction
       emu.step();
       
       // Check if we hit an API hook
       if is_api_address(rip) {
           handle_api_call();
       }
       
       // Check if we hit OEP
       if oep_detector.on_execute(rip) {
           break;
       }
   }
   ```

3. **Add Memory Hooks**
   - Use Unicorn's hook_add for memory writes
   - Track writes to code section
   - Detect self-decryption

4. **Integrate Components**
   - Connect PE loader → Emulation → OEP detection → Dumper
   - Wire up API hooks
   - Test with simple packed sample

### Testing Strategy

1. **Unit Tests**: Test individual components (pattern matching, structures)
2. **Simple Sample**: Test with basic packed PE (not Themida initially)
3. **Themida Sample**: Test with actual Themida 3.x protected binary
4. **Compare Output**: Compare with Magicmida output on same sample

### Architecture Decisions

**Why Rust**: Memory safety, performance, good Unicorn bindings
**Why Unicorn**: Proven emulator, cross-platform, used by mwemu successfully
**Why 64-bit focus**: Modern Themida samples, simpler calling convention
**Why basic IAT**: Most analysis use cases don't need runnable output

### References

- Magicmida source: Themida 2.x/3.x Windows unpacker in Delphi
- mwemu: Rust malware emulator framework
- OALABS Themida emulation: Python/Unicorn example
- unlicense: Python/Frida Themida unpacker

### File Structure

```
src/
├── lib.rs           - Error types, public API
├── main.rs          - CLI entry point
├── pe/              - PE parsing and dumping
│   ├── parser.rs    - goblin-based PE64 parser
│   ├── loader.rs    - Load PE into Unicorn
│   └── dumper.rs    - Dump unpacked PE
├── emu/             - Emulation engine
│   ├── engine.rs    - Unicorn wrapper
│   ├── hooks.rs     - Hook manager
│   └── state.rs     - State tracking
├── win64/           - Windows structures
│   ├── peb.rs       - PEB/TEB/GS
│   ├── ldr.rs       - LDR_DATA
│   └── api/         - API emulation
│       ├── kernel32.rs
│       ├── ntdll.rs
│       └── stubs.rs
├── themida/         - Themida-specific logic
│   ├── detector.rs  - Version detection
│   ├── oep.rs       - OEP detection
│   └── iat.rs       - IAT reconstruction
└── utils/           - Utilities
    ├── pattern.rs   - Pattern matching
    └── disasm.rs    - Disassembly helpers
```

### Estimated Remaining Work

- **Phase 2**: ~20-30 hours (complete API hooks, emulation loop)
- **Phase 3**: ~15-20 hours (Themida-specific logic, OEP detection)
- **Phase 4**: ~10-15 hours (IAT reconstruction, PE dumping)
- **Testing**: ~10-20 hours (debugging with real samples)

**Total**: ~55-85 hours for a working prototype

### Limitations (By Design)

1. **No VM devirtualization**: Themida's VM is extremely complex
2. **No anti-dump fixes**: Advanced anti-dumps may break dumps
3. **No TLS handling**: TLS callbacks are complex
4. **Limited API coverage**: Start with ~20 APIs, expand as needed
5. **Analysis-focused**: Dumps for static analysis, not execution

## Build Instructions (When Ready)

### On Debian/Ubuntu:
```bash
apt-get install -y build-essential libclang-dev cmake
cargo build --release
./target/release/themida-unpack -i sample.exe -o unpacked.exe -v
```

### In Docker:
```bash
docker run -it --rm -v $(pwd):/work rust:latest bash
cd /work
apt-get update && apt-get install -y libclang-dev cmake
cargo build --release
```

## Conclusion

**Foundation is solid**. All major components are structured and stubbed out. The main work remaining is:
1. Fixing the build environment (Linux)
2. Implementing the emulation loop
3. Integrating components
4. Testing with real samples

The architecture is sound and based on proven techniques from existing tools.
