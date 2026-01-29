# Midas

A Themida 3.x unpacker for Linux, written in Rust, using Unicorn CPU emulation.

**Midas** turns Themida-protected binaries into analyzable code through CPU emulation.

## Features

- **Pure Linux operation**: No Windows required
- **Unicorn-based emulation**: Emulates x86-64 instruction execution
- **Windows API emulation**: Implements critical Windows APIs
- **OEP detection**: Automatically finds the original entry point
- **IAT reconstruction**: Recovers import table (basic implementation)
- **Anti-debug bypasses**: Handles common anti-debugging techniques

## Architecture

```
PE File → Parser → Unicorn Loader → Emulation → OEP Detection → Dump
                         ↓
                   Windows API Hooks
                   (PEB, TEB, APIs)
```

## Status

✅ **Phase 2 Complete** - Core unpacking functionality implemented!

**What's Working:**
- ✅ PE64 parsing and section detection
- ✅ Themida version detection
- ✅ Unicorn emulation setup with full execution loop
- ✅ Windows structure emulation (PEB, TEB, LDR)
- ✅ API hooks framework with ~6 critical APIs
- ✅ Memory write tracking for code sections
- ✅ OEP detection heuristics
- ✅ Memory dumping and basic PE output
- ✅ JSON output mode for automation
- ✅ Detect-only mode for version identification

**In Development:**
- 🚧 IAT reconstruction (advanced)
- 🚧 PE reconstruction with proper imports
- 🚧 Additional API implementations
- 🚧 Testing with real Themida samples

## Building

### In Docker/Linux (Recommended)
```bash
docker run --rm -v "$(pwd):/midas" -w /midas rust:latest bash -c '
  apt-get update && apt-get install -y libclang-dev clang cmake
  export LIBCLANG_PATH=/usr/lib/llvm-19/lib
  cargo build --release
'

# Binary will be at: target/release/midas
```

### Or use the test script
```bash
chmod +x test-build.sh
./test-build.sh
```

### macOS Note
Due to Unicorn build requirements, this must be built on Linux. Use Docker as shown above.

## Usage

```bash
# Basic usage
midas -i protected.exe -o unpacked.exe

# Verbose output
midas -i protected.exe -o unpacked.exe -v

# Quiet mode (only errors)
midas -i protected.exe -o unpacked.exe -q

# JSON output (for automation)
midas -i protected.exe -o unpacked.exe --json

# Detect Themida version only (no unpacking)
midas -i protected.exe --detect-only

# Custom instruction limit
midas -i protected.exe -o unpacked.exe --max-instructions 50000000
```

### Exit Codes

- `0`: Success
- `1`: Failure

### Output Routing

- Success messages → stdout
- Logs and errors → stderr
- JSON output → stdout

## Limitations

- **64-bit only**: Currently supports only PE64 files
- **Themida 3.x focus**: Optimized for Themida 3.x
- **No virtualization**: Cannot unvirtualize VM-protected code
- **Non-runnable dumps**: Dumps are for analysis, not execution
- **API coverage**: Limited to ~20 critical APIs initially

## How It Works

1. **Parse PE**: Load and analyze the protected PE file
2. **Setup Emulation**: 
   - Map PE sections into Unicorn memory
   - Create fake PEB/TEB structures
   - Setup IAT with hook addresses
3. **Emulate**:
   - Execute from entry point
   - Hook Windows APIs as they're called
   - Monitor code section for writes
4. **Detect OEP**:
   - Watch for execution leaving Themida section
   - Identify transition to original code
5. **Dump**:
   - Extract decrypted memory
   - Reconstruct imports
   - Generate output PE

## Technical Details

### API Hooking

APIs are hooked by:
1. Mapping fake API addresses (e.g., 0xFEED_0000 range)
2. Detecting when execution reaches these addresses
3. Executing emulated implementation
4. Returning control to caller

### OEP Detection

OEP is detected by monitoring:
- Execution entering code section from outside
- Pattern of memory writes to code
- API call sequences typical of unpacked code

### Memory Layout

```
0x7FFF_F000: PEB (Process Environment Block)
0x7FFF_E000: TEB (Thread Environment Block)  
0x7FFF_D000: LDR_DATA
0x00100000: Stack (1MB)
0x00400000: PE Image (typical)
0x20000000: Workspace (allocations)
0xFEED_0000: Fake API addresses
```

## Dependencies

- **unicorn-engine**: CPU emulation
- **iced-x86**: x86/x64 disassembler
- **goblin**: PE parsing
- **clap**: CLI argument parsing

## Inspiration

Based on research of existing tools:
- **Magicmida**: Windows-native Themida unpacker (Delphi)
- **unlicense**: Python Themida unpacker using Frida
- **mwemu**: Rust malware emulator framework
- **unicorn_pe**: PE emulation with Unicorn

## License

GPL-3.0 - See LICENSE file

## Contributing

Contributions welcome! This is an active development project.
