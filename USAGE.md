# Midas Usage Guide

## Quick Start

```bash
# Build in Docker (required)
docker run --rm -v "$(pwd):/midas" -w /midas rust:latest bash -c '
  apt-get update && apt-get install -y libclang-dev clang cmake
  export LIBCLANG_PATH=/usr/lib/llvm-19/lib
  cargo build --release
'

# Or use the provided script
chmod +x test-build.sh
./test-build.sh

# Binary location
target/release/midas
```

## Basic Usage

### Unpack a Themida-protected executable

```bash
midas -i protected.exe -o unpacked.exe
```

### Detect Themida version only

```bash
midas -i protected.exe --detect-only
```

Output: `ThemidaVersion::V3` or similar

### Verbose debugging

```bash
midas -i protected.exe -o unpacked.exe -v
```

## Automation-Friendly Options

### JSON Output Mode

Perfect for programmatic integration:

```bash
midas -i protected.exe -o unpacked.exe --json
```

Output format:
```json
{
  "success": true,
  "output": "unpacked.exe",
  "themida_version": "ThemidaVersion::V3"
}
```

Or on failure:
```json
{
  "success": false,
  "error": "OEP not found"
}
```

### Quiet Mode

Only print errors (useful in pipelines):

```bash
midas -i protected.exe -o unpacked.exe --quiet
```

### Combine JSON + Quiet for Clean Automation

```bash
midas -i protected.exe -o unpacked.exe --json --quiet
```

This gives you:
- JSON output to stdout (parse this)
- Errors to stderr (log these)
- Exit code 0/1 (check this)

## Advanced Options

### Custom Instruction Limit

Default is 10 million instructions. Increase for complex packers:

```bash
midas -i protected.exe -o unpacked.exe --max-instructions 100000000
```

### Custom Workspace Address

```bash
midas -i protected.exe -o unpacked.exe --workspace 0x30000000
```

## Exit Codes

- `0`: Unpacking successful
- `1`: Unpacking failed

Example check:
```bash
if midas -i sample.exe -o out.exe --quiet; then
  echo "Success!"
else
  echo "Failed with exit code $?"
fi
```

## Output Routing

- **stdout**: Success messages and JSON output
- **stderr**: Logs, debug info, and errors

Example of capturing separately:
```bash
# Capture JSON output
result=$(midas -i sample.exe -o out.exe --json 2>/dev/null)

# Capture errors only
errors=$(midas -i sample.exe -o out.exe 2>&1 >/dev/null)
```

## Integration Examples

### Bash Script

```bash
#!/bin/bash

INPUT="$1"
OUTPUT="${INPUT%.exe}_unpacked.exe"

if midas -i "$INPUT" -o "$OUTPUT" --json --quiet > result.json; then
  echo "✓ Unpacked successfully to $OUTPUT"
  cat result.json
else
  echo "✗ Unpacking failed"
  exit 1
fi
```

### Python Integration

```python
import subprocess
import json
import sys

def unpack_themida(input_path, output_path):
    result = subprocess.run(
        ["midas", "-i", input_path, "-o", output_path, "--json", "--quiet"],
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0:
        data = json.loads(result.stdout)
        print(f"✓ Unpacked: {data['output']}")
        print(f"  Themida version: {data['themida_version']}")
        return True
    else:
        print(f"✗ Failed: {result.stderr}", file=sys.stderr)
        return False

# Usage
unpack_themida("protected.exe", "unpacked.exe")
```

### Rust Integration (for Zugriff)

```rust
use std::process::Command;
use serde_json::Value;

pub async fn unpack_with_midas(input: &Path, output: &Path) -> Result<()> {
    let result = Command::new("midas")
        .arg("-i").arg(input)
        .arg("-o").arg(output)
        .arg("--max-instructions").arg("100000000")
        .arg("--json")
        .arg("--quiet")
        .output()?;
    
    if result.status.success() {
        let data: Value = serde_json::from_slice(&result.stdout)?;
        
        if data["success"].as_bool().unwrap_or(false) {
            log::info!("Midas unpacking successful: {:?}", output);
            Ok(())
        } else {
            let error = data["error"].as_str().unwrap_or("Unknown error");
            Err(anyhow!("Midas failed: {}", error))
        }
    } else {
        let error = String::from_utf8_lossy(&result.stderr);
        Err(anyhow!("Midas execution failed: {}", error))
    }
}
```

## Troubleshooting

### "OEP not found" Error

The emulator hit the instruction limit before finding the OEP. Try:
- Increase `--max-instructions`
- Use verbose mode (`-v`) to see execution progress

### "Emulation error" 

The emulator hit an unimplemented instruction or API. This is expected for now. Check:
- Verbose output to see where it failed
- Consider this a known limitation

### No Output File

Even if unpacking "succeeds", the output may not be a valid PE. This is expected - the dumper needs more work.

## What to Expect

Currently, Midas will:
- ✅ Load and parse PE files
- ✅ Detect Themida versions
- ✅ Emulate execution with API hooks
- ✅ Track memory writes and OEP
- ✅ Dump memory to output file

But it may not:
- ❌ Successfully unpack all samples (needs testing)
- ❌ Produce runnable executables (dumps are for analysis)
- ❌ Reconstruct imports perfectly (IAT work in progress)

Use it for **analysis and research**, not for production unpacking yet.

## Help

```bash
midas --help
```

Shows all available options and their defaults.
