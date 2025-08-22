# TinyDump

Android native SO and DEX dumper.

## Features

- **SO Dump**: Extract SO files from running Android processes
- **DEX Dump**: Extract DEX files from running Android processes  
- **SO List**: List all SO files loaded by a process
- **Auto-Fix**: Integrated SoFixer for automatic SO file repair

## Build

```bash
# ARM64 Android
cargo build --target aarch64-linux-android --release
```

## Usage

```bash
# List all SO files
./tinydump --list-so -p <PID>
./tinydump --list-so -n <process_name>

# Dump SO file
./tinydump -t <so_name> -p <PID> -o <output_dir>

# Dump DEX files
./tinydump --dex -p <PID> -o <output_dir>
```

## Requirements

- **Root access only** 
- Android device with root access
- ARM64 architecture

## License

MIT License

## Thanks
https://github.com/F8LEFT/SoFixer