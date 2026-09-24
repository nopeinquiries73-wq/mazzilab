# Mazzi Lab — rebuilt

This version uses a small Render Docker service instead of trying to make the
browser guess how to load a WASM archive engine. The container installs 7-Zip,
which handles ZIP, RAR, 7Z and common compressed formats on the server.

## Deploy

Push the folder to GitHub and create a Render Blueprint from the repository.
Render reads `render.yaml` and builds the Dockerfile.

## Features

- ZIP / RAR / 7Z / TAR / GZ / BZ2 / XZ
- Drag and drop
- File explorer and search
- Code/text viewer
- Hex viewer
- Strings
- SHA-256
- Shannon entropy
- Static heuristic indicators
- JSON report
- Upload and expanded-size limits
- Automatic temporary workspace
- Cleanup when starting a new analysis
- No uploaded file is executed

## Safety

The server only extracts and reads files. It does not launch extracted programs,
scripts, macros or binaries. For serious malware research, use a separate
disposable VM/container with no credentials and restricted networking.

The heuristic "hits" are indicators, not an antivirus verdict.
