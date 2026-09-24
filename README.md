# TraceLab — Render-ready static archive analyzer

## Deploy on Render

1. Put this repository on GitHub.
2. In Render, create a new Blueprint and select the repository.
3. Render reads `render.yaml`.
4. The service installs the Python dependencies and starts Waitress.
5. Open the generated Render URL.

## Safety model

This application is a **static analyzer**. It does not execute uploaded files, scripts, PE files, macros, or binaries.

The backend limits upload size, archive entry count, and expanded size. Archive member names are reduced to basenames before being exposed to the application, avoiding normal Zip Slip path traversal.

## Current functionality

- Render-ready Flask backend
- ZIP upload and inspection
- File explorer
- Source/text viewer
- Hex viewer
- Strings extraction
- SHA-256
- Entropy
- Suspicious-string heuristics
- JSON report export
- Health endpoint
- No execution of samples

## Production hardening

For real malware samples, put the analysis worker in a separate disposable container/VM with no credentials, no host mounts, strict CPU/RAM/time limits, and no outbound network access by default. Store samples only ephemerally and delete them after analysis.

For a real antivirus result, integrate an authorized scanning engine or service. The heuristic scan in this repository must not be presented as an antivirus verdict.

RAR support should be implemented with a sandboxed parser/worker rather than adding an untrusted native extractor directly to the web process.
