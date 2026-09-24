import base64, hashlib, math, os, re, shutil, subprocess, tempfile, uuid
from pathlib import Path
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024

ROOT = Path(__file__).resolve().parent
UPLOADS = ROOT / "runtime"
UPLOADS.mkdir(exist_ok=True)
MAX_FILES = 5000
MAX_EXPANDED = 250 * 1024 * 1024
MAX_ENTRY = 25 * 1024 * 1024
sessions = {}

PATTERNS = [
    ("PowerShell", r"\bpowershell(?:\.exe)?\b"),
    ("Command shell", r"\bcmd(?:\.exe)?\b"),
    ("Script host", r"\b(?:wscript|cscript)(?:\.exe)?\b"),
    ("Rundll32", r"\brundll32(?:\.exe)?\b"),
    ("Regsvr32", r"\bregsvr32(?:\.exe)?\b"),
    ("Scheduled task", r"\bschtasks(?:\.exe)?\b"),
    ("Run key", r"currentversion[\\/]+run"),
    ("DownloadString", r"\bdownloadstring\b"),
    ("Base64 decode", r"frombase64string"),
    ("Remote thread", r"CreateRemoteThread"),
    ("VirtualAlloc", r"VirtualAlloc"),
    ("WriteProcessMemory", r"WriteProcessMemory"),
]

TEXT_EXTS = {
    ".txt",".log",".json",".xml",".html",".htm",".css",".js",".ts",".jsx",".tsx",
    ".py",".ps1",".bat",".cmd",".c",".cc",".cpp",".h",".hpp",".cs",".java",
    ".php",".rb",".go",".rs",".sql",".yaml",".yml",".ini",".cfg",".md"
}

def safe_member(path):
    p = Path(path.replace("\\", "/"))
    if p.is_absolute() or ".." in p.parts:
        return None
    clean = "/".join(x for x in p.parts if x not in ("", "."))
    return clean or None

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in counts if c)

def strings(data):
    out, cur = [], []
    for b in data:
        if 32 <= b <= 126:
            cur.append(chr(b))
        else:
            if len(cur) >= 4:
                out.append("".join(cur))
            cur = []
    if len(cur) >= 4:
        out.append("".join(cur))
    return list(dict.fromkeys(out))[:2000]

def scan_bytes(data):
    sample = data[:2_000_000].decode("utf-8", "ignore")
    hits = []
    for label, pattern in PATTERNS:
        if re.search(pattern, sample, re.I):
            hits.append(label)
    return hits

def archive_tool():
    for name in ("7zz", "7z"):
        p = shutil.which(name)
        if p:
            return p
    return None

def extract_archive(raw_path, out_dir):
    tool = archive_tool()
    if not tool:
        raise RuntimeError("Archive engine is not installed")
    cmd = [tool, "x", "-y", f"-o{out_dir}", str(raw_path)]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
    if proc.returncode != 0:
        msg = proc.stderr.decode("utf-8", "replace")[-1000:]
        raise RuntimeError(msg or "Archive extraction failed")

def build_index(root):
    files = []
    total = 0
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        safe = safe_member(rel)
        if not safe:
            continue
        size = p.stat().st_size
        if size > MAX_ENTRY:
            continue
        total += size
        if total > MAX_EXPANDED:
            raise RuntimeError("Expanded archive exceeds safety limit")
        data = p.read_bytes()
        files.append({
            "id": len(files),
            "name": safe,
            "size": size,
            "sha256": sha256(data),
            "entropy": round(entropy(data), 3),
            "hits": scan_bytes(data),
            "text": Path(safe).suffix.lower() in TEXT_EXTS
        })
        if len(files) >= MAX_FILES:
            raise RuntimeError("Archive contains too many files")
    return files

@app.get("/")
def home():
    return render_template("index.html")

@app.post("/api/upload")
def upload():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify(error="Choose an archive first."), 400
    ext = Path(f.filename).suffix.lower()
    if ext not in {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"}:
        return jsonify(error="Supported: ZIP, RAR, 7Z, TAR, GZ, BZ2 and XZ."), 415

    sid = uuid.uuid4().hex
    work = UPLOADS / sid
    src = work / ("sample" + ext)
    extracted = work / "files"
    work.mkdir(parents=True)
    extracted.mkdir()

    try:
        f.save(src)
        extract_archive(src, extracted)
        index = build_index(extracted)
        sessions[sid] = {"root": extracted, "files": index, "name": f.filename}
        src.unlink(missing_ok=True)
        return jsonify(session=sid, name=f.filename, files=index)
    except Exception as e:
        shutil.rmtree(work, ignore_errors=True)
        return jsonify(error=str(e)), 400

@app.get("/api/file/<sid>/<int:file_id>")
def get_file(sid, file_id):
    s = sessions.get(sid)
    if not s or file_id < 0 or file_id >= len(s["files"]):
        return jsonify(error="File not found"), 404
    meta = s["files"][file_id]
    path = s["root"] / meta["name"]
    if not path.exists() or not path.is_file():
        return jsonify(error="File not found"), 404
    data = path.read_bytes()
    return jsonify(
        name=meta["name"], size=len(data), sha256=meta["sha256"],
        entropy=meta["entropy"], hits=meta["hits"],
        data=base64.b64encode(data[:10 * 1024 * 1024]).decode()
    )

@app.post("/api/cleanup/<sid>")
def cleanup(sid):
    s = sessions.pop(sid, None)
    if s:
        shutil.rmtree(UPLOADS / sid, ignore_errors=True)
    return jsonify(ok=True)

@app.get("/health")
def health():
    return jsonify(status="ok")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
