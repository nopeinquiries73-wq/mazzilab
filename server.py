import base64, hashlib, io, json, math, os, re, shutil, tempfile, zipfile
from pathlib import Path
from flask import Flask, jsonify, request, send_from_directory

ROOT=Path(__file__).resolve().parent.parent
app=Flask(__name__,static_folder=str(ROOT/"frontend"),static_url_path="")
MAX_UPLOAD=50*1024*1024
MAX_FILES=5000
SUSPICIOUS=[
 r"powershell",r"cmd\.exe",r"wscript",r"cscript",r"rundll32",r"regsvr32",
 r"schtasks",r"currentversion\\run",r"invoke-expression",r"downloadstring",
 r"frombase64string",r"createRemoteThread",r"virtualalloc",r"writeprocessmemory"
]
sessions={}

def entropy(data):
    if not data:return 0.0
    counts=[0]*256
    for x in data:counts[x]+=1
    return -sum((n/len(data))*math.log2(n/len(data)) for n in counts if n)

def sha256(data):return hashlib.sha256(data).hexdigest()

def safe_name(name):
    return Path(name.replace("\\","/")).name

@app.get("/")
def index(): return send_from_directory(ROOT/"frontend","index.html")

@app.post("/api/analyze")
def analyze():
    f=request.files.get("file")
    if not f:return jsonify(error="missing file"),400
    if request.content_length and request.content_length>MAX_UPLOAD:return jsonify(error="upload too large"),413
    raw=f.read(MAX_UPLOAD+1)
    if len(raw)>MAX_UPLOAD:return jsonify(error="upload too large"),413
    if not raw.startswith(b"PK"): return jsonify(error="Only ZIP is enabled in this safe build; RAR can be added with a sandboxed parser."),415
    sid=hashlib.sha256(os.urandom(32)).hexdigest()
    files=[]
    try:
        z=zipfile.ZipFile(io.BytesIO(raw))
        if len(z.infolist())>MAX_FILES:return jsonify(error="too many archive entries"),413
        total=0
        for info in z.infolist():
            if info.is_dir():continue
            name=safe_name(info.filename)
            if info.file_size>10*1024*1024:return jsonify(error=f"file too large: {name}"),413
            total+=info.file_size
            if total>100*1024*1024:return jsonify(error="expanded size limit exceeded"),413
            data=z.read(info)
            text=data[:2_000_000].decode("utf-8","ignore")
            hits=[p for p in SUSPICIOUS if re.search(p,text,re.I)]
            files.append({"name":name,"size":len(data),"sha256":sha256(data),"entropy":round(entropy(data),4),"suspicious":hits})
            if len(files)>MAX_FILES:break
        sessions[sid]={"raw":raw,"files":files,"zip":z}
    except (zipfile.BadZipFile,RuntimeError) as e:return jsonify(error="invalid or unsupported ZIP"),400
    return jsonify(session=sid,archive=f.filename,files=files,note="Static heuristics only. No extracted file is executed.")

@app.get("/api/file/<int:index>")
def get_file(index):
    # Demo single-process session selection. For production use a signed session token.
    if not sessions:return jsonify(error="no active analysis"),404
    s=next(reversed(sessions.values()))
    if index<0 or index>=len(s["files"]):return jsonify(error="bad index"),404
    name=s["files"][index]["name"]
    target=next((i for i in s["zip"].infolist() if not i.is_dir() and safe_name(i.filename)==name),None)
    if not target:return jsonify(error="not found"),404
    data=s["zip"].read(target)
    return jsonify(name=name,data=base64.b64encode(data).decode(),sha256=sha256(data))

@app.get("/health")
def health():return {"status":"ok"}

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT","10000")))
