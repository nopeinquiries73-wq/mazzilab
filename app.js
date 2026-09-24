const $=x=>document.querySelector(x), state={files:[],selected:null,report:null};
function fmt(n){return n<1024?n+" B":n<1048576?(n/1024).toFixed(1)+" KB":(n/1048576).toFixed(2)+" MB"}
function esc(s){return String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]))}
function entropy(b){let c=new Array(256).fill(0);for(const x of b)c[x]++;let e=0;for(const n of c)if(n){let p=n/b.length;e-=p*Math.log2(p)}return e}
function hex(b){let o=[];for(let i=0;i<Math.min(b.length,4096);i+=16){let h="",a="";for(let j=0;j<16;j++){if(i+j<b.length){let x=b[i+j];h+=x.toString(16).padStart(2,"0")+" ";a+=x>31&&x<127?String.fromCharCode(x):"."}else{h+="   ";a+=" "}}o.push(i.toString(16).padStart(8,"0")+"  "+h+" |"+a+"|")}return o.join("\n")}
function strings(b){let out=[],s="";for(let x of b){if(x>=32&&x<127)s+=String.fromCharCode(x);else{if(s.length>=4)out.push(s);s=""}}if(s.length>=4)out.push(s);return [...new Set(out)].slice(0,1000).join("\n")}
async function sha(b){return [...new Uint8Array(await crypto.subtle.digest("SHA-256",b))].map(x=>x.toString(16).padStart(2,"0")).join("")}
async function load(file){
 $("#msg").textContent="Reading archive…";
 if(!/\.zip$/i.test(file.name)){ $("#msg").textContent="RAR requires the backend endpoint; ZIP is supported directly in this build."; return }
 const fd=new FormData();fd.append("file",file);
 const r=await fetch("/api/analyze",{method:"POST",body:fd});if(!r.ok){$("#msg").textContent="Analysis failed.";return}
 state.report=await r.json();state.files=state.report.files;$("#drop").hidden=true;$("#app").hidden=false;renderTree();showReport();
}
function renderTree(){let q=$("#filter").value.toLowerCase();$("#tree").innerHTML=state.files.filter(x=>x.name.toLowerCase().includes(q)).map((f,i)=>`<div class=node data-i="${i}">▸ ${esc(f.name)}</div>`).join("");$("#count").textContent=state.files.length;document.querySelectorAll(".node").forEach(n=>n.onclick=()=>select(+n.dataset.i))}
function select(i){state.selected=state.files[i];document.querySelectorAll(".node").forEach(n=>n.classList.remove("sel"));document.querySelector(`[data-i="${i}"]`).classList.add("sel");$("#title").textContent=state.selected.name;fetchFile(i)}
async function fetchFile(i){let r=await fetch("/api/file/"+encodeURIComponent(i));let x=await r.json();let b=Uint8Array.from(atob(x.data),c=>c.charCodeAt(0));$("#code").textContent=new TextDecoder().decode(b);$("#hex").textContent=hex(b);$("#strings").textContent=strings(b);$("#analysis").innerHTML=`<div class=card><label>SHA-256</label><strong>${x.sha256}</strong></div><div class=card><label>Entropy</label><strong>${entropy(b).toFixed(3)}</strong></div><div class=card><label>Size</label><strong>${fmt(b.length)}</strong></div>`}
function showReport(){let r=state.report;$("#overview").innerHTML=`<div class=card><label>Archive</label><strong>${esc(r.archive)}</strong></div><div class=card><label>Files</label><strong>${r.files.length}</strong></div><div class=card><label>Mode</label><strong>Static only</strong></div><p>${esc(r.note)}</p>`}
$("#go").onclick=()=>$("#file").files[0]&&load($("#file").files[0]);$("#filter").oninput=renderTree;
document.querySelectorAll(".tabs button").forEach(b=>b.onclick=()=>{document.querySelectorAll(".tabs button,.pane").forEach(x=>x.classList.remove("active"));b.classList.add("active");$("#"+b.dataset.t).classList.add("active")});
$("#scan").onclick=()=>alert("The backend already performs static archive analysis. No uploaded file is executed.");
$("#report").onclick=()=>{let a=document.createElement("a");a.href=URL.createObjectURL(new Blob([JSON.stringify(state.report,null,2)],{type:"application/json"}));a.download="tracelab-report.json";a.click()};
document.querySelector(".tabs button").classList.add("active");$("#overview").classList.add("active");