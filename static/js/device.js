const IP = window.DEVICE_IP;
let inspecting=false, lastSeq=0, logStarted=false;

async function loadDetail(){
  const d = await NS.get("/api/device/"+IP);
  if(!d.ok){ document.getElementById("detail").textContent="dispositivo no encontrado (escanea primero)"; return; }
  const dv=d.device; inspecting=d.inspecting;
  const shown = dv.custom_name || (dv.name&&dv.name!=="(sin nombre)"?dv.name:dv.ip);
  document.getElementById("dTitle").textContent = shown;
  const ni=document.getElementById("nameInput"); if(ni && !ni.value) ni.value = dv.custom_name || "";
  const ex=document.getElementById("exportLog"); if(ex) ex.href="/api/export/log.csv?ip="+encodeURIComponent(IP);
  document.getElementById("detail").innerHTML =
    `<div class="dl">identidad</div>
     <div>IP <span class="os num">${dv.ip}</span> &middot; mac <span class="mac num">${dv.mac}</span></div>
     <div>fabricante ${NS.esc(dv.vendor||"-")} &middot; iface ${NS.esc(dv.iface||"-")}</div>
     <div id="deepBox"><div class="dl">escaneo profundo (nmap)</div><div style="color:var(--faint)">pulsa "Escaneo profundo".</div></div>`;
  updateInspectBtn();
}

function updateInspectBtn(){
  const b=document.getElementById("inspectBtn");
  b.textContent = inspecting?"Detener intercepcion":"Inspeccionar";
  b.classList.toggle("primary", inspecting);
}

async function toggleInspect(){
  const url = inspecting?"/api/inspect/stop":"/api/inspect/start";
  const d = await NS.post(url,{ip:IP});
  if(!d.ok){ alert("Intercepcion: "+(d.error||"error")); return; }
  inspecting = (d.inspecting||[]).includes(IP);
  updateInspectBtn();
}

async function runDeep(){
  const b=document.getElementById("scanDeepBtn"); b.disabled=true; b.textContent="Analizando...";
  const box=document.getElementById("deepBox");
  box.innerHTML=`<div class="dl">escaneo profundo (nmap)</div><div style="color:var(--amber)">analizando... puede tardar</div>`;
  try{
    const r=await NS.post("/api/deepscan",{ip:IP});
    if(!r.ok){ box.innerHTML=`<div class="dl">escaneo profundo (nmap)</div><div style="color:var(--red)">${NS.esc(r.error||"error")}</div>`; }
    else{
      let h=`<div class="dl">escaneo profundo (nmap)</div><div class="kv">SO: <span class="os">${NS.esc(r.os||"desconocido")}</span>${r.os_accuracy?` (${r.os_accuracy}%)`:""}</div>`;
      if(r.ports&&r.ports.length){ h+=r.ports.map(p=>`<div class="port"><span class="p num">${p.port}/${p.proto}</span> <span class="s">${NS.esc(p.service)} ${NS.esc(p.product)} ${NS.esc(p.version)}</span></div>`).join(""); }
      else h+=`<div style="color:var(--faint)">sin puertos abiertos detectados.</div>`;
      box.innerHTML=h;
    }
  }catch(e){ box.innerHTML=`<div style="color:var(--red)">fallo la peticion</div>`; }
  finally{ b.disabled=false; b.textContent="Escaneo profundo"; }
}

// --- LOG: solo agrega lo nuevo, no re-renderiza (no parpadea) ---
async function pollLog(){
  try{
    const d = await NS.get(`/api/log?ip=${encodeURIComponent(IP)}&since=${lastSeq}`);
    const ev = d.events||[];
    if(ev.length){
      const box=document.getElementById("log");
      if(!logStarted){ box.innerHTML=""; logStarted=true; }
      const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
      const frag=document.createDocumentFragment();
      ev.forEach(e=>{
        const row=document.createElement("div"); row.className="row";
        row.innerHTML=`<span class="time num">${NS.hora(e.ts)}</span><span class="kind ${e.kind}">${e.kind}</span><span class="val">${NS.esc(e.value)}</span>`;
        frag.appendChild(row);
      });
      box.appendChild(frag);
      lastSeq = d.latest;
      if(atBottom) box.scrollTop = box.scrollHeight;
    }
  }catch(e){}
}

async function clearLog(){
  await NS.post("/api/log/reset",{ip:IP});
  lastSeq=0; logStarted=false;
  document.getElementById("log").innerHTML=`<div class="log-empty">Log limpiado. Apareceran las nuevas conexiones...</div>`;
}

loadDetail();
setInterval(pollLog, 1500);


async function saveName(){
  const name=document.getElementById("nameInput").value.trim();
  await NS.post("/api/device/"+IP+"/name",{name});
  document.getElementById("dTitle").textContent = name || IP;
}

let blocked=false;
async function refreshBlock(){
  try{ const d=await NS.get("/api/block/status"); blocked=(d.blocked||[]).includes(IP); updateBlockBtn(); }catch(e){}
}
function updateBlockBtn(){
  const b=document.getElementById("blockBtn"); if(!b) return;
  b.textContent = blocked?"Desbloquear":"Bloquear";
  b.classList.toggle("ghost", !blocked);
  b.style.color = blocked?"var(--red)":"";
  b.style.borderColor = blocked?"var(--red)":"";
}
async function toggleBlock(){
  const url = blocked?"/api/block/stop":"/api/block/start";
  const d = await NS.post(url,{ip:IP});
  if(!d.ok){ alert("Bloqueo: "+(d.error||"error")); return; }
  blocked = (d.blocked||[]).includes(IP); updateBlockBtn();
}
refreshBlock();
