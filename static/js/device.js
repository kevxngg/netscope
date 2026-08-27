const IP = window.DEVICE_IP;
let inspecting=false, lastSeq=0, logStarted=false, logEvents=[];

function deviceName(device){ return device.custom_name || (device.name&&device.name!=="(sin nombre)"?device.name:device.ip); }

function renderMetrics(device){
  const metrics=document.getElementById("deviceMetrics");
  if(metrics) metrics.innerHTML=`<div><span>Total</span><b>${NS.fmt(device.traffic||0)}</b></div><div><span>Enviado</span><b>${NS.fmt(device.sent_bytes||0)}</b></div><div><span>Recibido</span><b>${NS.fmt(device.recv_bytes||0)}</b></div>`;
  const state=document.getElementById("deviceState");
  if(state){ state.textContent=device.online?"conectado":"ausente"; state.classList.toggle("online",!!device.online); }
  const presence=document.getElementById("presenceBox");
  if(presence) presence.textContent=device.online?"Activo en el último escaneo":"No respondió al último escaneo";
}

function renderHistory(history){
  const box=document.getElementById("historyBox"), count=document.getElementById("historyCount");
  if(count) count.textContent=history.length+" eventos";
  if(!history.length){ box.innerHTML='<div class="empty">sin eventos registrados para este dispositivo.</div>'; return; }
  box.innerHTML=history.slice(0,10).map(e=>`<div class="history-row"><span class="time num">${NS.hora(e.ts)}</span><span class="history-type">${NS.esc(e.type||"evento")}</span><span>${NS.esc(e.detail||e.ip||"-")}</span></div>`).join("");
}

function renderLog(){
  const filter=document.getElementById("logFilter")?.value||"all";
  const events=filter==="all"?logEvents:logEvents.filter(e=>e.kind===filter);
  const box=document.getElementById("log");
  if(!events.length){ box.innerHTML='<div class="log-empty">sin eventos para este filtro.</div>'; return; }
  box.innerHTML=events.map(e=>`<div class="row"><span class="time num">${NS.hora(e.ts)}</span><span class="kind ${e.kind}">${e.kind}</span><span class="val">${NS.esc(e.value)}</span></div>`).join("");
}

async function loadDetail(){
  const d = await NS.get("/api/device/"+IP);
  if(!d.ok){ document.getElementById("detail").textContent="dispositivo no encontrado (escanea primero)"; return; }
  const dv=d.device; inspecting=d.inspecting;
  const shown = deviceName(dv);
  document.getElementById("dTitle").textContent = shown;
  document.getElementById("identityHint").textContent = dv.trusted?"dispositivo confiable":"pendiente de revisar";
  const ni=document.getElementById("nameInput"); if(ni && !ni.value) ni.value = dv.custom_name || "";
  const ex=document.getElementById("exportLog"); if(ex) ex.href="/api/export/log.csv?ip="+encodeURIComponent(IP);
  document.getElementById("detail").innerHTML =
    `<div class="identity-grid"><div><span>IP</span><b class="os num">${dv.ip}</b></div><div><span>MAC</span><b class="mac num">${NS.esc(dv.mac||"-")}</b></div><div><span>Fabricante</span><b>${NS.esc(dv.vendor||"-")}</b></div><div><span>Interfaz</span><b>${NS.esc(dv.iface||"-")}</b></div><div><span>Visto</span><b>${dv.seen_count||0} veces</b></div><div><span>Estado</span><b>${dv.online?"conectado":"ausente"}</b></div></div>
     <div class="dl">escaneo profundo (nmap)</div><div class="device-note">Detecta sistema operativo, puertos y servicios cuando pulses el botón.</div>
     <div id="deepBox"><div style="color:var(--faint)">pulsa "Escaneo profundo".</div></div>`;
  renderMetrics(dv); renderHistory(d.history||[]);
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
      logEvents=logEvents.concat(ev).slice(-300);
      lastSeq = d.latest;
      renderLog();
    }
  }catch(e){}
}

async function clearLog(){
  await NS.post("/api/log/reset",{ip:IP});
  lastSeq=0; logStarted=false;
  logEvents=[]; renderLog();
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
document.getElementById("logFilter").addEventListener("change",renderLog);
