const ID = window.DEVICE_ID;
let inspecting=false, lastSeq=0, logEvents=[], flowRows=[], currentIP="", online=false;

const SIGNAL_LABEL={mac:"MAC de fábrica",mac_random:"MAC aleatoria",hostname:"nombre de red",
  dhcp_fp:"huella DHCP",os:"sistema operativo",port_set:"puertos abiertos",schedule:"patrón horario"};

function deviceName(d){ return d.label_manual || d.label || (d.name&&d.name!=="(sin nombre)"?d.name:"equipo #"+ID); }

function renderMetrics(d){
  const m=document.getElementById("deviceMetrics");
  if(m) m.innerHTML=`<div><span>Total</span><b>${NS.fmt(d.traffic||0)}</b></div><div><span>Enviado</span><b>${NS.fmt(d.sent_bytes||0)}</b></div><div><span>Recibido</span><b>${NS.fmt(d.recv_bytes||0)}</b></div>`;
  const st=document.getElementById("deviceState");
  if(st){ st.textContent=d.online?"conectado":"ausente"; st.classList.toggle("online",!!d.online); }
  const p=document.getElementById("presenceBox");
  if(p) p.textContent=d.online?"Activo en el último escaneo":"No respondió al último escaneo";
}

function renderSignals(signals,d){
  const box=document.getElementById("signalsBox");
  const hint=document.getElementById("signalsHint");
  if(hint) hint.textContent=`confianza ${(Math.round((d.confidence||0)*100))}%`;
  if(!signals||!signals.length){ box.innerHTML='<div style="color:var(--faint)">sin señales todavía (escanea la red).</div>'; return; }
  const order={mac:0,hostname:1,dhcp_fp:2,os:3,port_set:4,mac_random:5,schedule:6};
  signals.sort((a,b)=>(order[a.kind]??9)-(order[b.kind]??9));
  box.innerHTML=signals.map(s=>{
    const w=Math.round((s.weight||0)*100);
    return `<div class="sig-row"><span class="sig-kind">${SIGNAL_LABEL[s.kind]||s.kind}</span><span class="sig-val num">${NS.esc(String(s.value))}</span><span class="sig-w" title="peso">${w>0?w+"%":""}</span></div>`;
  }).join("");
}

function renderHistory(history){
  const box=document.getElementById("historyBox"), count=document.getElementById("historyCount");
  if(count) count.textContent=history.length+" eventos";
  if(!history.length){ box.innerHTML='<div class="empty">sin eventos registrados para este dispositivo.</div>'; return; }
  box.innerHTML=history.slice(0,12).map(e=>`<div class="history-row"><span class="time num">${NS.hora(e.ts)}</span><span class="history-type">${NS.esc(e.type||"evento")}</span><span>${NS.esc(e.detail||"-")}</span></div>`).join("");
}

async function loadHistTraffic(){
  const box=document.getElementById("histTraffic"); if(!box) return;
  try{
    const d=await NS.get(`/api/history/traffic?identity_id=${ID}&days=7`);
    const days=(d.daily||[]);
    if(!days.length){ box.innerHTML=""; return; }
    const max=Math.max(...days.map(x=>x.bytes_in+x.bytes_out),1);
    box.innerHTML=`<div class="hist-title">tráfico últimos 7 días</div><div class="hist-bars">`+
      days.map(x=>{ const tot=x.bytes_in+x.bytes_out; const h=Math.max(3,(tot/max)*46);
        const day=new Date(x.day_ts*1000).toLocaleDateString(undefined,{weekday:"short"});
        return `<div class="hist-bar" title="${day}: ${NS.fmt(tot)}"><i style="height:${h}px"></i><span>${day}</span></div>`;
      }).join("")+`</div>`;
  }catch(e){ box.innerHTML=""; }
}

async function loadDetail(){
  const d = await NS.get("/api/device/"+ID);
  if(!d.ok){ document.getElementById("detail").textContent="identidad no encontrada"; return; }
  const dv=d.device; inspecting=d.inspecting; currentIP=dv.ip||""; online=!!dv.online;
  const profile=NS.deviceProfile(dv);
  document.getElementById("dTitle").textContent = deviceName(dv);
  document.getElementById("deviceHeroIcon").innerHTML=NS.deviceIcon(profile.type);
  document.getElementById("identityHint").textContent = `${profile.label}${profile.brand?" · "+profile.brand:""} · ${dv.trusted?"confiable":"por revisar"}`;
  const ni=document.getElementById("nameInput"); if(ni && !ni.value) ni.value = dv.label_manual || "";
  const ex=document.getElementById("exportLog"); if(ex) ex.href="/api/export/log.csv?ip="+encodeURIComponent(currentIP);
  const firstSeen=dv.first_seen?new Date(dv.first_seen*1000).toLocaleDateString():"-";
  document.getElementById("detail").innerHTML =
    `<div class="identity-grid"><div><span>IP actual</span><b class="os num">${dv.ip||"— (ausente)"}</b></div><div><span>MAC</span><b class="mac num">${NS.esc(dv.mac||"-")}</b></div><div><span>Fabricante</span><b>${NS.esc(dv.vendor||"-")}</b></div><div><span>Interfaz</span><b>${NS.esc(dv.iface||"-")}</b></div><div><span>Primera vez</span><b>${firstSeen}</b></div><div><span>Estado</span><b>${dv.online?"conectado":"ausente"}</b></div></div>`;
  renderMetrics(dv); renderSignals(d.signals||[], dv); renderHistory(d.history||[]);
  flowRows=d.flows||[]; renderFlows();
  renderFingerprint(d.fingerprint||{}, dv);
  loadHistTraffic();
  updateInspectBtn(); refreshBlock();
}

function renderFingerprint(fp,d){
  const box=document.getElementById("fingerprintBox"); if(!box) return;
  const hint=document.getElementById("fpHint");
  const rows=[
    ["Modelo", fp.model],
    ["Sistema", fp.os],
    ["Tipo", fp.device_type],
    ["Fabricante (real)", fp.manufacturer],
    ["Fabricante (OUI)", fp.vendor||d.vendor],
    ["Nombre UPnP", fp.friendly_name],
    ["Nº de modelo", fp.model_number],
  ].filter(r=>r[1]);
  if(hint) hint.textContent = fp.model || fp.os || (fp.vendor||d.vendor) || "sin datos";
  if(!rows.length){
    box.innerHTML='<div style="color:var(--faint)">Aún sin datos extra. Usa <b><a href="/deepscan" style="color:var(--green)">Escaneo profundo</a></b> (SO + UPnP) o <b>Inspecciona</b> el equipo para capturar su User-Agent (modelo exacto).</div>';
    return;
  }
  let h=`<div class="identity-grid">`+rows.map(r=>
    `<div><span>${NS.esc(r[0])}</span><b>${NS.esc(String(r[1]))}</b></div>`).join("")+`</div>`;
  if(fp.user_agent){
    h+=`<div class="dl" style="margin-top:10px">User-Agent capturado</div>`+
       `<div class="device-note num" style="word-break:break-all">${NS.esc(fp.user_agent)}</div>`;
  }
  box.innerHTML=h;
}

function updateInspectBtn(){
  const b=document.getElementById("inspectBtn"); if(!b) return;
  b.disabled = !online && !inspecting;
  b.textContent = inspecting?"Detener intercepcion":(online?"Inspeccionar":"Inspeccionar (ausente)");
  b.classList.toggle("primary", inspecting);
}

async function toggleInspect(){
  const wasInspecting=inspecting;
  const url = inspecting?"/api/inspect/stop":"/api/inspect/start";
  const d = await NS.post(url,{identity_id:ID, ip:currentIP});
  if(!d.ok){ alert("Intercepcion: "+(d.error||"error")); return; }
  inspecting = (d.inspecting||[]).includes(currentIP);
  if(!wasInspecting&&inspecting){ lastSeq=0; logEvents=[]; flowRows=[]; renderLog(); renderFlows(); }
  updateInspectBtn();
}


async function pollLog(){
  if(!currentIP) return;
  try{
    const d = await NS.get(`/api/log?ip=${encodeURIComponent(currentIP)}&since=${lastSeq}`);
    const ev = d.events||[];
    if(ev.length){ logEvents=logEvents.concat(ev).slice(-300); lastSeq=d.latest; renderLog(); }
    flowRows=d.flows||[]; renderFlows(d.capture_running,d.capture_iface,d.capture_error);
  }catch(e){}
}

function renderFlows(captureRunning=true,captureIface="",captureError=""){
  const box=document.getElementById("flowList"), hint=document.getElementById("flowHint");
  if(!box) return;
  if(hint) hint.textContent=inspecting?(captureError?"error de captura":captureRunning?`capturando${captureIface?" en "+captureIface:""}`:"captura no disponible"):(flowRows.length?"ultima sesion":"activa Inspeccionar");
  if(!currentIP){ box.innerHTML='<div class="empty">El dispositivo esta ausente.</div>'; return; }
  if(!flowRows.length){
    const message=captureError?`Captura detenida: ${NS.esc(captureError)}. Comprueba Npcap y ejecuta NetScope como administrador.`:inspecting?'Esperando trafico. Abre una app o pagina desde el dispositivo.':'Activa "Inspeccionar" y genera trafico desde el dispositivo.';
    box.innerHTML=`<div class="empty">${message}</div>`;
    return;
  }
  box.innerHTML=[...flowRows].sort((a,b)=>(b.last_seen||0)-(a.last_seen||0)).map(flow=>{
    const peer=flow.peer_host||flow.peer_ip||"-";
    const endpoint=flow.port?`${peer}:${flow.port}`:peer;
    const scope=flow.peer_local?'<span class="flow-scope local">LAN</span>':'<span class="flow-scope">Internet</span>';
    return `<div class="flow-row"><span class="flow-peer"><b>${NS.esc(endpoint)}</b>${scope}${flow.peer_host?`<small class="num">${NS.esc(flow.peer_ip)}</small>`:""}</span><span class="flow-proto">${NS.esc(flow.proto)}</span><span class="flow-up num">${NS.fmt(flow.sent_bytes)}</span><span class="flow-down num">${NS.fmt(flow.recv_bytes)}</span><span class="num">${flow.packets||0}</span><span class="num">${NS.hora(flow.last_seen)}</span></div>`;
  }).join("");
}

function renderLog(){
  const filter=document.getElementById("logFilter")?.value||"all";
  const events=filter==="all"?logEvents:logEvents.filter(e=>e.kind===filter);
  const box=document.getElementById("log");
  if(!currentIP){ box.innerHTML='<div class="log-empty">Equipo ausente: sin captura en vivo.</div>'; return; }
  if(!events.length){ box.innerHTML='<div class="log-empty">Activa "Inspeccionar" para capturar a dónde habla este equipo.</div>'; return; }
  box.innerHTML=[...events].reverse().map(e=>`<div class="row"><span class="time num">${NS.hora(e.ts)}</span><span class="kind ${e.kind}">${e.kind}</span><span class="val">${NS.esc(e.value)}</span></div>`).join("");
}

async function clearLog(){
  if(currentIP) await NS.post("/api/log/reset",{ip:currentIP});
  lastSeq=0; logEvents=[]; flowRows=[]; renderLog(); renderFlows();
}

async function saveName(){
  const name=document.getElementById("nameInput").value.trim();
  await NS.post("/api/device/"+ID+"/name",{name});
  document.getElementById("dTitle").textContent = name || ("equipo #"+ID);
}

let blocked=false;
async function refreshBlock(){
  try{ const d=await NS.get("/api/block/status"); blocked=(d.blocked||[]).includes(currentIP); updateBlockBtn(); }catch(e){}
}
function updateBlockBtn(){
  const b=document.getElementById("blockBtn"); if(!b) return;
  b.disabled = !online && !blocked;
  b.textContent = blocked?"Desbloquear":"Bloquear";
  b.classList.toggle("ghost", !blocked);
  b.style.color = blocked?"var(--red)":"";
  b.style.borderColor = blocked?"var(--red)":"";
}
async function toggleBlock(){
  const url = blocked?"/api/block/stop":"/api/block/start";
  const d = await NS.post(url,{identity_id:ID, ip:currentIP});
  if(!d.ok){ alert("Bloqueo: "+(d.error||"error")); return; }
  if(!blocked&&d.warning) alert("Bloqueo activo. "+d.warning);
  blocked = (d.blocked||[]).includes(currentIP); updateBlockBtn();
}

loadDetail();
setInterval(loadDetail, 6000);
setInterval(pollLog, 1500);
document.getElementById("logFilter").addEventListener("change",renderLog);
