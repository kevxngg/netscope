let devices=[], gateway="", inspecting=new Set(), enriching=false, everScanned=false;
let searchTerm="", filterMode="all", sortMode="ip";

async function loadStatus(){ try{ const d=await NS.get("/api/inspect/status"); inspecting=new Set(d.targets||[]); }catch(e){} }

async function load(){
  const d = await NS.get("/api/devices");
  devices = (d.devices||[]).slice().sort((a,b)=>NS.ipNum(a.ip)-NS.ipNum(b.ip));
  gateway = d.gateway||"";
  enriching = !!d.enriching;
  const cnt = devices.length+" equipos"+(enriching?" · resolviendo nombres…":"");
  document.getElementById("devCnt").textContent = cnt;
  document.getElementById("scanMeta").textContent = d.ts ? "último escaneo "+NS.hora(d.ts) : "sin escaneo";
  render();
  if(d.error && !devices.length){
    document.getElementById("tree").innerHTML=`<div class="empty error">${NS.esc(d.error)}</div>`;
  }

  // Si al entrar no hay nada escaneado aun, lanza un escaneo automatico.
  if(!everScanned && !devices.length && !enriching){ everScanned=true; scanNow(); }
}

function render(){
  const el=document.getElementById("tree");
  if(!devices.length){
    el.innerHTML=`<div class="empty">${enriching?"escaneando la red…":'sin dispositivos. Pulsa "Escanear red".'}</div>`;
    return;
  }
  const filtered=devices.filter(dv=>{
    const hay=[dv.ip,dv.mac,dv.name,dv.custom_name,dv.vendor].join(" ").toLowerCase();
    const matches=!searchTerm||hay.includes(searchTerm);
    let status=true;
    if(filterMode==="online") status=dv.online;
    else if(filterMode==="offline") status=!dv.online;
    else if(filterMode==="unknown") status=!dv.trusted;
    else if(filterMode==="trusted") status=dv.trusted;
    else if(filterMode==="unnamed") status=!displayName(dv);
    return matches&&status;
  }).sort((a,b)=>{
    if(sortMode==="name") return displayName(a).localeCompare(displayName(b));
    if(sortMode==="traffic") return (b.traffic||0)-(a.traffic||0);
    if(sortMode==="last_seen") return (b.last_seen||0)-(a.last_seen||0);
    if(sortMode==="vendor") return (a.vendor||"").localeCompare(b.vendor||"");
    return NS.ipNum(a.ip||"0.0.0.0")-NS.ipNum(b.ip||"0.0.0.0");
  });
  const gwDev=filtered.find(x=>x.ip===gateway);
  const branches=filtered.filter(x=>x.ip!==gateway);
  let h=`<div class="root">[router] ${gateway||"?"} &nbsp; ${gwDev?NS.esc(gwDev.vendor||""):""}</div>`;
  if(!filtered.length) h+=`<div class="empty">ningún dispositivo coincide con este filtro.</div>`;
  branches.forEach(dv=>{
    const insp=inspecting.has(dv.ip);
    const shown = displayName(dv);
    const nm = shown?NS.esc(shown):`<span style="color:var(--faint)">${enriching?"…":"(sin nombre)"}</span>`;
    const vn = dv.vendor?NS.esc(dv.vendor):(enriching?'<span style="color:var(--faint)">…</span>':"");
    const type=deviceType(dv), traffic=NS.fmt(dv.traffic||0);
    const seen=dv.last_seen?"visto "+new Date(dv.last_seen*1000).toLocaleDateString():"sin historial";
    const trustLabel=dv.trusted?"Marcar como desconocido":"Marcar como confiable";
    h+=`<div class="dev ${dv.online?'':'is-offline'}" onclick="location.href='/device/${dv.ip}'">
      <span class="dev-icon" aria-hidden="true">${type.icon}</span>
      <span class="dev-main"><span class="nm">${nm}${dv.is_self?'<span class="self">este equipo</span>':''}</span><span class="dev-meta"><span class="dev-kind">${type.label}</span><span class="ip num">${dv.ip}</span><span class="mac num">${NS.esc(dv.mac||"-")}</span></span></span>
      <span class="dev-info"><span class="vn">${vn}</span><span class="dev-stats">${dv.online?"conectado":"ausente"} · ${traffic} · ${seen}</span></span>
      <span class="acts">
        ${dv.trusted?'<span class="tag trusted">confiable</span>':'<span class="tag unknown">revisar</span>'}
        ${insp?'<span class="tag on">interceptando</span>':''}
        <button class="icon-action" title="${trustLabel}" onclick="toggleTrust(event,'${dv.ip}',${!dv.trusted})">${dv.trusted?'✓':'!'}</button>
        <button class="icon-action" title="${insp?'Detener inspección':'Inspeccionar dispositivo'}" onclick="toggleInspectDevice(event,'${dv.ip}')">${insp?'■':'◉'}</button>
        <button class="icon-action" title="Abrir detalle" onclick="event.stopPropagation();location.href='/device/${dv.ip}'">→</button>
      </span>
    </div>`;
  });
  el.innerHTML=h;
}

async function toggleTrust(event,ip,trusted){
  event.stopPropagation();
  const result=await NS.post(`/api/device/${encodeURIComponent(ip)}/trust`,{trusted});
  if(result.ok) await load();
}

async function toggleInspectDevice(event,ip){
  event.stopPropagation();
  const active=inspecting.has(ip), url=active?"/api/inspect/stop":"/api/inspect/start";
  const result=await NS.post(url,{ip});
  if(result.ok){ inspecting=new Set(result.inspecting||[]); render(); }
}

function displayName(device){ return device.custom_name || (device.name&&device.name!=="(sin nombre)"?device.name:""); }
function deviceType(device){
  const value=(displayName(device)+" "+(device.vendor||"")).toLowerCase();
  if(/camera|camara|cctv|ipcam|hikvision|dahua|wyze|arlo|ring|reolink|nest cam/.test(value)) return {icon:"▥",label:"Cámara"};
  if(/router|gateway|ubiquiti|tp-link|cisco|netgear|hitron|arris/.test(value)) return {icon:"⌁",label:"Router"};
  if(/iphone|android|samsung|xiaomi|huawei|pixel|phone|mobile|galaxy/.test(value)) return {icon:"◉",label:"Celular"};
  if(/printer|impresora|epson|canon|brother|hp /.test(value)) return {icon:"▣",label:"Impresora"};
  if(/tv|roku|chromecast|playstation|xbox|firestick/.test(value)) return {icon:"▤",label:"TV / consola"};
  if(/laptop|notebook|desktop|computer|computador|pc|windows|linux|macbook|intel|dell|lenovo|asus|acer|apple/.test(value)) return {icon:"◇",label:"Computador"};
  return {icon:"◇",label:"Dispositivo"};
}

function updateDeviceView(){ render(); }

async function scanNow(){
  const b=document.getElementById("scanBtn"); b.disabled=true; b.textContent="Escaneando…";
  try{
    const result=await NS.post("/api/scan");
    if(!result.ok) throw new Error(result.error||"no se pudo escanear la red");
    await load();
  }catch(e){
    document.getElementById("tree").innerHTML=`<div class="empty error">${NS.esc(e.message||"fallo la peticion")}</div>`;
  }
  finally{ b.disabled=false; b.textContent="Escanear red"; }
}

loadStatus().then(load);
// Refresco: rapido mientras se resuelven nombres, tranquilo cuando ya termino.
setInterval(async()=>{ try{ await loadStatus(); await load(); }catch(e){} }, 2500);

document.getElementById("deviceSearch").addEventListener("input",e=>{searchTerm=e.target.value.toLowerCase().trim();updateDeviceView();});
document.getElementById("deviceFilter").addEventListener("change",e=>{filterMode=e.target.value;updateDeviceView();});
document.getElementById("deviceSort").addEventListener("change",e=>{sortMode=e.target.value;updateDeviceView();});
