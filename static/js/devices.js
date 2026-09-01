let devices=[], gateway="", inspecting=new Set(), enriching=false, everScanned=false;
let searchTerm="", filterMode="all", sortMode="ip";

async function loadStatus(){ try{ const d=await NS.get("/api/inspect/status"); inspecting=new Set(d.targets||[]); }catch(e){} }

async function load(){
  const d = await NS.get("/api/devices");
  devices = (d.devices||[]).slice().sort((a,b)=>NS.ipNum(a.ip||"255.255.255.255")-NS.ipNum(b.ip||"255.255.255.255"));
  gateway = d.gateway||"";
  enriching = !!d.enriching;
  const cnt = devices.length+" equipos"+(enriching?" · resolviendo nombres…":"");
  document.getElementById("devCnt").textContent = cnt;
  document.getElementById("scanMeta").textContent = d.ts ? "último escaneo "+NS.hora(d.ts) : "sin escaneo";
  render();
  if(d.error && !devices.length){
    document.getElementById("tree").innerHTML=`<div class="empty error">${NS.esc(d.error)}</div>`;
  }
  if(!everScanned && !devices.length && !enriching){ everScanned=true; scanNow(); }
}

function displayName(dv){ return dv.label_manual || dv.label || (dv.name&&dv.name!=="(sin nombre)"?dv.name:""); }

function confBadge(dv){
  if(dv.identity_id==null) return "";
  const c=dv.confidence||0;
  const [txt,cls]=c>=0.75?["alta","hi"]:c>=0.4?["media","mid"]:["baja","lo"];
  return `<span class="conf ${cls}" title="confianza de identidad ${(c*100).toFixed(0)}%">${txt}</span>`;
}

function render(){
  const el=document.getElementById("tree");
  if(!devices.length){
    el.innerHTML=`<div class="empty">${enriching?"escaneando la red…":'sin dispositivos. Pulsa "Escanear red".'}</div>`;
    return;
  }
  const filtered=devices.filter(dv=>{
    const hay=[dv.ip,dv.mac,dv.name,dv.label,dv.label_manual,dv.vendor,dv.brand,dv.device_type_label].join(" ").toLowerCase();
    const matches=!searchTerm||hay.includes(searchTerm);
    let status=true;
    if(filterMode==="online") status=dv.online;
    else if(filterMode==="offline") status=!dv.online;
    else if(filterMode==="unknown") status=!dv.trusted;
    else if(filterMode==="trusted") status=dv.trusted;
    else if(filterMode==="unnamed") status=!displayName(dv);
    else if(filterMode.startsWith("type:")) status=dv.device_type===filterMode.slice(5);
    return matches&&status;
  }).sort((a,b)=>{
    if(sortMode==="name") return displayName(a).localeCompare(displayName(b));
    if(sortMode==="traffic") return (b.traffic||0)-(a.traffic||0);
    if(sortMode==="last_seen") return (b.last_seen||0)-(a.last_seen||0);
    if(sortMode==="vendor") return (a.vendor||"").localeCompare(b.vendor||"");
    return NS.ipNum(a.ip||"255.255.255.255")-NS.ipNum(b.ip||"255.255.255.255");
  });
  const gwDev=filtered.find(x=>x.ip===gateway);
  const branches=filtered.filter(x=>x.ip!==gateway);
  let h=`<div class="root"><span class="root-icon">${NS.deviceIcon("router")}</span><span>Router ${NS.esc(gateway||"?")}${gwDev&&gwDev.brand?` · ${NS.esc(gwDev.brand)}`:""}</span></div>`;
  if(!filtered.length) h+=`<div class="empty">ningún dispositivo coincide con este filtro.</div>`;
  branches.forEach(dv=>{
    const hasId = dv.identity_id!=null;
    const href = hasId?`/device/${dv.identity_id}`:null;
    const insp=dv.online&&dv.ip&&inspecting.has(dv.ip);
    const shown = displayName(dv);
    const nm = shown?NS.esc(shown):`<span style="color:var(--faint)">${enriching||!hasId?"…":"(sin nombre)"}</span>`;
    const vn = dv.vendor?NS.esc(dv.vendor):(enriching?'<span style="color:var(--faint)">…</span>':"");
    const type=NS.deviceProfile(dv), traffic=NS.fmt(dv.traffic||0);
    const seen=dv.last_seen?"visto "+new Date(dv.last_seen*1000).toLocaleDateString():"sin historial";
    const trustLabel=dv.trusted?"Marcar como desconocido":"Marcar como confiable";
    h+=`<div class="dev ${dv.online?'':'is-offline'}" ${href?`onclick="location.href='${href}'"`:''} style="${href?'':'cursor:default'}">
      <span class="dev-icon type-${type.type}" aria-hidden="true">${NS.deviceIcon(type.type)}</span>
      <span class="dev-main"><span class="nm">${nm}${dv.is_self?'<span class="self">este equipo</span>':''}${confBadge(dv)}</span><span class="dev-meta"><span class="dev-kind">${NS.esc(type.label)}</span>${type.brand?`<span class="brand-badge">${NS.esc(type.brand)}</span>`:""}<span class="ip num">${NS.esc(dv.ip||"—")}</span><span class="mac num">${NS.esc(dv.mac||"-")}</span></span></span>
      <span class="dev-info"><span class="vn">${vn}</span><span class="dev-stats">${dv.online?"conectado":"ausente"} · ${traffic} · ${seen}</span></span>
      <span class="acts">
        ${dv.trusted?'<span class="tag trusted">confiable</span>':'<span class="tag unknown">revisar</span>'}
        ${insp?'<span class="tag on">interceptando</span>':''}
        ${hasId?`<button class="icon-action" title="${trustLabel}" onclick="toggleTrust(event,${dv.identity_id},${!dv.trusted})">${dv.trusted?'✓':'!'}</button>`:''}
        ${hasId&&dv.online?`<button class="icon-action" title="${insp?'Detener inspección':'Inspeccionar dispositivo'}" onclick="toggleInspectDevice(event,${dv.identity_id},'${dv.ip}')">${insp?'■':'◉'}</button>`:''}
        ${href?`<button class="icon-action" title="Abrir detalle" onclick="event.stopPropagation();location.href='${href}'">→</button>`:''}
      </span>
    </div>`;
  });
  el.innerHTML=h;
}

async function toggleTrust(event,identity_id,trusted){
  event.stopPropagation();
  const result=await NS.post(`/api/device/${identity_id}/trust`,{trusted});
  if(result.ok) await load();
}

async function toggleInspectDevice(event,identity_id,ip){
  event.stopPropagation();
  const active=ip&&inspecting.has(ip), url=active?"/api/inspect/stop":"/api/inspect/start";
  const result=await NS.post(url,{identity_id,ip});
  if(result.ok){ inspecting=new Set(result.inspecting||[]); render(); }
  else alert("Intercepción: "+(result.error||"error"));
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
setInterval(async()=>{ try{ await loadStatus(); await load(); }catch(e){} }, 2500);

document.getElementById("deviceSearch").addEventListener("input",e=>{searchTerm=e.target.value.toLowerCase().trim();updateDeviceView();});
document.getElementById("deviceFilter").addEventListener("change",e=>{filterMode=e.target.value;updateDeviceView();});
document.getElementById("deviceSort").addEventListener("change",e=>{sortMode=e.target.value;updateDeviceView();});
