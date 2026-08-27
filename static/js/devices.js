let devices=[], gateway="", inspecting=new Set(), enriching=false, everScanned=false;

async function loadStatus(){ try{ const d=await NS.get("/api/inspect/status"); inspecting=new Set(d.targets||[]); }catch(e){} }

async function load(){
  const d = await NS.get("/api/devices");
  devices = (d.devices||[]).slice().sort((a,b)=>NS.ipNum(a.ip)-NS.ipNum(b.ip));
  gateway = d.gateway||"";
  enriching = !!d.enriching;
  const cnt = devices.length+" equipos"+(enriching?" · resolviendo nombres…":"");
  document.getElementById("devCnt").textContent = cnt;
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
  const gwDev=devices.find(x=>x.ip===gateway);
  const branches=devices.filter(x=>x.ip!==gateway);
  let h=`<div class="root">[router] ${gateway||"?"} &nbsp; ${gwDev?NS.esc(gwDev.vendor||""):""}</div>`;
  branches.forEach(dv=>{
    const insp=inspecting.has(dv.ip);
    const shown = dv.custom_name || (dv.name && dv.name!=="(sin nombre)" ? dv.name : "");
    const nm = shown?NS.esc(shown):`<span style="color:var(--faint)">${enriching?"…":"(sin nombre)"}</span>`;
    const vn = dv.vendor?NS.esc(dv.vendor):(enriching?'<span style="color:var(--faint)">…</span>':"");
    h+=`<div class="dev" onclick="location.href='/device/${dv.ip}'">
      <span class="ip num">${dv.ip}</span>
      <span class="nm">${nm}${dv.is_self?'<span class="self">este equipo</span>':''}</span>
      <span class="vn">${vn}</span>
      <span class="acts">
        ${insp?'<span class="tag on">interceptando</span>':''}
        <span class="tag">ver detalle &rarr;</span>
      </span>
    </div>`;
  });
  el.innerHTML=h;
}

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
