let nets=[], scanning=false, autoTimer=null, expanded=new Set();
let term="", band="all", sortMode="signal";

function bandClass(b){ if(!b) return ""; if(b.includes("2.4")) return "b24"; if(b.includes("6")) return "b6"; return "b5"; }
function sigColor(p){ if(p==null) return "var(--faint)"; if(p>=66) return "var(--green)"; if(p>=33) return "var(--amber)"; return "var(--red)"; }

function ago(ts){
  if(!ts) return "-";
  const s=Math.max(0,Math.floor(Date.now()/1000-ts));
  if(s<60) return s+"s";
  if(s<3600) return Math.floor(s/60)+"m";
  if(s<86400) return Math.floor(s/3600)+"h";
  return Math.floor(s/86400)+"d";
}

async function scanWifi(){
  if(scanning) return; scanning=true;
  const b=document.getElementById("scanWifiBtn"); b.disabled=true; b.textContent="Escaneando…";
  try{
    const d=await NS.get("/api/wifi/scan");
    if(!d.ok){ renderError(d); return; }
    nets=d.networks||[];
    render();
  }catch(e){ renderError({detail:"No se pudo escanear (¿la app corre como administrador?)."}); }
  finally{ scanning=false; b.disabled=false; b.textContent="Escanear"; }
}

function renderError(d){
  const box=document.getElementById("wifiList");
  document.getElementById("wifiCount").textContent="0 redes";
  const loc = d.error==="location";
  box.innerHTML=`<div class="wifi-error">
    <b>${loc?"Windows bloquea el escaneo (falta ubicación)":"No se pudo escanear"}</b>
    <p>${NS.esc(d.detail||"Error desconocido.")}</p>
    ${loc?'<p class="wifi-hint">Abre <b>Configuración → Privacidad y seguridad → Ubicación</b> y actívala; luego pulsa <b>Escanear</b> otra vez. Si esa opción aparece <b>administrada por tu organización</b>, tu empresa la tiene bloqueada por política y el escaneo no es posible en este equipo (usa un equipo personal donde controles la ubicación).</p>':''}
  </div>`;
}

function render(){
  const box=document.getElementById("wifiList");
  document.getElementById("wifiCount").textContent = nets.length+" redes";
  let list=nets.filter(n=>{
    const hay=(n.ssid+" "+n.bssid).toLowerCase();
    if(term && !hay.includes(term)) return false;
    if(band!=="all" && !(n.band||"").includes(band)) return false;
    return true;
  });
  list.sort((a,b)=>{
    if(sortMode==="ssid") return (a.ssid||"~").localeCompare(b.ssid||"~");
    if(sortMode==="channel") return (parseInt(a.channel)||999)-(parseInt(b.channel)||999);
    if(sortMode==="last") return (b.last_seen||0)-(a.last_seen||0);
    return (b.signal_pct||0)-(a.signal_pct||0);
  });
  if(!list.length){ box.innerHTML='<div class="empty">Ninguna red coincide (o aún no has escaneado).</div>'; return; }
  box.innerHTML=list.map(n=>{
    const name=n.ssid?NS.esc(n.ssid):'<span style="color:var(--faint)">(oculta)</span>';
    const key=n.bssid, open=expanded.has(key);
    const sig=n.signal_pct;
    const secBadge=n.open?'<span class="wtag open">abierta</span>':'<span class="wtag sec">con clave</span>';
    const bandBadge=n.band?`<span class="wtag ${bandClass(n.band)}">${NS.esc(n.band)}</span>`:'';
    const mineBadge=n.is_current?'<span class="wtag mine">tu red</span>':'';
    const vendor=n.vendor?` · <span class="wifi-vn">${NS.esc(n.vendor)}</span>`:'';
    return `<div class="wifi-card ${open?'open':''} ${n.is_current?'mine':''}">
      <div class="wifi-row" onclick="toggle('${key}')">
        <span class="wifi-sig" title="${sig==null?'?':sig+'%'}"><i style="height:${Math.max(6,(sig||0)*0.34)}px;background:${sigColor(sig)}"></i></span>
        <span class="wifi-main">
          <span class="wifi-name">${name}${mineBadge}${secBadge}${bandBadge}</span>
          <span class="wifi-sub"><span class="mac num">${NS.esc(n.bssid)}</span>${vendor} · canal ${NS.esc(String(n.channel||'?'))}${n.freq_mhz?` · ${n.freq_mhz} MHz`:''}</span>
        </span>
        <span class="wifi-sigpct num" style="color:${sigColor(sig)}">${sig==null?'—':sig+'%'}</span>
      </div>
      ${open?detail(n):''}
    </div>`;
  }).join("");
}

function detail(n){
  const rows=[
    ["SSID (nombre)", n.ssid||"(oculta)"],
    ["BSSID (MAC)", n.bssid],
    ["Fabricante (router)", n.vendor||"—"],
    ["¿Tu red?", n.is_current?"Sí, estás conectado aquí":"No"],
    ["Banda", n.band||"—"],
    ["Canal", n.channel||"—"],
    ["Frecuencia", n.freq_mhz?n.freq_mhz+" MHz":"—"],
    ["Señal", n.signal_pct!=null?n.signal_pct+" %":"—"],
    ["Tipo de radio", n.radio||"—"],
    ["Seguridad", n.open?"Abierta (sin clave)":(n.security||"cifrada")],
    ["Cifrado", n.encryption||"—"],
    ["Tipo de red", n.net_type||"—"],
    ["Primera vez", n.first_seen?new Date(n.first_seen*1000).toLocaleString():"—"],
    ["Visto hace", ago(n.last_seen)],
    ["WPS", '<span class="na">no disponible en Windows</span>'],
    ["Beacon interval", '<span class="na">requiere modo monitor</span>'],
    ["TSF", '<span class="na">requiere modo monitor</span>'],
  ];
  return `<div class="wifi-detail">`+rows.map(r=>
    `<div><span>${r[0]}</span><b>${r[1].toString().startsWith('<')?r[1]:NS.esc(String(r[1]))}</b></div>`).join("")+`</div>`;
}

function toggle(key){ if(expanded.has(key)) expanded.delete(key); else expanded.add(key); render(); }

document.getElementById("autoScan").addEventListener("change",e=>{
  if(e.target.checked){ scanWifi(); autoTimer=setInterval(scanWifi,10000); }
  else if(autoTimer){ clearInterval(autoTimer); autoTimer=null; }
});
document.getElementById("wifiSearch").addEventListener("input",e=>{term=e.target.value.toLowerCase().trim();render();});
document.getElementById("wifiBand").addEventListener("change",e=>{band=e.target.value;render();});
document.getElementById("wifiSort").addEventListener("change",e=>{sortMode=e.target.value;render();});

scanWifi();
