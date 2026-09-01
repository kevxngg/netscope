// ---------- utilidades compartidas ----------
const NS = {
  fmt(b){ if(!b) return "0 B"; const u=["B","KB","MB","GB","TB"]; const i=Math.floor(Math.log(b)/Math.log(1024)); return (b/Math.pow(1024,i)).toFixed(i?1:0)+" "+u[i]; },
  esc(s){ return String(s??"").replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); },
  ipNum(ip){ return ip.split(".").map(Number).reduce((s,o)=>s*256+o,0); },
  hora(ts){ const d=new Date(ts*1000); return d.toLocaleTimeString(); },
  deviceIcon(type){
    const body={
      router:'<rect x="3" y="9" width="18" height="9" rx="2"/><path d="M7 9V5m10 4V5M6 14h.01M10 14h.01M14 14h4"/>',
      phone:'<rect x="7" y="2" width="10" height="20" rx="2"/><path d="M10 5h4m-3 14h2"/>',
      tablet:'<rect x="4" y="2" width="16" height="20" rx="2"/><path d="M11 19h2"/>',
      computer:'<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8m-4-4v4"/>',
      camera:'<path d="M4 7h4l2-2h4l2 2h4a2 2 0 0 1 2 2v9H2V9a2 2 0 0 1 2-2Z"/><circle cx="12" cy="13" r="4"/>',
      printer:'<path d="M6 9V3h12v6M6 18H3V9h18v9h-3M6 14h12v7H6z"/><path d="M17 12h1"/>',
      tv:'<rect x="2" y="4" width="20" height="15" rx="2"/><path d="m8 2 4 2 4-2M9 22h6"/>',
      console:'<path d="M7 8h10c2 0 3 2 4 7l1 4c.3 2-2 3-3 1l-3-4H8l-3 4c-1 2-3.3 1-3-1l1-4c1-5 2-7 4-7Z"/><path d="M7 12v4m-2-2h4m8-1h.01m2 2h.01"/>',
      speaker:'<rect x="6" y="2" width="12" height="20" rx="2"/><circle cx="12" cy="8" r="2"/><circle cx="12" cy="16" r="4"/>',
      wearable:'<path d="M9 2h6l1 5v10l-1 5H9l-1-5V7z"/><rect x="8" y="7" width="8" height="10" rx="2"/>',
      network:'<path d="M12 3v6M5 21v-5h14v5M5 16v-3h14v3"/><circle cx="12" cy="3" r="2"/><circle cx="5" cy="21" r="2"/><circle cx="19" cy="21" r="2"/>',
      iot:'<path d="M9 18h6m-5 3h4M8 14c-2-1-3-3-3-5a7 7 0 0 1 14 0c0 2-1 4-3 5-1 1-1 2-1 3H9c0-1 0-2-1-3Z"/>',
      unknown:'<rect x="4" y="4" width="16" height="16" rx="4"/><path d="M9.5 9a2.7 2.7 0 0 1 5 1.5c0 2-2.5 2-2.5 4M12 17h.01"/>'
    };
    return `<svg class="device-svg" viewBox="0 0 24 24" aria-hidden="true">${body[type]||body.unknown}</svg>`;
  },
  deviceProfile(d){
    const labels={router:"Router / gateway",phone:"Celular",tablet:"Tablet",computer:"Computador",camera:"Camara",printer:"Impresora",tv:"TV / streaming",console:"Consola",speaker:"Altavoz",wearable:"Reloj / wearable",network:"Equipo de red",iot:"Dispositivo IoT",unknown:"Dispositivo"};
    const type=d.device_type||"unknown";
    return {type,label:d.device_type_label||labels[type]||labels.unknown,brand:d.brand||d.vendor||""};
  },
  async get(u){ const r=await fetch(u); return r.json(); },
  async post(u,b){ const r=await fetch(u,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(b||{})}); return r.json(); },
};

// ---------- tema claro/oscuro ----------
(function(){
  const saved = localStorage.getItem("ns-theme") || "dark";
  document.documentElement.setAttribute("data-theme", saved);
  const btn = document.getElementById("themeToggle");
  if(btn){ btn.onclick = ()=>{
    const now = document.documentElement.getAttribute("data-theme")==="dark"?"light":"dark";
    document.documentElement.setAttribute("data-theme", now);
    localStorage.setItem("ns-theme", now);
  };}
})();

// ---------- menu movil ----------
(function(){
  const b=document.getElementById("menuBtn"), s=document.getElementById("sidebar"), o=document.getElementById("overlay");
  if(!b) return;
  const toggle=(on)=>{ s.classList.toggle("open",on); o.classList.toggle("open",on); };
  b.onclick=()=>toggle(!s.classList.contains("open"));
  o.onclick=()=>toggle(false);
})();

// ---------- badges del sidebar + pill de estado (comun a todas las paginas) ----------
async function refreshSummary(){
  try{
    const s = await NS.get("/api/summary");
    const set=(k,v)=>{ const el=document.querySelector(`[data-count="${k}"]`); if(el) el.textContent=v; };
    set("devices", s.devices);
    set("traffic", s.traffic_ips);
    const insp=document.querySelector('[data-count="inspecting"]');
    if(insp){ if(s.inspecting && s.inspecting.length){ insp.style.display=""; insp.textContent=s.inspecting.length; } else insp.style.display="none"; }
    const pill=document.getElementById("statusPill"), txt=document.getElementById("statusTxt");
    if(pill){
      if(!s.admin){ pill.classList.add("warn"); txt.textContent="sin privilegios"; }
      else if(s.inspecting && s.inspecting.length){ pill.classList.remove("warn"); txt.textContent=s.inspecting.length+" interceptando"; }
      else { pill.classList.remove("warn"); txt.textContent="en vivo"; }
    }
  }catch(e){}
}
refreshSummary();
setInterval(refreshSummary, 5000);
