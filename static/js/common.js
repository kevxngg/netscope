// ---------- utilidades compartidas ----------
const NS = {
  fmt(b){ if(!b) return "0 B"; const u=["B","KB","MB","GB","TB"]; const i=Math.floor(Math.log(b)/Math.log(1024)); return (b/Math.pow(1024,i)).toFixed(i?1:0)+" "+u[i]; },
  esc(s){ return (s||"").replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); },
  ipNum(ip){ return ip.split(".").map(Number).reduce((s,o)=>s*256+o,0); },
  hora(ts){ const d=new Date(ts*1000); return d.toLocaleTimeString(); },
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
