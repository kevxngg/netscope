const ICON={nuevo:"+",bloqueo:"x"};
async function load(){
  const d=await NS.get("/api/events");
  const el=document.getElementById("events");
  const ev=d.events||[];
  if(!ev.length){ el.innerHTML=`<div class="empty">Sin eventos todavia.</div>`; return; }
  el.innerHTML=ev.map(e=>{
    const t=new Date(e.ts*1000).toLocaleString();
    const color=e.type==="bloqueo"?"var(--red)":"var(--green)";
    const label=e.type==="nuevo"?"Nuevo dispositivo":(e.type==="bloqueo"?"Bloqueo":e.type);
    return `<div style="display:grid;grid-template-columns:150px 160px 1fr;gap:12px;padding:11px 16px;border-bottom:1px solid var(--border-soft)">
      <span style="color:var(--faint);font-size:12.5px">${t}</span>
      <span style="color:${color}">${label}</span>
      <span>${NS.esc(e.detail||"")} <span style="color:var(--green)">${e.ip||""}</span> <span style="color:var(--muted);font-size:12px">${e.mac||""}</span></span>
    </div>`;
  }).join("");
}
load(); setInterval(load,6000);
