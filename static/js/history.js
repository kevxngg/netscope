async function load(){
  const d=await NS.get("/api/events");
  const el=document.getElementById("events");
  const ev=d.events||[];
  if(!ev.length){ el.innerHTML=`<div class="empty">Sin eventos todavia.</div>`; return; }
  el.innerHTML=ev.map(e=>{
    const t=new Date(e.ts*1000).toLocaleString();
    const color=e.type==="bloqueo"?"var(--red)":(e.type==="nuevo"?"var(--green)":"var(--muted)");
    const label=e.type==="nuevo"?"Nuevo dispositivo":(e.type==="bloqueo"?"Bloqueo":e.type);
    const who=e.label?`<span style="color:var(--green)">${NS.esc(e.label)}</span> `:"";
    const link=e.identity_id?` <a href="/device/${e.identity_id}" style="color:var(--faint);font-size:12px">ver ficha</a>`:"";
    return `<div style="display:grid;grid-template-columns:170px 150px 1fr;gap:12px;padding:11px 16px;border-bottom:1px solid var(--border-soft)">
      <span style="color:var(--faint);font-size:12.5px">${t}</span>
      <span style="color:${color}">${label}</span>
      <span>${who}${NS.esc(e.detail||"")}${link}</span>
    </div>`;
  }).join("");
}
load(); setInterval(load,6000);
