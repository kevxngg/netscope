async function load(){
  const s = await NS.get("/api/system");
  const mark=o=>o.ok?'<span class="os">OK</span>':'<span style="color:var(--red)">FALTA</span>';
  let h=`<div class="dl">sistema</div><div>${NS.esc(s.os.name)} &middot; Python ${s.python}</div>
    <div class="dl">permisos</div><div>${s.admin?'<span class="os">administrador / root</span>':'<span style="color:var(--red)">SIN privilegios</span>'}</div>
    <div class="dl">dependencias</div>
    <div>captura: ${mark(s.capture)} <span style="color:var(--muted)">(${NS.esc(s.capture.detail)})</span></div>
    <div>nmap: ${mark(s.nmap)} <span style="color:var(--muted)">(${NS.esc(s.nmap.detail)})</span></div>
    <div>netbios: ${mark(s.netbios)} <span style="color:var(--muted)">(${NS.esc(s.netbios.detail)})</span></div>`;
  const hints=[];
  if(!s.admin) hints.push(s.os.id==="windows"?"Abre PowerShell como Administrador.":"Ejecuta con: sudo python3 app.py");
  ["capture","nmap","netbios"].forEach(k=>{ if(!s[k].ok && s[k].hint) hints.push(NS.esc(s[k].hint)); });
  if(hints.length) h+=`<div class="dl">acciones sugeridas</div>`+hints.map(x=>`<div style="color:var(--amber)">- ${x}</div>`).join("");
  document.getElementById("sys").innerHTML=h;
}
load(); setInterval(load,6000);
