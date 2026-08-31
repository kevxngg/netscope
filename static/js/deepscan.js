let devs=[];

async function loadDevices(){
  try{
    const d=await NS.get("/api/devices");
    devs=(d.devices||[]).filter(x=>x.ip);
    const sel=document.getElementById("deepDevice");
    devs.sort((a,b)=>NS.ipNum(a.ip)-NS.ipNum(b.ip));
    sel.innerHTML='<option value="">— elige un equipo de la red —</option>'+
      devs.map(x=>{
        const name=x.label_manual||x.label||(x.name&&x.name!=="(sin nombre)"?x.name:x.vendor||"equipo");
        return `<option value="${NS.esc(x.ip)}">${NS.esc(name)} · ${NS.esc(x.ip)}</option>`;
      }).join("");
  }catch(e){}
}

document.getElementById("deepDevice").addEventListener("change",e=>{
  const ip=e.target.value; if(ip) document.getElementById("deepIp").value=ip;
});

function renderPorts(ports){
  if(!ports||!ports.length) return '<div style="color:var(--faint)">sin puertos abiertos detectados.</div>';
  return '<div class="deep-ports">'+ports.map(p=>
    `<div class="port"><span class="p num">${NS.esc(String(p.port))}/${NS.esc(p.proto||"")}</span> <span class="s">${NS.esc(p.service||"")} ${NS.esc(p.product||"")} ${NS.esc(p.version||"")}</span></div>`
  ).join("")+'</div>';
}

async function runDeep(){
  const ip=(document.getElementById("deepIp").value||document.getElementById("deepDevice").value||"").trim();
  if(!ip){ alert("Elige un equipo o escribe una IP."); return; }
  const b=document.getElementById("deepBtn"); b.disabled=true; b.textContent="Analizando…";
  const box=document.getElementById("deepResult"), meta=document.getElementById("deepMeta");
  meta.textContent=ip;
  box.innerHTML='<div style="color:var(--amber)"><span class="spinner"></span>analizando '+NS.esc(ip)+'… puede tardar hasta 2 min</div>';
  try{
    const r=await NS.post("/api/deepscan",{ip});
    if(!r.ok){ box.innerHTML=`<div style="color:var(--red)">${NS.esc(r.error||"error")}</div>`; return; }
    const up=r.upnp||{};
    const upRows=[
      ["Sistema (nmap)", r.os||"desconocido", r.os_accuracy?` (${r.os_accuracy}%)`:""],
      ["Fabricante (UPnP)", up.manufacturer||"", ""],
      ["Modelo (UPnP)", up.model_name||up.friendly_name||"", ""],
      ["Nº de modelo", up.model_number||"", ""],
      ["Tipo (UPnP)", up.device_type||"", ""],
    ].filter(x=>x[1]);
    let h='<div class="deep-grid">'+upRows.map(x=>
      `<div><span>${x[0]}</span><b>${NS.esc(String(x[1]))}${x[2]}</b></div>`).join("")+'</div>';
    h+='<div class="dl" style="margin-top:14px">Puertos y servicios</div>'+renderPorts(r.ports);
    box.innerHTML=h;
  }catch(e){ box.innerHTML='<div style="color:var(--red)">falló la petición.</div>'; }
  finally{ b.disabled=false; b.textContent="Analizar"; }
}

loadDevices();
