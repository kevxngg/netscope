async function load(){
  const s = await NS.get("/api/summary");
  document.getElementById("sDevices").textContent = s.devices;
  document.getElementById("sTraffic").textContent = s.traffic_ips;
  document.getElementById("sInspect").textContent = (s.inspecting||[]).length;
  document.getElementById("sNmap").textContent = s.nmap ? "OK" : "falta";
  document.getElementById("sGateway").textContent = s.gateway || "desconocido";
  const sys = await NS.get("/api/system");
  const mark = o => o.ok ? "OK" : "falta";
  document.getElementById("sysBox").innerHTML =
    `${NS.esc(sys.os.name)} &middot; Python ${sys.python}<br>`+
    `permisos: <span class="os">${sys.admin?"admin/root":"SIN privilegios"}</span> &middot; `+
    `captura: ${mark(sys.capture)} &middot; nmap: ${mark(sys.nmap)}`;
}
load(); setInterval(load, 6000);

async function loadWifi(){
  try{
    const w = await NS.get("/api/wifi");
    const box=document.getElementById("wifiBox"), st=document.getElementById("wifiState");
    if(!w || !w.connected){ st.textContent="sin conexion Wi-Fi"; box.innerHTML='<div class="v" style="color:var(--faint)">No se detecto una red Wi-Fi (quiza estas por cable).</div>'; return; }
    st.textContent="conectado";
    const cell=(k,v)=> v?`<div><div class="k">${k}</div><div class="v">${NS.esc(v)}</div></div>`:"";
    box.innerHTML =
      `<div style="grid-column:1/-1"><div class="k">Red (SSID)</div><div class="wifi-ssid">${NS.esc(w.ssid||"-")}</div></div>`+
      cell("Senal", w.signal)+cell("Canal", w.channel)+cell("Banda", w.band)+
      cell("Tipo", w.radio)+cell("Seguridad", w.security)+
      cell("Rx", w.rx?w.rx+" Mbps":"")+cell("Tx", w.tx?w.tx+" Mbps":"")+
      cell("BSSID", w.bssid);
  }catch(e){
    const box=document.getElementById("wifiBox"), st=document.getElementById("wifiState");
    if(st) st.textContent="no disponible";
    if(box) box.innerHTML='<div class="v" style="color:var(--faint)">No se pudo obtener la info Wi-Fi en este equipo.</div>';
  }
}
loadWifi(); setInterval(loadWifi, 20000);
