async function load(){
  const s = await NS.get("/api/summary");
  document.getElementById("sDevices").textContent = s.devices;
  document.getElementById("sTraffic").textContent = s.traffic_ips;
  document.getElementById("sInspect").textContent = (s.inspecting||[]).length;
  document.getElementById("sNmap").textContent = s.nmap ? "OK" : "falta";
  document.getElementById("sGateway").textContent = s.gateway || "desconocido";
  const health=s.health||{};
  document.getElementById("internetState").textContent=health.internet?"Internet conectado":"Internet no disponible";
  document.getElementById("healthBox").innerHTML=
    `<div><span>Gateway</span><b>${NS.esc(health.gateway||"-")}</b></div>`+
    `<div><span>Latencia</span><b>${health.latency_ms==null?"-":health.latency_ms+" ms"}</b></div>`+
    `<div><span>Pérdida</span><b>${health.packet_loss==null?"-":health.packet_loss+"%"}</b></div>`;
  const traffic=s.traffic||{};
  document.getElementById("trafficBox").innerHTML=
    `<div><span>Total</span><b>${NS.fmt(traffic.bytes||0)}</b></div>`+
    `<div><span>Enviado</span><b>${NS.fmt(traffic.sent_bytes||0)}</b></div>`+
    `<div><span>Recibido</span><b>${NS.fmt(traffic.recv_bytes||0)}</b></div>`+
    `<div><span>Subida ahora</span><b>${NS.fmt(traffic.sent_rate||0)}/s</b></div>`+
    `<div><span>Bajada ahora</span><b>${NS.fmt(traffic.recv_rate||0)}/s</b></div>`+
    `<div><span>Pico</span><b>${NS.fmt(traffic.peak_rate||0)}/s</b></div>`;
  const di=s.devices_info||{};
  document.getElementById("deviceInfoBox").innerHTML=
    `<div><span>Desconocidos</span><b>${di.unknown||0}</b></div>`+
    `<div><span>Nuevos hoy</span><b>${di.new_today||0}</b></div>`+
    `<div><span>Con nombre</span><b>${di.named||0}</b></div>`;
  const sec=s.security||{}, checks=[["Permisos",sec.admin],["Captura",sec.capture],["nmap",sec.nmap],["NetBIOS",sec.netbios]];
  document.getElementById("securityState").textContent=checks.every(x=>x[1])?"listo":"revisar";
  document.getElementById("securityBox").innerHTML=checks.map(([name,ok])=>`<div><span class="status-mark ${ok?'ok':'warn'}">${ok?'OK':'!'}</span>${name}</div>`).join("");
  const events=s.events||[];
  document.getElementById("eventsBox").innerHTML=events.length?events.map(e=>`<div class="event-row"><span>${NS.esc(e.type||"evento")}</span><b>${NS.esc(e.label||e.detail||"-")}</b></div>`).join(""):`<div class="empty">sin eventos recientes</div>`;
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
    const net=w.internet||{};
    const location=[net.city,net.region,net.country].filter(Boolean).join(", ");
    const localNote=w.details_note?`<div class="wifi-disclaimer">${NS.esc(w.details_note)}</div>`:"";
    box.innerHTML =
      `<div class="wifi-section-title">Wi-Fi local</div>`+
      `<div class="wifi-ssid-cell"><div class="k">Red (SSID)</div><div class="wifi-ssid">${NS.esc(w.ssid||"-")}</div></div>`+
      cell("Senal", w.signal)+cell("Canal", w.channel)+cell("Banda", w.band)+
      cell("Tipo", w.radio)+cell("Seguridad", w.security)+
      cell("Rx", w.rx?w.rx+" Mbps":"")+cell("Tx", w.tx?w.tx+" Mbps":"")+
      cell("BSSID", w.bssid)+
      `<div class="wifi-section-title">Internet y ubicación aproximada</div>`+
      cell("IP pública", net.ip)+cell("Proveedor", net.provider)+cell("ASN", net.asn)+
      cell("Ciudad aproximada", location)+cell("Zona horaria", net.timezone)+
      `<div class="wifi-disclaimer">La ciudad y el proveedor se estiman desde la IP pública y pueden no coincidir con tu ubicación exacta.</div>`+
      localNote;
  }catch(e){
    const box=document.getElementById("wifiBox"), st=document.getElementById("wifiState");
    if(st) st.textContent="no disponible";
    if(box) box.innerHTML='<div class="v" style="color:var(--faint)">No se pudo obtener la info Wi-Fi en este equipo.</div>';
  }
}
loadWifi(); setInterval(loadWifi, 20000);
