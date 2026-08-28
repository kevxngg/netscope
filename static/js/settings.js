async function load(){
  const s=await NS.get("/api/settings");
  document.getElementById("alerts").checked=!!s.alerts_enabled;
  document.getElementById("tgToken").value=s.tg_token||"";
  document.getElementById("tgChat").value=s.tg_chat||"";
  const site=document.getElementById("siteName"); if(site) site.value=s.site_name||"casa";
}
async function save(){
  await NS.post("/api/settings",{
    alerts_enabled:document.getElementById("alerts").checked,
    tg_token:document.getElementById("tgToken").value.trim(),
    tg_chat:document.getElementById("tgChat").value.trim(),
  });
  msg("Guardado.");
}
async function saveSite(){
  const name=document.getElementById("siteName").value.trim()||"casa";
  await NS.post("/api/settings",{site_name:name});
  msg("Sitio cambiado a \""+name+"\". Reinicia NetScope para aplicarlo del todo.");
}
async function test(){
  msg("Enviando...");
  const r=await NS.post("/api/notify/test");
  msg(r.ok?"Mensaje enviado (revisa Telegram).":"No se pudo enviar (revisa token/chat id).");
}
function msg(t){ document.getElementById("msg").textContent=t; }
load();
