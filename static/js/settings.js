async function load(){
  const s=await NS.get("/api/settings");
  document.getElementById("alerts").checked=!!s.alerts_enabled;
  document.getElementById("tgToken").value=s.tg_token||"";
  document.getElementById("tgChat").value=s.tg_chat||"";
}
async function save(){
  await NS.post("/api/settings",{
    alerts_enabled:document.getElementById("alerts").checked,
    tg_token:document.getElementById("tgToken").value.trim(),
    tg_chat:document.getElementById("tgChat").value.trim(),
  });
  msg("Guardado.");
}
async function test(){
  msg("Enviando...");
  const r=await NS.post("/api/notify/test");
  msg(r.ok?"Mensaje enviado (revisa Telegram).":"No se pudo enviar (revisa token/chat id).");
}
function msg(t){ document.getElementById("msg").textContent=t; }
load();
