async function load(){
  const s=await NS.get("/api/settings");
  const site=document.getElementById("siteName"); if(site) site.value=s.site_name||"casa";
}
async function saveSite(){
  const name=document.getElementById("siteName").value.trim()||"casa";
  await NS.post("/api/settings",{site_name:name});
  msg("Sitio cambiado a \""+name+"\". Reinicia NetScope para aplicarlo del todo.");
}
function msg(t){ document.getElementById("msg").textContent=t; }
load();
