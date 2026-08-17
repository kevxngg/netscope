const DOWN = b => `https://speed.cloudflare.com/__down?bytes=${b}`;
const UP   = "https://speed.cloudflare.com/__up";
let running=false;

async function latency(n=5){
  const t=[];
  for(let i=0;i<n;i++){
    try{ const t0=performance.now(); await fetch(DOWN(0),{cache:"no-store"}); t.push(performance.now()-t0); }catch(e){}
  }
  if(!t.length) return null;
  t.sort((a,b)=>a-b); return Math.round(t[Math.floor(t.length/2)]);
}

async function download(seconds=10){
  const el=document.getElementById("down");
  let total=0; const start=performance.now(); const ctrl=new AbortController();
  const stop=setTimeout(()=>ctrl.abort(), seconds*1000);
  try{
    // varias descargas en paralelo para saturar el enlace
    await Promise.all([0,1,2].map(async()=>{
      while(performance.now()-start < seconds*1000){
        const r=await fetch(DOWN(25000000),{cache:"no-store",signal:ctrl.signal});
        const reader=r.body.getReader();
        while(true){ const {done,value}=await reader.read(); if(done)break;
          total+=value.length;
          const mbps=(total*8)/((performance.now()-start)/1000)/1e6;
          el.textContent=mbps.toFixed(1);
        }
      }
    }));
  }catch(e){}
  clearTimeout(stop);
  const mbps=(total*8)/((performance.now()-start)/1000)/1e6;
  return mbps.toFixed(1);
}

async function upload(seconds=8){
  const el=document.getElementById("up");
  const blob=new Uint8Array(2000000); let total=0; const start=performance.now();
  try{
    while(performance.now()-start < seconds*1000){
      const t0=performance.now();
      await fetch(UP,{method:"POST",body:blob,cache:"no-store"});
      total+=blob.length;
      const mbps=(total*8)/((performance.now()-start)/1000)/1e6;
      el.textContent=mbps.toFixed(1);
    }
  }catch(e){}
  const mbps=(total*8)/((performance.now()-start)/1000)/1e6;
  return mbps.toFixed(1);
}

async function runTest(){
  if(running) return; running=true;
  const b=document.getElementById("runBtn"); b.disabled=true; b.textContent="Midiendo...";
  const st=document.getElementById("status");
  ["ping","down","up"].forEach(id=>document.getElementById(id).textContent="--");
  try{
    st.innerHTML='<span class="spinner"></span>Midiendo latencia...';
    const p=await latency(); document.getElementById("ping").textContent = p!=null?p:"--";
    st.innerHTML='<span class="spinner"></span>Midiendo descarga...';
    await download();
    st.innerHTML='<span class="spinner"></span>Midiendo subida...';
    await upload();
    st.textContent="Listo · medido con Cloudflare · "+new Date().toLocaleTimeString();
  }catch(e){ st.textContent="No se pudo completar la prueba (revisa tu conexion)."; }
  finally{ b.disabled=false; b.textContent="Repetir prueba"; running=false; }
}
// autoarranca al abrir la pagina
window.addEventListener("load", ()=>setTimeout(runTest, 400));
