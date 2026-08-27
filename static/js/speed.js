const DOWN = b => `https://speed.cloudflare.com/__down?bytes=${b}`;
const UP   = "https://speed.cloudflare.com/__up";
let running=false, abortController=null;

function setProgress(value){
  const bar=document.getElementById("progressBar"); if(bar) bar.style.width=`${value}%`;
}

async function latency(n=5){
  const t=[];
  for(let i=0;i<n;i++){
    if(abortController?.signal.aborted) throw new DOMException("Cancelado","AbortError");
    try{ const t0=performance.now(); const response=await fetch(DOWN(0),{cache:"no-store",signal:abortController?.signal}); if(!response.ok) throw Error("latencia"); t.push(performance.now()-t0); }catch(e){ if(e.name==="AbortError") throw e; }
  }
  if(!t.length) return null;
  t.sort((a,b)=>a-b); const median=t[Math.floor(t.length/2)];
  return {median:Math.round(median),min:Math.round(t[0]),max:Math.round(t[t.length-1]),jitter:Math.round(t.reduce((sum,value)=>sum+Math.abs(value-median),0)/t.length)};
}

async function download(seconds=10){
  const el=document.getElementById("down");
  let total=0; const start=performance.now(); const ctrl=new AbortController();
  const cancelPhase=()=>ctrl.abort();
  abortController?.signal.addEventListener("abort",cancelPhase,{once:true});
  const stop=setTimeout(()=>ctrl.abort(), seconds*1000);
  try{
    // varias descargas en paralelo para saturar el enlace
    await Promise.all([0,1,2].map(async()=>{
      while(performance.now()-start < seconds*1000){
        const r=await fetch(DOWN(25000000),{cache:"no-store",signal:ctrl.signal});
        if(!r.ok) throw Error("descarga");
        const reader=r.body.getReader();
        while(true){ const {done,value}=await reader.read(); if(done)break;
          total+=value.length;
          const mbps=(total*8)/((performance.now()-start)/1000)/1e6;
          el.textContent=mbps.toFixed(1);
        }
      }
    }));
  }catch(e){ if(e.name==="AbortError" && !running) throw e; }
  clearTimeout(stop);
  abortController?.signal.removeEventListener("abort",cancelPhase);
  if(!total) throw Error("No se recibieron datos de descarga.");
  const mbps=(total*8)/((performance.now()-start)/1000)/1e6;
  return Number(mbps.toFixed(1));
}

async function upload(seconds=8){
  const el=document.getElementById("up");
  const blob=new Uint8Array(2000000); let total=0; const start=performance.now();
  try{
    while(performance.now()-start < seconds*1000){
      if(abortController?.signal.aborted) throw new DOMException("Cancelado","AbortError");
      const t0=performance.now();
      const response=await fetch(UP,{method:"POST",body:blob,cache:"no-store",signal:abortController?.signal});
      if(!response.ok) throw Error("subida");
      total+=blob.length;
      const mbps=(total*8)/((performance.now()-start)/1000)/1e6;
      el.textContent=mbps.toFixed(1);
    }
  }catch(e){ if(e.name==="AbortError") throw e; }
  if(!total) throw Error("No se enviaron datos de subida.");
  const mbps=(total*8)/((performance.now()-start)/1000)/1e6;
  return Number(mbps.toFixed(1));
}

function saveResult(result){
  const history=JSON.parse(localStorage.getItem("ns-speed-history")||"[]");
  history.unshift(result); localStorage.setItem("ns-speed-history",JSON.stringify(history.slice(0,5))); renderHistory();
}
function renderHistory(){
  const box=document.getElementById("speedHistory"), history=JSON.parse(localStorage.getItem("ns-speed-history")||"[]");
  if(!history.length){box.innerHTML='<div class="empty">Todavía no hay mediciones guardadas.</div>';return;}
  box.innerHTML=history.map(item=>`<div class="speed-history-row"><span>${new Date(item.ts).toLocaleString()}</span><b>${item.download} Mbps ↓</b><b>${item.upload} Mbps ↑</b><span>${item.latency} ms</span></div>`).join("");
}
function clearHistory(){ localStorage.removeItem("ns-speed-history"); renderHistory(); }
function cancelTest(){ if(abortController) abortController.abort(); }

async function runTest(){
  if(running) return; running=true;
  abortController=new AbortController();
  const b=document.getElementById("runBtn"), cancel=document.getElementById("cancelBtn"); b.disabled=true; b.textContent="Midiendo..."; cancel.hidden=false;
  const st=document.getElementById("status");
  ["ping","down","up"].forEach(id=>document.getElementById(id).textContent="--");
  setProgress(0); document.getElementById("resultMeta").textContent="";
  try{
    st.innerHTML='<span class="spinner"></span>Midiendo latencia...';
    setProgress(15); const p=await latency(); document.getElementById("ping").textContent = p?p.median:"--";
    st.innerHTML='<span class="spinner"></span>Midiendo descarga...';
    setProgress(25); const down=await download(); document.getElementById("down").textContent=down.toFixed(1); setProgress(60);
    st.innerHTML='<span class="spinner"></span>Midiendo subida...';
    const up=await upload(); document.getElementById("up").textContent=up.toFixed(1); setProgress(100);
    st.textContent="Prueba completada";
    document.getElementById("resultMeta").textContent=`Cloudflare · ${new Date().toLocaleTimeString()} · jitter ${p?.jitter||"-"} ms · rango ${p?.min||"-"}-${p?.max||"-"} ms`;
    saveResult({ts:Date.now(),download:down,upload:up,latency:p?.median||"-"});
  }catch(e){ st.textContent=e.name==="AbortError"?"Prueba cancelada.":(e.message||"No se pudo completar la prueba. Revisa tu conexión."); }
  finally{ b.disabled=false; cancel.hidden=true; b.textContent="Repetir prueba"; running=false; abortController=null; }
}
renderHistory();
