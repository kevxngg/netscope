let lastTotal=null, lastT=null;
const hist=[]; // bytes/seg
function drawChart(){
  const cv=document.getElementById("chart"); if(!cv) return;
  const dpr=window.devicePixelRatio||1, w=cv.clientWidth, h=cv.height;
  cv.width=w*dpr; cv.getContext("2d").scale(dpr,dpr);
  const ctx=cv.getContext("2d"); ctx.clearRect(0,0,w,h);
  if(hist.length<2) return;
  const max=Math.max(...hist,1);
  const css=getComputedStyle(document.documentElement);
  const green=css.getPropertyValue("--green").trim()||"#3ef08f";
  const n=hist.length, step=w/Math.max(1,(n-1));
  // area
  ctx.beginPath(); ctx.moveTo(0,h);
  hist.forEach((v,i)=>ctx.lineTo(i*step, h-(v/max)*(h-6)-3));
  ctx.lineTo((n-1)*step,h); ctx.closePath();
  ctx.fillStyle=green+"22"; ctx.fill();
  // linea
  ctx.beginPath();
  hist.forEach((v,i)=>{ const x=i*step,y=h-(v/max)*(h-6)-3; i?ctx.lineTo(x,y):ctx.moveTo(x,y); });
  ctx.strokeStyle=green; ctx.lineWidth=2; ctx.stroke();
}

async function load(){
  const d = await NS.get("/api/traffic");
  const rows=d.traffic||[];
  document.getElementById("trafCnt").textContent = rows.length?rows.length+" IPs":"-";
  const total=rows.reduce((a,t)=>a+t.bytes,0), now=performance.now();
  if(lastTotal!=null){
    const dt=(now-lastT)/1000, bps=Math.max(0,(total-lastTotal))/Math.max(dt,0.001);
    hist.push(bps); if(hist.length>60) hist.shift();
    const rt=document.getElementById("rateTxt"); if(rt) rt.textContent=NS.fmt(bps)+"/s";
    drawChart();
  }
  lastTotal=total; lastT=now;
  const el=document.getElementById("traf");
  if(!rows.length){ el.innerHTML=`<div class="empty">esperando paquetes...</div>`; return; }
  const max=Math.max(...rows.map(t=>t.bytes),1);
  el.innerHTML=rows.slice(0,50).map(t=>{
    const w=Math.max(2,(t.bytes/max)*100), tot=t.bytes||1;
    const sp=(t.sent_bytes/tot)*100, rp=(t.recv_bytes/tot)*100;
    const label=(t.name&&t.name!=="(sin nombre)")?NS.esc(t.name):(t.vendor?NS.esc(t.vendor):"IP externa/desconocida");
    return `<div class="trow">
      <div class="tt"><div class="nm">${label}<span class="ip num">${t.ip}</span>${t.is_local?'':'<span class="ext">externa</span>'}</div>
      <div class="tot num">${NS.fmt(t.bytes)} &middot; ${t.packets} pkt</div></div>
      <div class="bar" style="width:${w}%"><div class="s" style="width:${sp}%"></div><div class="r" style="width:${rp}%"></div></div>
      <div class="leg"><span class="u"><b>&#9650;</b> envia ${NS.fmt(t.sent_bytes)}</span><span class="d"><b>&#9660;</b> recibe ${NS.fmt(t.recv_bytes)}</span></div>
    </div>`;
  }).join("");
}
async function resetTraffic(){ await NS.post("/api/traffic/reset"); load(); }
load(); setInterval(load,2000);
