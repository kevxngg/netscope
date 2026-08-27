let lastTotal=null, lastT=null, trafficLoading=false;
const hist=[]; // bytes/seg
let animationFrame=0, renderedValue=0, targetValue=0, previousFrame=0;
const MB=1024*1024;

function scaleFor(value){
  if(value<=MB) return MB;
  const step=value<5*MB?MB:5*MB;
  return Math.max(step,Math.ceil(value/step)*step);
}

function formatScale(value){
  return value>=MB ? `${Math.round(value/MB)} MB/s` : `${Math.round(value/1024)} KB/s`;
}

function drawChart(){
  const cv=document.getElementById("chart"); if(!cv) return;
  const dpr=window.devicePixelRatio||1, w=cv.clientWidth, h=180;
  if(!w) return;
  cv.width=Math.round(w*dpr); cv.height=Math.round(h*dpr);
  const ctx=cv.getContext("2d"); ctx.setTransform(dpr,0,0,dpr,0,0); ctx.clearRect(0,0,w,h);
  const empty=document.getElementById("chartEmpty");
  if(hist.length<2){ if(empty) empty.style.display="grid"; return; }
  if(empty) empty.style.display="none";
  const max=scaleFor(Math.max(...hist, renderedValue, 1));
  const css=getComputedStyle(document.documentElement);
  const green=css.getPropertyValue("--green").trim()||"#3ef08f";
  const n=hist.length, step=w/Math.max(1,(n-1));
  const scale=document.getElementById("chartScale");
  if(scale){
    [...scale.children].forEach((label,index)=>{
      const value=max*(1-index/4);
      label.textContent=index===4?"0 MB/s":formatScale(value);
    });
  }
  ctx.strokeStyle=css.getPropertyValue("--border").trim()||"#1c2a1c";
  ctx.lineWidth=1;
  for(let i=1;i<4;i++){ const y=Math.round((h-8)*(i/4))+.5; ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(w,y); ctx.stroke(); }
  const values=hist.slice();
  values[values.length-1]=renderedValue;
  const point=(v,i)=>[i*step,h-(v/max)*(h-14)-7];
  const points=values.map(point);
  const fill=ctx.createLinearGradient(0,0,0,h); fill.addColorStop(0,green+"55"); fill.addColorStop(1,green+"04");
  const smoothPath=(close=false)=>{
    ctx.beginPath();
    if(!points.length) return;
    ctx.moveTo(points[0][0],points[0][1]);
    for(let i=1;i<points.length;i++){
      const [x0,y0]=points[i-1], [x1,y1]=points[i];
      const midX=(x0+x1)/2;
      ctx.quadraticCurveTo(x0+(midX-x0)*.65,y0,midX,(y0+y1)/2);
      ctx.quadraticCurveTo(midX+(x1-midX)*.35,(y0+y1)/2,x1,y1);
    }
    if(close){ ctx.lineTo(points[points.length-1][0],h); ctx.lineTo(0,h); ctx.closePath(); }
  };
  ctx.beginPath(); ctx.moveTo(0,h); smoothPath(true);
  ctx.lineTo((n-1)*step,h); ctx.closePath();
  ctx.fillStyle=fill; ctx.fill();
  smoothPath();
  ctx.strokeStyle=green; ctx.lineWidth=2; ctx.stroke();
  const [x,y]=points[points.length-1];
  ctx.beginPath(); ctx.arc(x,y,4,0,Math.PI*2); ctx.fillStyle=green; ctx.fill();
  ctx.beginPath(); ctx.arc(x,y,8,0,Math.PI*2); ctx.strokeStyle=green+"33"; ctx.lineWidth=1; ctx.stroke();
}

function animateChart(now){
  if(!previousFrame) previousFrame=now;
  const elapsed=Math.min(1,(now-previousFrame)/450);
  renderedValue += (targetValue-renderedValue)*(0.12+elapsed*0.18);
  drawChart();
  animationFrame=requestAnimationFrame(animateChart);
}

async function load(){
  if(trafficLoading) return;
  trafficLoading=true;
  try{
  const d = await NS.get("/api/traffic");
  const rows=d.traffic||[];
  document.getElementById("trafCnt").textContent = rows.length?rows.length+" IPs":"-";
  const total=rows.reduce((a,t)=>a+t.bytes,0), now=performance.now();
  if(lastTotal!=null){
    const dt=(now-lastT)/1000, bps=Math.max(0,(total-lastTotal))/Math.max(dt,0.001);
    hist.push(bps); if(hist.length>60) hist.shift();
    targetValue=bps;
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
  } finally {
    trafficLoading=false;
  }
}
async function resetTraffic(){ await NS.post("/api/traffic/reset"); load(); }
async function pollTraffic(){
  await load();
  window.setTimeout(pollTraffic,500);
}
pollTraffic();
animationFrame=requestAnimationFrame(animateChart);
window.addEventListener("resize",drawChart);
