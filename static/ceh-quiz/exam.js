/* CEH 模擬考：依題庫組題、計時作答、交卷後計分與檢討。
   共用主頁面的 DATA、DMAP、DOMS、TIERS、S、mark()、esc() 等全域值，所以要在主程式之後載入。 */
(function(){
'use strict';
const XLS='cehexam_v1';
// CEH v13 官方考試藍圖的領域比例（%）
const BLUEPRINT={D1:6,D2:21,D3:17,D4:14,D5:16,D6:6,D7:8,D8:6,D9:6};
const DOM_ORDER=['D1','D2','D3','D4','D5','D6','D7','D8','D9'];
const OFFICIAL={n:125,min:240};
const QMAP=new Map(DATA.map(q=>[q.n,q]));
const dlabel=code=>(DOMS.find(d=>d[0]===code)||[,'其他'])[1];
const DEF={n:125,time:'std',mode:'blueprint',doms:[],tiers:['short','mid','long'],
  onlyWrong:false,fresh:true,hl:false,pass:70};

let X=xload();
function xload(){
  try{const o=JSON.parse(localStorage.getItem(XLS));
    if(o&&o.cfg) return {cur:null,hist:[],...o,cfg:{...DEF,...o.cfg}};}catch(e){}
  return {cfg:{...DEF},cur:null,hist:[]};
}
function xsave(){ try{localStorage.setItem(XLS,JSON.stringify(X));}catch(e){} }

let V={page:'setup',hid:null,idx:0,filter:'all'};
let expOn=false, timer=null;
const $=id=>document.getElementById(id);
const app=$('examApp');
app.innerHTML=`
<div class="bar"><div class="bar-in">
  <div class="brand"><b id="xtitle">模擬考</b><span id="xsub"></span></div>
  <div class="xright" id="xright"></div>
</div><div class="rail"><div id="xrail"></div></div></div>
<div class="wrap" id="xwrap">
  <main><div id="xmain"></div><div class="nav" id="xnav"></div></main>
  <aside class="xside" id="xside"></aside>
</div>
<div class="scrim xscrim" id="xscrim" data-act="close"></div>
<dialog class="xdlg" id="xdlg"></dialog>`;

/* ---------- helpers ---------- */
function shuffle(a){ for(let i=a.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[a[i],a[j]]=[a[j],a[i]];} return a; }
const pad=n=>String(n).padStart(2,'0');
function fmtMin(m){ if(m<60) return m+' 分鐘'; const h=Math.floor(m/60), r=m%60; return h+' 小時'+(r?' '+r+' 分':''); }
function fmtDur(ms){ const s=Math.round(ms/1000); if(s<60) return s+' 秒';
  const h=Math.floor(s/3600), m=Math.round(s%3600/60); return (h?h+' 小時 ':'')+m+' 分'; }
function fmtClock(ms){ const t=Math.max(0,Math.ceil(ms/1000)), h=Math.floor(t/3600), m=Math.floor(t%3600/60), s=t%60;
  return h? `${h}:${pad(m)}:${pad(s)}` : `${m}:${pad(s)}`; }
function fmtDate(ts){ const d=new Date(ts), now=new Date();
  return (d.getFullYear()!==now.getFullYear()?d.getFullYear()+'/':'')+`${d.getMonth()+1}/${d.getDate()} ${pad(d.getHours())}:${pad(d.getMinutes())}`; }
function head(title,sub,right){ $('xtitle').textContent=title; $('xsub').textContent=sub; $('xright').innerHTML=right; }
function highlight(text,on){ if(!on) return esc(text); const h=S.hl; S.hl=true; const out=mark(text); S.hl=h; return out; }
function isPhone(){ return matchMedia('(max-width:720px)').matches; }
function toTop(){ if($('xmain').getBoundingClientRect().top<0) window.scrollTo({top:0}); }

/* ---------- 組題 ---------- */
function pool(cfg){
  let p=DATA;
  if(cfg.tiers.length<3) p=p.filter(q=>cfg.tiers.includes(q.t));
  if(cfg.onlyWrong) p=p.filter(q=>S.wrong[q.n]);
  if(cfg.mode==='pick') p=p.filter(q=>cfg.doms.includes(DMAP[q.n]));
  return p;
}
// 依官方比例分配每個領域的題數；某領域題目不夠時，把缺額依比例分給其他領域
function plan(cfg,p){
  const avail={}; p.forEach(q=>{const d=DMAP[q.n]; avail[d]=(avail[d]||0)+1;});
  let need=Math.min(cfg.n,p.length), doms=DOM_ORDER.filter(d=>avail[d]);
  const out={}; doms.forEach(d=>out[d]=0);
  while(need>0 && doms.length){
    const wsum=doms.reduce((s,d)=>s+BLUEPRINT[d],0);
    const raw=doms.map(d=>{const v=need*BLUEPRINT[d]/wsum; return {d,v,f:Math.floor(v)};});
    let given=raw.reduce((s,r)=>s+r.f,0);
    raw.slice().sort((a,b)=>(b.v-b.f)-(a.v-a.f)).forEach(r=>{ if(given<need){r.f++;given++;} });
    let used=0;
    raw.forEach(r=>{const take=Math.min(avail[r.d]-out[r.d],r.f); out[r.d]+=take; used+=take;});
    need-=used; doms=doms.filter(d=>out[d]<avail[d]);
    if(!used) break;
  }
  return out;
}
function seenSet(){
  const s=new Set(Object.keys(S.ans).map(Number));
  X.hist.forEach(h=>h.qs.forEach(n=>s.add(n)));
  return s;
}
// 打亂後把沒做過的題排前面（sort 是穩定的，同一組內仍是亂序）
function order(list,cfg,seen){
  shuffle(list);
  if(cfg.fresh) list.sort((a,b)=>(seen.has(a.n)?1:0)-(seen.has(b.n)?1:0));
  return list;
}
function assemble(cfg){
  const p=pool(cfg), seen=seenSet();
  let picked=[];
  if(cfg.mode==='blueprint'){
    const pl=plan(cfg,p);
    for(const d in pl) picked.push(...order(p.filter(q=>DMAP[q.n]===d),cfg,seen).slice(0,pl[d]));
  } else picked=order(p.slice(),cfg,seen).slice(0,Math.min(cfg.n,p.length));
  return shuffle(picked.map(q=>q.n));
}
function minutesFor(cfg,n){
  if(cfg.time==='none') return 0;
  const base=n*OFFICIAL.min/OFFICIAL.n;
  return Math.ceil(cfg.time==='relax'?base*1.5:base);
}
function cfgLabel(cfg){
  const m={blueprint:'官方比例',random:'隨機',pick:'指定領域'}[cfg.mode];
  const t=cfg.tiers.length<3? ' · '+cfg.tiers.map(k=>TIERS.find(x=>x.k===k).label).join('/') : '';
  return m+t+(cfg.onlyWrong?' · 錯題本':'');
}
function start(){
  const cfg=X.cfg, qs=assemble(cfg);
  if(!qs.length) return;
  const min=minutesFor(cfg,qs.length), now=Date.now();
  X.cur={id:now,qs,ans:{},flag:{},i:0,at:now,end:min?now+min*60000:0,min,
    pass:cfg.pass,hl:cfg.hl,label:cfgLabel(cfg),cfg:{...cfg}};
  xsave(); V.page='run'; draw(); window.scrollTo(0,0);
}

/* ---------- 交卷與計分 ---------- */
function score(h){
  let ok=0; const dom={};
  h.qs.forEach(n=>{ const d=DMAP[n]; dom[d]=dom[d]||{t:0,o:0}; dom[d].t++;
    const g=h.ans[n]; if(g!==undefined && QMAP.get(n).a.includes(g)){ok++;dom[d].o++;} });
  return {ok,dom};
}
function finish(auto){
  const E=X.cur; if(!E) return;
  stopTimer();
  const endT=E.end?Math.min(Date.now(),E.end):Date.now();
  const {ok}=score(E);
  // 答錯與未答進練習的錯題本，也排進記憶曲線
  E.qs.forEach(n=>{
    const right=E.ans[n]!==undefined && QMAP.get(n).a.includes(E.ans[n]);
    if(!right) S.wrong[n]={c:domName(n)};
    if(typeof srsGrade==='function') srsGrade(n,right?'ok':'no');
  });
  save();
  const pct=Math.round(ok/E.qs.length*100);
  const h={id:E.id,at:E.at,dur:endT-E.at,n:E.qs.length,qs:E.qs,ans:E.ans,flag:E.flag,ok,pct,
    passAt:E.pass,pass:pct>=E.pass,label:E.label,min:E.min,auto:!!auto,hl:E.hl,cfg:E.cfg};
  X.hist.unshift(h); X.hist=X.hist.slice(0,30); X.cur=null; xsave();
  V={page:'result',hid:h.id,idx:0,filter:'all'};
  draw(); window.scrollTo(0,0);
}

/* ---------- timer ---------- */
function startTimer(){
  stopTimer();
  const E=X.cur; if(!E||!E.end) return;
  const tick=()=>{
    const left=E.end-Date.now();
    if(left<=0){ finish(true); return; }
    document.querySelectorAll('.xtimer,.xtimer2').forEach(el=>{
      el.textContent=fmtClock(left); el.classList.toggle('low',left<5*60000); });
  };
  tick(); timer=setInterval(tick,1000);
}
function stopTimer(){ if(timer){clearInterval(timer);timer=null;} }

/* ---------- sheets ---------- */
function closeX(){
  expOn=false; document.body.classList.remove('x-nav','x-exp');
  const e=$('xexp'); if(e) e.classList.remove('open');
  const b=$('xexpbtn'); if(b) b.textContent='看解答';
}
function setExp(on){
  const el=$('xexp'); if(!el) return;
  expOn=on; el.classList.toggle('open',on); el.scrollTop=0;
  document.body.classList.toggle('x-exp',on);
  const b=$('xexpbtn'); if(b) b.textContent=on?'收起解答':'看解答';
  if(on && !isPhone()) el.scrollIntoView({block:'nearest',behavior:'smooth'});
}
function ask(title,msg,okLabel,cancelLabel,danger){
  return new Promise(res=>{
    const d=$('xdlg');
    d.innerHTML=`<h3>${title}</h3><p>${msg}</p><div class="xdlg-b">
      <button class="btn" value="no">${cancelLabel||'取消'}</button>
      <button class="btn pri${danger?' danger':''}" value="ok">${okLabel}</button></div>`;
    d.querySelectorAll('button').forEach(b=>b.onclick=()=>{ res(b.value==='ok'); d.close(); });
    d.onclose=()=>res(false);
    d.showModal();
  });
}

/* ---------- pages ---------- */
function draw(){
  closeX(); stopTimer();
  $('xwrap').classList.toggle('solo',V.page==='setup'||V.page==='result');
  $('xnav').innerHTML=''; $('xside').innerHTML='';
  if(V.page==='run') drawRun();
  else if(V.page==='result') drawResult();
  else if(V.page==='review') drawReview();
  else drawSetup();
}

function drawSetup(){
  head('模擬考',`CEH v13 · ${DATA.length} 題題庫`,`<a class="ic" href="#">回練習</a>`);
  $('xrail').style.width='0';
  const cfg=X.cfg, p=pool(cfg), N=Math.min(cfg.n,p.length), min=minutesFor(cfg,N);
  const wrongN=Object.keys(S.wrong).length;
  const chip=(k,v,label,on)=>`<button class="chip" data-k="${k}" data-v="${v}" aria-pressed="${!!on}">${label}</button>`;
  let dist='';
  if(cfg.mode==='blueprint' && p.length){
    const pl=plan(cfg,p);
    dist=`<div class="xdist">${DOM_ORDER.filter(d=>pl[d]).map(d=>`<span>${esc(dlabel(d))}<b>${pl[d]}</b></span>`).join('')}</div>`;
  }
  const sum = p.length
    ? `從 <b>${p.length}</b> 題中抽 <b>${N}</b> 題 · ${min?'限時 <b>'+fmtMin(min)+'</b>':'不計時'} · 及格 <b>${cfg.pass}%</b>`
      + (p.length<cfg.n?`<br><span class="xwarn">這個範圍只有 ${p.length} 題，會少於 ${cfg.n} 題。</span>`:'')
      + dist
    : `<span class="xwarn">這個範圍沒有題目，放寬條件再試。</span>`;
  const hist = X.hist.length
    ? X.hist.map(h=>`<button class="xhist" data-act="hist" data-id="${h.id}">
        <span class="s ${h.pass?'y':'n'}">${h.pct}%</span>
        <span class="m">${h.ok} / ${h.n} 題答對 · ${esc(h.label)}<small>${fmtDate(h.at)} · 用時 ${fmtDur(h.dur)}</small></span>
        <span class="go">查看</span></button>`).join('')
      + `<button class="lnk xclear" data-act="clearhist">清除考試紀錄</button>`
    : `<p class="empty">考完的成績會留在這裡，可以回頭檢討。</p>`;
  $('xmain').innerHTML=`
  <div class="card xcard">
    <div class="xintro"><h2>模擬考</h2><p>依條件從題庫抽題。作答時不顯示對錯，交卷後才計分，答錯的題會進錯題本和記憶複習。</p></div>
    <div class="xsec"><h4>題數</h4><div class="chips">
      ${[10,25,50,75,125].map(n=>chip('n',n,n===125?'125 題 <em>正式</em>':n+' 題',cfg.n===n)).join('')}</div></div>
    <div class="xsec"><h4>時間</h4><div class="chips">
      ${chip('time','std','比照正式',cfg.time==='std')}${chip('time','relax','寬鬆 1.5 倍',cfg.time==='relax')}${chip('time','none','不計時',cfg.time==='none')}</div>
      <p class="xnote">正式考試 125 題 4 小時，平均每題約 1.9 分鐘。時間到會自動交卷。</p></div>
    <div class="xsec"><h4>組題方式</h4><div class="chips">
      ${chip('mode','blueprint','依官方領域比例',cfg.mode==='blueprint')}${chip('mode','random','完全隨機',cfg.mode==='random')}${chip('mode','pick','指定領域',cfg.mode==='pick')}</div>
      ${cfg.mode==='pick'?`<div class="chips">${DOM_ORDER.map(d=>chip('dom',d,esc(dlabel(d))+`<em>${DOMQ[d].length}</em>`,cfg.doms.includes(d))).join('')}</div>`:''}
      <p class="xnote">官方比例：偵察 21%、系統入侵 17%、Web 16%、網路與邊界 14%、行動/IoT/OT 8%，其餘各 6%。</p></div>
    <div class="xsec"><h4>題目長度</h4><div class="chips">
      ${['short','mid','long'].map(t=>chip('tier',t,TIERS.find(x=>x.k===t).label,cfg.tiers.includes(t))).join('')}</div></div>
    <div class="xsec"><h4>出題偏好</h4><div class="chips">
      ${chip('onlyWrong',1,`只考錯題本<em>${wrongN}</em>`,cfg.onlyWrong)}
      ${chip('fresh',1,'優先出沒做過的題',cfg.fresh)}
      ${chip('hl',1,'保留重點標記',cfg.hl)}</div></div>
    <div class="xsec"><h4>及格線</h4><div class="chips">
      ${[60,70,80].map(v=>chip('pass',v,v+'%',cfg.pass===v)).join('')}</div>
      <p class="xnote">正式考試的及格線依題本不同，落在 60% 到 85% 之間。</p></div>
    <div class="xsum">${sum}</div>
    <button class="btn pri xgo" data-act="start" ${p.length?'':'disabled'}>開始考試</button>
  </div>
  <div class="card xcard"><div class="xsec"><h4>歷次成績</h4>${hist}</div></div>`;
}

function drawRun(){
  const E=X.cur;
  if(!E){ V.page='setup'; return draw(); }
  if(E.end && Date.now()>=E.end) return finish(true);
  const n=E.qs.length; E.i=Math.max(0,Math.min(E.i,n-1));
  const qn=E.qs[E.i], q=QMAP.get(qn), given=E.ans[qn];
  const done=E.qs.filter(x=>E.ans[x]!==undefined).length, flags=E.qs.filter(x=>E.flag[x]).length;
  head('模擬考',`${E.i+1} / ${n} 題 · 已答 ${done}`,
    (E.end?`<span class="xtimer" title="剩餘時間"></span>`:'')
    +`<button class="ic xmb" data-act="nav">題目表</button><button class="ic" data-act="submit">交卷</button>`);
  $('xrail').style.width=((E.i+1)/n*100)+'%';
  $('xmain').innerHTML=`<div class="card" data-d="${DMAP[qn]}">
    <div class="meta"><span class="qno">第 ${E.i+1} 題</span><span class="dot"></span>
      <span class="cat">${esc(dlabel(DMAP[qn]))}</span>
      <button class="flag xflag" data-act="flag" data-on="${E.flag[qn]?1:0}">${E.flag[qn]?'已標記':'標記'}</button></div>
    <div class="stem">${highlight(q.q,E.hl)}</div>
    <div class="opts">${q.o.map((t,i)=>`<button class="opt${given===i?' picked':''}" data-act="ans" data-i="${i}" aria-pressed="${given===i}">
      <span class="k">${LET[i]}</span><span class="tx">${esc(t)}</span></button>`).join('')}</div>
  </div>`;
  const last=E.i===n-1;
  $('xnav').innerHTML=`<button class="btn" data-act="prev" ${E.i===0?'disabled':''}>上一題</button>
    <button class="btn mid" data-act="flag">${E.flag[qn]?'取消標記':'標記'}</button>
    <button class="btn pri" data-act="${last?'submit':'next'}">${last?'交卷':'下一題'}</button>
    <span class="keys">已答 ${done} / ${n}<em>A–H 作答　F 標記　← → 換題</em></span>`;
  $('xside').innerHTML=`<div class="sheet-h"><b>題目表</b><button class="ic" data-act="close">關閉</button></div>
    <div class="panel"><h4>進度</h4>
      ${E.end?`<div class="big xtimer2"></div>`:''}
      <div class="stat"><span>已答</span><b>${done} / ${n}</b></div>
      <div class="stat"><span>未答</span><b>${n-done}</b></div>
      <div class="stat"><span>標記</span><b>${flags}</b></div></div>
    <div class="panel"><h4>題目表</h4>
      <div class="xlegend"><span><i style="background:var(--accent-soft)"></i>已答</span>
        <span><i></i>未答</span><span><i style="background:var(--warn)"></i>標記</span></div>
      <div class="xgrid">${E.qs.map((x,i)=>`<button data-act="go" data-i="${i}" class="${E.ans[x]!==undefined?'a':''}${E.flag[x]?' f':''}${i===E.i?' cur':''}">${i+1}</button>`).join('')}</div></div>
    <button class="btn pri" data-act="submit">交卷</button>
    <button class="lnk" data-act="abandon">放棄這次考試</button>`;
  startTimer();
}

function current(){ return X.hist.find(x=>x.id===V.hid); }
function stateOf(h,n){ const g=h.ans[n]; return g===undefined?'un':(QMAP.get(n).a.includes(g)?'ok':'no'); }
function filtered(h){
  return h.qs.map((n,i)=>i).filter(i=>{ const n=h.qs[i], s=stateOf(h,n);
    return V.filter==='all' || (V.filter==='f'? !!h.flag[n] : s===V.filter); });
}

function drawResult(){
  const h=current(); if(!h){ V.page='setup'; return draw(); }
  head('成績單',fmtDate(h.at)+' · '+h.label,`<a class="ic" href="#">回練習</a>`);
  $('xrail').style.width='0';
  const {dom}=score(h);
  const st=h.qs.map(n=>stateOf(h,n));
  const cnt={all:h.n,no:st.filter(s=>s==='no').length,un:st.filter(s=>s==='un').length,f:h.qs.filter(n=>h.flag[n]).length};
  const doms=DOM_ORDER.filter(d=>dom[d]).map(d=>{ const p=Math.round(dom[d].o/dom[d].t*100);
    return `<div class="wk" data-d="${d}"><div class="l"><span>${esc(dlabel(d))}</span><em>${dom[d].o} / ${dom[d].t} · ${p}%</em></div>
      <div class="t"><i style="width:${Math.max(p,2)}%;background:${p>=h.passAt?'var(--ok)':'var(--bad)'}"></i></div></div>`; }).join('');
  const fchip=(k,label)=>`<button class="chip" data-act="filter" data-f="${k}" aria-pressed="${V.filter===k}">${label}<em>${cnt[k]}</em></button>`;
  const rows=filtered(h).map(i=>{ const n=h.qs[i], q=QMAP.get(n), s=st[i], g=h.ans[n];
    const r= s==='un'?'未答' : s==='ok'?'答對' : `${LET[g]} → ${q.a.map(x=>LET[x]).join('/')}`;
    return `<button class="xrow" data-act="rv" data-i="${i}" data-s="${s}"><span class="i">${i+1}</span>
      <span class="tx">${esc(q.q.slice(0,140))}</span><span class="r">${r}</span></button>`; }).join('')
    || `<p class="empty">沒有符合的題目。</p>`;
  $('xmain').innerHTML=`
  <div class="card xcard">
    <div class="xscore ${h.pass?'y':'n'}"><div class="big">${h.pct}%</div>
      <div class="verdict ${h.pass?'y':'n'}">${h.pass?'通過':'未通過'}<b>及格線 ${h.passAt}%</b></div></div>
    <div class="xstats">
      <div><span>答對</span><b>${h.ok} / ${h.n}</b></div>
      <div><span>答錯</span><b>${cnt.no}</b></div>
      <div><span>未答</span><b>${cnt.un}</b></div>
      <div><span>用時</span><b>${fmtDur(h.dur)}</b></div></div>
    ${h.auto?`<p class="xnote xwarn">時間到，系統自動交卷。</p>`:''}
    <div class="xsec"><h4>各領域得分</h4><div class="xdoms">${doms}</div></div>
    <p class="xnote">${h.n-h.ok?`答錯與未答的 ${h.n-h.ok} 題已加入練習的錯題本，並排進記憶複習。`:'全部答對。'}</p>
    <div class="xacts"><button class="btn pri" data-act="review">逐題檢討</button>
      <button class="btn" data-act="again">用相同條件再考一次</button>
      <button class="btn" data-act="setup">調整條件</button></div>
  </div>
  <div class="card xcard"><div class="xsec"><h4>題目一覽</h4>
    <div class="chips">${fchip('all','全部')}${fchip('no','答錯')}${fchip('un','未答')}${fchip('f','有標記')}</div>
    <div style="margin-top:10px">${rows}</div></div></div>`;
}

function drawReview(){
  const h=current(); if(!h){ V.page='setup'; return draw(); }
  let list=filtered(h); if(!list.length){ V.filter='all'; list=filtered(h); }
  V.idx=Math.max(0,Math.min(V.idx,list.length-1));
  const i=list[V.idx], qn=h.qs[i], q=QMAP.get(qn), g=h.ans[qn], s=stateOf(h,qn);
  head('檢討',`第 ${i+1} 題 · ${V.idx+1} / ${list.length}${V.filter!=='all'?' （篩選中）':''}`,
    `<button class="ic xmb" data-act="nav">題目表</button><button class="ic" data-act="result">成績單</button>`);
  $('xrail').style.width=((V.idx+1)/list.length*100)+'%';
  const sol=q.a.map(x=>LET[x]).join('/');
  const verdict= s==='un'?`<div class="verdict r">未作答<b>正解 ${sol}</b></div>`
    : `<div class="verdict ${s==='ok'?'y':'n'}">${s==='ok'?'答對':'答錯'}<b>你選 ${LET[g]}${s==='ok'?'':' · 正解 '+sol}</b></div>`;
  $('xmain').innerHTML=`<div class="card" data-d="${DMAP[qn]}">
    <div class="meta"><span class="qno">第 ${i+1} 題</span><span class="dot"></span>
      <span class="cat">${esc(dlabel(DMAP[qn]))}<span class="ce"> · Q${qn}</span></span>
      ${h.flag[qn]?'<span class="xbadge">考試時有標記</span>':''}</div>
    <div class="stem">${mark(q.q)}</div>
    <div class="opts">${q.o.map((t,k)=>`<button class="opt ${q.a.includes(k)?'ok':k===g?'no':'dim'}" disabled>
      <span class="k">${LET[k]}</span><span class="tx">${esc(t)}</span></button>`).join('')}</div>
    <div class="exp" id="xexp"><div class="sheet-h"><b>詳解</b><button class="ic" data-act="close">關閉</button></div>
      <div class="vrow">${verdict}</div><h3>詳解 &middot; 中文</h3><div class="body">${esc(q.e)}</div></div>
  </div>`;
  $('xnav').innerHTML=`<button class="btn" data-act="rprev" ${V.idx===0?'disabled':''}>上一題</button>
    <button class="btn mid" id="xexpbtn" data-act="exp">看解答</button>
    <button class="btn pri" data-act="rnext" ${V.idx>=list.length-1?'disabled':''}>下一題</button>
    <span class="keys">${V.idx+1} / ${list.length}<em>Enter 看解答　← → 換題</em></span>`;
  $('xside').innerHTML=`<div class="sheet-h"><b>題目表</b><button class="ic" data-act="close">關閉</button></div>
    <div class="panel"><h4>成績</h4><div class="big">${h.pct}%</div>
      <div class="stat"><span>答對</span><b>${h.ok} / ${h.n}</b></div></div>
    <div class="panel"><h4>題目表</h4>
      <div class="xlegend"><span><i style="background:var(--ok-soft)"></i>答對</span>
        <span><i style="background:var(--bad-soft)"></i>答錯</span><span><i style="border-style:dashed"></i>未答</span></div>
      <div class="xgrid">${h.qs.map((x,k)=>`<button data-act="rgo" data-i="${k}" class="${stateOf(h,x)}${h.flag[x]?' f':''}${k===i?' cur':''}">${k+1}</button>`).join('')}</div></div>
    <button class="btn" data-act="result">回成績單</button>`;
}

/* ---------- actions ---------- */
function moveRun(d){ const E=X.cur; if(!E) return; const ni=E.i+d;
  if(ni<0||ni>=E.qs.length) return; E.i=ni; xsave(); closeX(); drawRun(); toTop(); }
function moveReview(d){ const h=current(); if(!h) return; const L=filtered(h); const ni=V.idx+d;
  if(ni<0||ni>=L.length) return; V.idx=ni; closeX(); drawReview(); toTop(); }
async function submit(){
  const E=X.cur; if(!E) return;
  const un=E.qs.filter(x=>E.ans[x]===undefined).length, fl=E.qs.filter(x=>E.flag[x]).length;
  const parts=[]; if(un) parts.push(`還有 <b>${un}</b> 題沒作答`); if(fl) parts.push(`<b>${fl}</b> 題有標記`);
  closeX();
  const ok=await ask('確定交卷？',(parts.length?parts.join('，')+'。':'全部都答完了。')+'交卷後就不能再改答案。','交卷','繼續作答');
  if(ok && X.cur) finish(false);
}
app.addEventListener('click',async e=>{
  const b=e.target.closest('[data-k],[data-act]'); if(!b||!app.contains(b)||b.closest('dialog')) return;
  if(b.dataset.k){
    const k=b.dataset.k, v=b.dataset.v, c=X.cfg;
    if(k==='n'||k==='pass') c[k]=+v;
    else if(k==='time'||k==='mode') c[k]=v;
    else if(k==='dom') c.doms=c.doms.includes(v)?c.doms.filter(x=>x!==v):[...c.doms,v];
    else if(k==='tier'){ const t=c.tiers.includes(v)?c.tiers.filter(x=>x!==v):[...c.tiers,v]; if(t.length) c.tiers=t; }
    else c[k]=!c[k];
    xsave(); drawSetup(); return;
  }
  const a=b.dataset.act, E=X.cur;
  switch(a){
    case 'start': start(); break;
    case 'ans': { const qn=E.qs[E.i], i=+b.dataset.i;
      if(E.ans[qn]===i) delete E.ans[qn]; else E.ans[qn]=i; xsave(); drawRun(); break; }
    case 'flag': { const qn=E.qs[E.i]; if(E.flag[qn]) delete E.flag[qn]; else E.flag[qn]=1; xsave(); drawRun(); break; }
    case 'prev': moveRun(-1); break;
    case 'next': moveRun(1); break;
    case 'go': E.i=+b.dataset.i; xsave(); closeX(); drawRun(); window.scrollTo({top:0}); break;
    case 'nav': document.body.classList.add('x-nav'); break;
    case 'close': closeX(); break;
    case 'submit': submit(); break;
    case 'abandon': closeX();
      if(await ask('放棄這次考試？','這次的作答不會計分，也不會留下紀錄。','放棄','繼續作答',true)){
        X.cur=null; xsave(); V.page='setup'; draw(); }
      break;
    case 'hist': V={page:'result',hid:+b.dataset.id,idx:0,filter:'all'}; draw(); window.scrollTo(0,0); break;
    case 'clearhist':
      if(await ask('清除考試紀錄？','所有歷次成績會刪除，無法復原。錯題本不受影響。','清除','取消',true)){
        X.hist=[]; xsave(); draw(); }
      break;
    case 'filter': V.filter=b.dataset.f; drawResult(); break;
    case 'review': V.page='review'; V.idx=0; draw(); window.scrollTo(0,0); break;
    case 'rv': V.page='review'; V.idx=Math.max(0,filtered(current()).indexOf(+b.dataset.i)); draw(); window.scrollTo(0,0); break;
    case 'rgo': { const h=current(), i=+b.dataset.i; let L=filtered(h);
      if(!L.includes(i)){ V.filter='all'; L=filtered(h); }
      V.idx=L.indexOf(i); closeX(); drawReview(); window.scrollTo({top:0}); break; }
    case 'rprev': moveReview(-1); break;
    case 'rnext': moveReview(1); break;
    case 'exp': setExp(!expOn); break;
    case 'result': V.page='result'; draw(); window.scrollTo(0,0); break;
    case 'again': { const h=current(); if(h&&h.cfg) X.cfg={...DEF,...h.cfg}; start(); break; }
    case 'setup': V.page='setup'; draw(); window.scrollTo(0,0); break;
  }
});

addEventListener('keydown',e=>{
  if(!document.body.classList.contains('mode-exam') || $('xdlg').open) return;
  if(e.key==='Escape'){ closeX(); return; }
  if(e.target.tagName==='INPUT'||e.metaKey||e.ctrlKey||e.altKey) return;
  if(V.page==='run' && X.cur){
    const E=X.cur;
    if(e.key==='ArrowRight') return moveRun(1);
    if(e.key==='ArrowLeft') return moveRun(-1);
    if(e.key==='Enter'){ e.preventDefault(); return E.i===E.qs.length-1? submit() : moveRun(1); }
    if(e.key.toLowerCase()==='f'){ const qn=E.qs[E.i]; if(E.flag[qn]) delete E.flag[qn]; else E.flag[qn]=1; xsave(); return drawRun(); }
    const i=LET.indexOf(e.key.toUpperCase()), q=QMAP.get(E.qs[E.i]);
    if(i>=0 && i<q.o.length){ e.preventDefault(); E.ans[E.qs[E.i]]=i; xsave(); drawRun(); }
  } else if(V.page==='review'){
    if(e.key==='ArrowRight') return moveReview(1);
    if(e.key==='ArrowLeft') return moveReview(-1);
    if(e.key==='Enter'){ e.preventDefault(); setExp(!expOn); }
  }
});

// 左右滑動換題
(function(){
  let x0=null,y0=0,t0=0; const m=$('xmain');
  m.addEventListener('touchstart',e=>{
    if(e.touches.length!==1||e.target.closest('.exp')||(V.page!=='run'&&V.page!=='review')){x0=null;return;}
    x0=e.touches[0].clientX; y0=e.touches[0].clientY; t0=Date.now();
  },{passive:true});
  m.addEventListener('touchend',e=>{
    if(x0===null) return;
    const dx=e.changedTouches[0].clientX-x0, dy=e.changedTouches[0].clientY-y0; x0=null;
    if(Date.now()-t0>700||Math.abs(dx)<70||Math.abs(dx)<Math.abs(dy)*1.8||String(getSelection())) return;
    (V.page==='run'?moveRun:moveReview)(dx<0?1:-1);
  },{passive:true});
})();

/* ---------- routing: #exam 進入考試，其餘回練習 ---------- */
function route(){
  const on=location.hash==='#exam';
  document.body.classList.toggle('mode-exam',on);
  if(on){
    if(typeof closeSheets==='function') closeSheets();
    if(X.cur) V.page='run'; else if(V.page==='run') V.page='setup';
    draw(); window.scrollTo(0,0);
  } else {
    stopTimer(); closeX();
    if(typeof render==='function') render();
  }
}
addEventListener('hashchange',route);
document.addEventListener('visibilitychange',()=>{ if(!document.hidden && V.page==='run' && document.body.classList.contains('mode-exam')) drawRun(); });
window.examHasRunning=()=>!!X.cur;
route();
})();
