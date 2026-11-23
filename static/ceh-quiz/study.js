/* CEH 背題模式：直接顯示正解與詳解，分組瀏覽，手機左右滑換題。
   共用主頁面的 DATA、DOMQ、DMAP、DOMS、TIERS、S、mark()、esc()、save()、domName() 等全域值，要在主程式之後載入。 */
(function(){
'use strict';
const KLS='cehstudy_v1';
const DOM_ORDER=['D1','D2','D3','D4','D5','D6','D7','D8','D9'];
const TIER_KEYS=['short','mid','long'];
const SIZES=[[10,'10 題'],[20,'20 題'],[30,'30 題'],[50,'50 題'],[0,'不分組']];
const DEF={dom:'all',tiers:[],size:20,only:false,exp:false,rnd:false,shuf:false,seed:1};   // tiers 空陣列＝全部長度

let K=kload();
function kload(){
  try{const o=JSON.parse(localStorage.getItem(KLS));
    if(o&&o.seen) return {...DEF,at:{},pos:{},...o};}catch(e){}
  return {...DEF,at:{},pos:{},seen:{}};
}
// 舊版只存單一長度 K.tier，換成可複選的 K.tiers
if(K.tier!==undefined){ if(K.tier!=='all') K.tiers=[K.tier]; delete K.tier; }
if(!Array.isArray(K.tiers)) K.tiers=[];
function ksave(){ try{localStorage.setItem(KLS,JSON.stringify(K));}catch(e){} }
const $=id=>document.getElementById(id);
const dlabel=c=>(DOMS.find(d=>d[0]===c)||[,'其他'])[1];
const isPhone=()=>matchMedia('(max-width:720px)').matches;

const app=$('studyApp');
app.innerHTML=`
<div class="bar"><div class="bar-in">
  <div class="brand"><b>背題</b><span id="ssub"></span></div>
  <div class="modes" role="group" aria-label="模式">
    <button data-go="practice" aria-pressed="false">練習</button>
    <button data-go="rev" aria-pressed="false"><span><span class="lg">記憶</span>複習</span></button>
    <a href="#study" aria-pressed="true">背題</a>
    <a href="#exam">模擬考</a>
  </div>
  <div class="mbtns"><button class="ic" data-sact="nav">組別</button></div>
</div><div class="rail"><div id="srail"></div></div></div>
<div class="wrap" id="swrap">
  <main><div id="smain"></div><div class="nav" id="snav"></div></main>
  <aside class="sside" id="sside"></aside>
</div>
<div class="scrim sscrim" data-sact="close"></div>`;

/* ---------- 範圍與分組 ---------- */
let G=[], gi=0, deck=[], pos=0, anim='';
const scopeKey=()=>K.dom+'|'+(K.tiers.length?K.tiers.join('+'):'all')+'|'+K.size+(K.shuf?'|r'+K.seed:'');
const gkey=()=>scopeKey()+'|'+gi;
function scope(){
  let d=DATA;
  if(K.dom==='wrong') d=d.filter(q=>S.wrong[q.n]);
  else if(K.dom!=='all') d=d.filter(q=>DMAP[q.n]===K.dom);
  if(K.tiers.length) d=d.filter(q=>K.tiers.includes(q.t));
  // 隨機：整個範圍先洗牌再分組，每組都是混在一起的題目；同一個 seed 洗出來的順序固定
  if(K.shuf){ d=d.slice(); let seed=hash('shuf'+K.seed);
    for(let i=d.length-1;i>0;i--){ seed=(seed*1103515245+12345)&0x7fffffff;
      const j=seed%(i+1); [d[i],d[j]]=[d[j],d[i]]; } }
  return d;
}
function build(){
  const s=scope(), n=K.size||s.length||1;
  G=[]; for(let i=0;i<s.length;i+=n) G.push(s.slice(i,i+n));
  gi=Math.min(K.at[scopeKey()]||0, Math.max(0,G.length-1));
  loadGroup();
}
// 這一組的題目在進組時固定下來，看的途中取消錯題也不會讓題目跳掉
function loadGroup(){
  const d=(G[gi]||[]).slice();
  if(K.rnd){ let seed=hash(gkey());
    for(let i=d.length-1;i>0;i--){ seed=(seed*1103515245+12345)&0x7fffffff;
      const j=seed%(i+1); [d[i],d[j]]=[d[j],d[i]]; } }
  deck=d; K.at[scopeKey()]=gi;
  pos=K.pos[gkey()]||0; if(pos>=deck.length) pos=0;
}
function move(d){
  if(d>0){
    if(pos<deck.length) pos++;
    else if(gi<G.length-1){ gi++; loadGroup(); pos=0; }
    else return false;
  } else {
    if(pos>0) pos--;
    else if(gi>0){ gi--; loadGroup(); pos=Math.max(0,deck.length-1); }
    else return false;
  }
  K.pos[gkey()]=pos; ksave(); return true;
}
function go(d){
  const g0=gi;
  if(!move(d)) return false;
  anim=d>0?'in-r':'in-l'; drawMain(); anim='';
  if(gi!==g0) drawSide(); else syncRow();
  if($('smain').getBoundingClientRect().top<0) window.scrollTo({top:0});
  return true;
}

/* ---------- 題目卡 ---------- */
function head(){
  const sl = (K.dom==='wrong'?'錯題本':K.dom==='all'?'全部':dlabel(K.dom))
    + (K.tiers.length?' · '+K.tiers.map(k=>TIERS.find(t=>t.k===k).label).join('＋'):'')
    + (K.shuf?' · 隨機':'');
  const len=deck.length;
  $('ssub').textContent = len
    ? `${sl} · 第 ${gi+1} / ${G.length} 組 · ${Math.min(pos+1,len)} / ${len}`
    : sl+' · 0 題';
  $('srail').style.width = len ? (Math.min(pos+1,len)/len*100)+'%' : '0';
}
function drawMain(){
  const m=$('smain');
  head();
  if(!deck.length){
    m.innerHTML=`<div class="card done"><div class="big">0</div>
      <p class="empty" style="font-size:14px;margin-top:12px">${K.dom==='wrong'
        ?'錯題本是空的。在練習或模擬考答錯、或在這裡按「標成錯題」的題目會收進來。'
        :'這個範圍沒有題目，換一個領域或長度。'}</p></div>`;
    $('snav').innerHTML=''; return;
  }
  if(pos>=deck.length) return drawEnd();
  const q=deck[pos];
  if(!K.seen[q.n]){ K.seen[q.n]=1; }
  K.pos[gkey()]=pos; ksave();
  const tl=TIERS.find(t=>t.k===q.t)||TIERS[0];
  const sol=q.a.map(x=>LET[x]).join(' / ');
  const shown=q.o.map((t,i)=>[t,i]).filter(([,i])=>!K.only||q.a.includes(i));
  const hidden=q.o.length-shown.length;
  m.innerHTML=`<div class="card scard ${anim}" data-d="${DMAP[q.n]||''}">
    <div class="meta">
      <span class="qno">Q${q.n}</span><span class="dot"></span>
      <span class="cat">${esc(dlabel(DMAP[q.n])||q.c)}<span class="ce"> · ${esc(q.ce)}</span></span><span class="dot"></span>
      <span class="gauge ${tl.g}" title="${tl.label}"><i></i><i></i><i></i></span>
      ${q.s?`<span class="snapbadge">${q.s==='tool'?'工具題':'名詞題'}</span>`:''}
      ${flagBtn(q)}
    </div>
    <div class="sans"><b>正解 ${sol}</b><span>${q.a.map(i=>esc(q.o[i])).join('　/　')}</span></div>
    <div class="stem">${mark(q.q)}</div>
    <div class="opts">${shown.map(([t,i])=>`<div class="opt ${q.a.includes(i)?'ok':'dim'}">
      <span class="k">${LET[i]}</span><span class="tx">${esc(t)}</span></div>`).join('')}</div>
    ${hidden?`<p class="shid">另外 ${hidden} 個選項已隱藏</p>`:''}
    <div class="sx${K.exp?' open':''}" id="sx">
      <button class="sx-t" data-sact="exp"><span>詳解</span><span class="sx-ans">正解 ${sol}</span><i aria-hidden="true">▾</i></button>
      <div class="sx-b"><div class="body">${esc(q.e)}</div></div>
    </div>
  </div>`;
  drawNav();
}
function flagBtn(q){
  const on=!!S.wrong[q.n];
  return `<button class="flag" data-sact="flag" data-on="${on?1:0}">${on?'已在錯題本':'標成錯題'}</button>`;
}
function drawEnd(){
  const len=deck.length, w=deck.filter(q=>S.wrong[q.n]).length, last=gi>=G.length-1;
  $('smain').innerHTML=`<div class="card done sdone scard ${anim}">
    <div class="big">✓</div>
    <h3>第 ${gi+1} 組看完了</h3>
    <p class="empty">這組 ${len} 題，其中 ${w} 題在錯題本。${last?'這是最後一組。':'往左滑或按「下一組」繼續。'}</p>
    <div class="sendb">
      ${last?'':'<button class="btn pri" data-sact="next">下一組</button>'}
      <button class="btn" data-sact="again">這組從頭再看</button>
    </div></div>`;
  drawNav();
}
function drawNav(){
  const end=pos>=deck.length, len=deck.length;
  $('snav').innerHTML=`
    <button class="btn" data-sact="prev"${pos===0&&gi===0?' disabled':''}>上一題</button>
    <button class="btn pri" data-sact="next"${end&&gi>=G.length-1?' disabled':''}>${end?'下一組':'下一題'}</button>
    ${end?'':`<button class="btn mid" data-sact="exp">${K.exp?'收起詳解':'看詳解'}</button>`}
    <span class="keys">第 ${gi+1} 組 · ${Math.min(pos+1,len)} / ${len}<em>← → 換題　空白鍵 詳解　M 錯題</em></span>`;
}
function setExp(on){
  K.exp=on; ksave();
  const sx=$('sx'); if(sx) sx.classList.toggle('open',on);
  const b=document.querySelector('#snav .mid'); if(b) b.textContent=on?'收起詳解':'看詳解';
  const t=document.querySelector('[data-sact="exp"][data-k]'); if(t) t.setAttribute('aria-pressed',String(on));
  if(on && sx) sx.scrollIntoView({block:isPhone()?'start':'nearest',behavior:'smooth'});
}

/* ---------- 側欄 / 手機的組別抽屜 ---------- */
function chip(k,v,label,n,on,extra){
  return `<button class="chip" data-sact="${k}" data-v="${v}" aria-pressed="${on}"${extra||''}>${label}${n!==undefined?`<em>${n}</em>`:''}</button>`;
}
function drawSide(){
  const s=$('sside'), st=s.scrollTop;
  const wn=Object.keys(S.wrong).length;
  const doms=[chip('dom','all','全部',DATA.length,K.dom==='all')]
    .concat(DOM_ORDER.map(c=>chip('dom',c,`<i class="dd"></i>${esc(dlabel(c))}`,(DOMQ[c]||[]).length,K.dom===c,` data-d="${c}"`)))
    .concat(chip('dom','wrong','錯題本',wn,K.dom==='wrong'));
  // 長度的題數跟著目前選的領域算
  const inDom = K.dom==='wrong'?DATA.filter(q=>S.wrong[q.n]):K.dom==='all'?DATA:DATA.filter(q=>DMAP[q.n]===K.dom);
  const tiers=[chip('tier','all','全部長度',undefined,!K.tiers.length)]
    .concat(TIER_KEYS.map(k=>{ const t=TIERS.find(x=>x.k===k);
      return chip('tier',k,t.label,inDom.filter(q=>q.t===k).length,K.tiers.includes(k)); }));
  const sizes=SIZES.map(([v,l])=>chip('size',v,l,undefined,K.size===v));
  const seenAll=Object.keys(K.seen).length;
  const theme=($('theme')||{}).textContent||'主題';
  s.innerHTML=`
    <div class="sheet-h"><b>組別與設定</b><button class="ic" data-sact="close">完成</button></div>
    <div class="panel"><h4>範圍</h4><div class="chips">${doms.join('')}</div><div class="chips">${tiers.join('')}</div>
      <div class="chips">${chip('shuf','0','依題號',undefined,!K.shuf)}${chip('shuf','1','隨機',undefined,K.shuf)}${K.shuf?'<button class="chip" data-sact="reshuf">重新洗牌</button>':''}</div></div>
    <div class="panel"><h4>每組題數</h4><div class="chips">${sizes.join('')}</div></div>
    <div class="panel"><h4>組別 <span class="sgc">${G.length} 組</span></h4>
      <div class="sgl" id="sgl">${G.length?G.map((g,i)=>rowHtml(g,i)).join(''):'<p class="empty">這個範圍沒有題目。</p>'}</div></div>
    <div class="panel"><h4>顯示</h4><div class="stg">
      <button class="ic" data-sact="only" aria-pressed="${K.only}">只看正解選項</button>
      <button class="ic" data-sact="exp" data-k="1" aria-pressed="${K.exp}">詳解一直展開</button>
      <button class="ic" data-sact="rnd" aria-pressed="${K.rnd}">組內隨機順序</button>
      <button class="ic" data-sact="hl" aria-pressed="${S.hl!==false}">重點標記</button>
      <button class="ic" data-sact="theme">${esc(theme)}</button>
    </div></div>
    <div class="panel"><h4>進度</h4>
      <div class="stat"><span>看過的題目</span><b>${seenAll} / ${DATA.length}</b></div>
      <div class="stat"><span>錯題本</span><b>${wn}</b></div>
      <p class="empty" style="margin:8px 0 10px">「標成錯題」和練習頁共用同一份錯題本，可以回練習用「只練錯題」測自己。</p>
      <button class="lnk" data-sact="reset" style="background:none;padding:0">清除看過紀錄</button>
    </div>`;
  s.scrollTop=st;
}
function rowHtml(g,i){
  const seen=g.filter(q=>K.seen[q.n]).length;
  const lo=Math.min(...g.map(q=>q.n)), hi=Math.max(...g.map(q=>q.n));
  return `<button class="sg${i===gi?' cur':''}${seen===g.length?' full':''}" data-sact="grp" data-i="${i}">
    <span class="n">第 ${i+1} 組</span><span class="r">${K.shuf?'隨機 '+g.length+' 題':`Q${lo}–${hi}`}</span><span class="p">${seen}/${g.length}</span>
    <span class="t"><i style="width:${seen/g.length*100}%"></i></span></button>`;
}
function syncRow(){
  const el=document.querySelector(`#sgl .sg[data-i="${gi}"]`); if(!el||!G[gi]) return;
  const tmp=document.createElement('div'); tmp.innerHTML=rowHtml(G[gi],gi).trim();
  el.replaceWith(tmp.firstChild);
}
function openSheet(){
  drawSide(); document.body.classList.add('s-nav');
  // 只捲動組別清單本身，不要把整個抽屜捲走
  const l=$('sgl'), c=l&&l.querySelector('.sg.cur');
  if(c) requestAnimationFrame(()=>{ l.scrollTop=c.offsetTop-l.clientHeight/2+c.offsetHeight/2; });
}
function closeSheet(){ document.body.classList.remove('s-nav'); }

/* ---------- 操作 ---------- */
function rescope(){ build(); drawSide(); drawMain(); window.scrollTo({top:0}); }
app.addEventListener('click',e=>{
  const b=e.target.closest('[data-sact],[data-go]'); if(!b||b.disabled) return;
  if(b.dataset.go){ const m=b.dataset.go; location.hash=''; if(typeof setMode==='function') setMode(m); return; }
  const v=b.dataset.v, q=deck[pos];
  switch(b.dataset.sact){
    case 'prev': go(-1); break;
    case 'next': go(1); break;
    case 'exp': setExp(!K.exp); break;
    case 'nav': openSheet(); break;
    case 'close': closeSheet(); break;
    case 'flag':
      if(!q) break;
      if(S.wrong[q.n]) delete S.wrong[q.n]; else S.wrong[q.n]={c:domName(q.n)};
      save(); b.outerHTML=flagBtn(q); drawSide(); break;
    case 'dom': K.dom=v; ksave(); rescope(); break;
    case 'shuf': K.shuf=v==='1'; ksave(); rescope(); break;
    case 'reshuf': {
      // 換一個 seed 重新洗；舊順序的進度用不到了，一併清掉
      const old='|r'+K.seed;
      for(const m of [K.at,K.pos]) for(const k of Object.keys(m)) if(k.endsWith(old)||k.includes(old+'|')) delete m[k];
      K.seed=(K.seed%1e6)+1+Math.floor(Math.random()*1e5); ksave(); rescope(); break; }
    case 'tier':
      // 長度可以複選；三種都選等於全部長度
      if(v==='all') K.tiers=[];
      else { const on=K.tiers.includes(v);
        K.tiers = on ? K.tiers.filter(x=>x!==v) : TIER_KEYS.filter(x=>x===v||K.tiers.includes(x));
        if(K.tiers.length===TIER_KEYS.length) K.tiers=[]; }
      ksave(); rescope(); break;
    case 'size': K.size=+v; ksave(); rescope(); break;
    case 'grp':
      gi=+b.dataset.i; loadGroup(); ksave(); closeSheet();
      anim='in-r'; drawMain(); anim=''; drawSide(); window.scrollTo({top:0}); break;
    case 'again': pos=0; K.pos[gkey()]=0; ksave(); anim='in-l'; drawMain(); anim=''; break;
    case 'only': K.only=!K.only; ksave(); drawSide(); drawMain(); break;
    case 'rnd': { const cur=q&&q.n; K.rnd=!K.rnd; ksave(); loadGroup();
      const i=deck.findIndex(x=>x.n===cur); if(i>=0) pos=i; drawSide(); drawMain(); break; }
    case 'hl': S.hl=(S.hl===false); save(); drawSide(); drawMain(); break;
    case 'theme': { const t=$('theme'); if(t) t.click(); drawSide(); break; }
    case 'reset':
      if(confirm('清除背題的「看過」紀錄？錯題本和練習紀錄不受影響。')){
        K.seen={}; K.pos={}; K.at={}; ksave(); rescope(); }
      break;
  }
});

addEventListener('keydown',e=>{
  if(!document.body.classList.contains('mode-study')) return;
  if(e.key==='Escape'){ closeSheet(); return; }
  if(e.target.tagName==='INPUT'||e.metaKey||e.ctrlKey||e.altKey) return;
  if(document.body.classList.contains('s-nav')) return;
  if(e.key==='ArrowRight'){ e.preventDefault(); go(1); }
  else if(e.key==='ArrowLeft'){ e.preventDefault(); go(-1); }
  else if(e.key===' '||e.key==='Enter'){ e.preventDefault(); if(pos<deck.length) setExp(!K.exp); else go(1); }
  else if(e.key.toLowerCase()==='m'){ const f=document.querySelector('#smain [data-sact="flag"]'); if(f) f.click(); }
});

/* ---------- 左右滑動換題：卡片跟著手指走，放開後滑出去 ---------- */
(function(){
  const m=$('smain');
  let x0=null,y0=0,t0=0,axis=null,card=null;
  m.addEventListener('touchstart',e=>{
    if(e.touches.length!==1){x0=null;return;}
    x0=e.touches[0].clientX; y0=e.touches[0].clientY; t0=Date.now(); axis=null;
    card=m.querySelector('.scard');
  },{passive:true});
  m.addEventListener('touchmove',e=>{
    if(x0===null||!card) return;
    const dx=e.touches[0].clientX-x0, dy=e.touches[0].clientY-y0;
    if(!axis){ if(Math.abs(dx)<10&&Math.abs(dy)<10) return;
      axis=Math.abs(dx)>Math.abs(dy)*1.3?'x':'y'; }
    if(axis!=='x') return;
    // 到頭或到底時阻力變大，提示沒有下一張
    const edge=(dx>0&&pos===0&&gi===0)||(dx<0&&pos>=deck.length&&gi>=G.length-1);
    card.style.transition='none';
    card.style.transform=`translateX(${edge?dx/4:dx}px) rotate(${(edge?dx/4:dx)/40}deg)`;
  },{passive:true});
  m.addEventListener('touchend',e=>{
    if(x0===null) return;
    const dx=e.changedTouches[0].clientX-x0, dt=Date.now()-t0, c=card;
    const isX=axis==='x'; x0=null; axis=null; card=null;
    if(!c||!isX) return;
    const fling=Math.abs(dx)>80||(Math.abs(dx)>35&&dt<260);
    const d=dx<0?1:-1;
    const can=d>0 ? !(pos>=deck.length&&gi>=G.length-1) : !(pos===0&&gi===0);
    if(fling&&can&&!String(getSelection())){
      c.style.transition='transform .16s ease-in,opacity .16s ease-in';
      c.style.transform=`translateX(${dx<0?-115:115}%)`; c.style.opacity='0';
      setTimeout(()=>go(d),150);
    } else {
      c.style.transition='transform .22s ease'; c.style.transform='';
    }
  },{passive:true});
  m.addEventListener('touchcancel',()=>{ if(card){card.style.transform='';} x0=null; card=null; },{passive:true});
})();

/* ---------- routing：#study 進入背題 ---------- */
function route(){
  const on=location.hash==='#study';
  document.body.classList.toggle('mode-study',on);
  if(on){
    if(typeof closeSheets==='function') closeSheets();
    build(); drawSide(); drawMain(); window.scrollTo(0,0);
  } else closeSheet();
}
addEventListener('hashchange',route);
route();
})();
