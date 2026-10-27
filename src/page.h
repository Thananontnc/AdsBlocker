#pragma once
// Dashboard HTML for the ESP8266 AdBlocker web UI, kept in its own header so the
// Arduino IDE preprocessor doesn't choke on the inlined markup.
// Minimal, mobile-first, follows the phone's light/dark setting. Four tabs: Home,
// Devices, Sites, Settings. Device names live in the viewer's browser (localStorage),
// so the board spends no RAM on them.

const char PAGE[] PROGMEM = R"HTML(<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>AdBlock</title><style>
:root{--bg:#fafafa;--card:#fff;--fg:#18181b;--mut:#71717a;--line:#ececee;--soft:#f4f4f5;--ok:#16a34a;--okbg:#f0fdf4;--warn:#d97706;--warnbg:#fffbeb;--bad:#dc2626;--badbg:#fef2f2}
@media(prefers-color-scheme:dark){:root{--bg:#09090b;--card:#111113;--fg:#fafafa;--mut:#a1a1aa;--line:#232326;--soft:#1a1a1d;--ok:#22c55e;--okbg:#0b1f13;--warn:#f59e0b;--warnbg:#221a08;--bad:#f87171;--badbg:#2a1111}}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans Thai",sans-serif}
.wrap{max-width:640px;margin:auto;padding:max(16px,env(safe-area-inset-top)) 16px 48px}
header{display:flex;align-items:center;justify-content:space-between;margin:4px 0 16px}
header b{font-size:18px;letter-spacing:-.01em}
.pill{display:inline-flex;align-items:center;gap:6px;font-size:13px;color:var(--mut)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--ok)}.off .dot{background:var(--warn)}.err .dot{background:var(--bad)}
nav{display:flex;background:var(--soft);border-radius:12px;padding:3px;margin-bottom:20px;position:sticky;top:8px;z-index:5}
nav button{flex:1;min-width:0;border:0;background:none;color:var(--mut);font:inherit;font-size:13.5px;padding:8px 0;border-radius:9px;cursor:pointer}
nav button.on{background:var(--card);color:var(--fg);font-weight:600;box-shadow:0 1px 2px #0000000f}
section[data-tab]{display:none}section.on{display:block}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:4px 16px;margin-bottom:14px}
.card.pad{padding:18px 16px}
.lbl{font-size:12px;font-weight:600;color:var(--mut);text-transform:uppercase;letter-spacing:.06em;margin:22px 4px 8px}
.big{font-size:44px;font-weight:700;letter-spacing:-.03em;line-height:1.1}
.mut{color:var(--mut)}.sm{font-size:13px}
.state{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:16px;padding-top:14px;border-top:1px solid var(--line)}
.state b{display:flex;align-items:center;gap:8px}.state.off b{color:var(--warn)}
.row{display:flex;align-items:center;gap:12px;padding:13px 0;border-top:1px solid var(--line);min-height:52px}
.card>.row:first-child{border-top:0}
.row .t{flex:1;min-width:0;overflow-wrap:anywhere}.row .t small{display:block;color:var(--mut);font-size:13px}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:14px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:12px}
.stat b{display:block;font-size:17px}.stat span{font-size:12px;color:var(--mut)}
button.b{font:inherit;font-size:14px;border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:10px;padding:7px 13px;cursor:pointer;white-space:nowrap}
button.b:active{opacity:.7}button.p{background:var(--fg);color:var(--bg);border-color:var(--fg);font-weight:600}
button.r{color:var(--bad)}button.lnk{border:0;background:none;color:var(--mut);padding:7px 4px}
.chips{display:flex;gap:6px}
.sw{position:relative;flex:none;width:44px;height:26px}.sw input{position:absolute;opacity:0;width:100%;height:100%;margin:0;cursor:pointer;z-index:1}
.sw i{position:absolute;inset:0;border-radius:99px;background:var(--line)}.sw i::after{content:"";position:absolute;top:3px;left:3px;width:20px;height:20px;border-radius:50%;background:#fff;box-shadow:0 1px 2px #0003}
.sw input:checked+i{background:var(--ok)}.sw input:checked+i::after{left:21px}.ready .sw i,.ready .sw i::after{transition:.18s}
.sw input:focus-visible+i{outline:2px solid var(--fg);outline-offset:2px}
.ck{flex:none;width:44px;text-align:center;color:var(--ok);font-weight:700}
.tag{font-size:11px;font-weight:600;color:var(--bad);background:var(--badbg);border-radius:6px;padding:1px 6px;margin-left:6px}
.k1{color:var(--warn)}.k2{color:var(--bad)}
.bar{height:3px;border-radius:9px;background:var(--line);margin-top:7px;overflow:hidden}.bar i{display:block;height:100%;background:var(--bad);opacity:.7}
form.in{display:flex;gap:8px;padding:14px 0}
input.tx{flex:1;min-width:0;font:inherit;padding:10px 12px;border:1px solid var(--line);border-radius:10px;background:var(--bg);color:var(--fg)}
input.tx:focus{outline:2px solid var(--fg);outline-offset:-1px}
.seg{display:inline-flex;background:var(--soft);border-radius:10px;padding:3px;margin:4px 0 2px}
.seg button{border:0;background:none;font:inherit;font-size:13px;color:var(--mut);padding:5px 12px;border-radius:7px;cursor:pointer}.seg button.on{background:var(--card);color:var(--fg);font-weight:600}
select.tx{flex:1;min-width:0;font:inherit;font-size:14px;padding:8px 10px;border:1px solid var(--line);border-radius:10px;background:var(--card);color:var(--fg)}
.bar2{display:flex;gap:8px;align-items:center;margin-bottom:10px}.bar2 .seg{margin:0}
.st1,.st2{display:inline-block;white-space:nowrap;font-size:11px;font-weight:600;color:var(--bad);background:var(--badbg);border-radius:6px;padding:1px 6px;margin-left:6px}
.empty{color:var(--mut);font-size:14px;padding:16px 0;text-align:center}
.ico{flex:none;width:36px;height:36px;border-radius:10px;background:var(--soft);display:grid;place-items:center;color:var(--mut)}
.ico svg{width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
.name{border:0;background:none;color:inherit;font:inherit;font-weight:600;padding:0;cursor:pointer;text-align:left}
.kv{display:grid;grid-template-columns:auto 1fr;gap:6px 16px;padding:14px 0;font-size:14px}.kv span:nth-child(odd){color:var(--mut)}.kv span:nth-child(even){text-align:right;overflow-wrap:anywhere}
.alert{background:var(--badbg);color:var(--bad);border-radius:12px;padding:10px 14px;margin-bottom:14px;font-size:13.5px;display:none}
input[type=file]{font-size:13px;flex:1;min-width:0;width:0;color:var(--mut)}
.prog{height:3px;background:var(--line);border-radius:9px;overflow:hidden;display:none;margin-bottom:12px}.prog i{display:block;height:100%;width:0;background:var(--fg)}
#toast{position:fixed;left:50%;bottom:max(20px,env(safe-area-inset-bottom));transform:translate(-50%,16px);opacity:0;background:var(--fg);color:var(--bg);padding:10px 16px;border-radius:12px;font-size:14px;transition:.2s;pointer-events:none;max-width:90vw;text-align:center;z-index:9}
#toast.show{opacity:1;transform:translate(-50%,0)}
</style></head><body><div class=wrap>
<header><b>AdBlock</b><span class=pill id=pill><span class=dot></span><span id=pillT>&hellip;</span></span></header>
<div class=alert id=credwarn>Default passwords are in use. Set WEB_PASS in secrets.h and reflash.</div>
<nav id=nav><button data-t=home class=on>Home</button><button data-t=activity>Activity</button><button data-t=devices>Devices</button><button data-t=sites>Sites</button><button data-t=settings>Settings</button></nav>

<section data-tab=home class=on>
<div class="card pad"><div class=big id=nBlocked>&ndash;</div><div class="mut sm" id=nSub>requests blocked</div>
<div class=state id=state><b id=stateT><span class=dot></span>Protected</b>
<div class=chips id=pauseC><button class="b lnk" onclick=pause(300)>5 min</button><button class="b lnk" onclick=pause(1800)>30 min</button><button class=b onclick=pause(3600)>Pause 1 h</button></div>
<button class="b p" id=resumeB onclick=resume() style=display:none>Resume</button></div></div>
<div class=stats><div class=stat><b id=nDev>&ndash;</b><span>Devices</span></div><div class=stat><b id=nDom>&ndash;</b><span>Sites listed</span></div><div class=stat><b id=nUp>&ndash;</b><span>Uptime</span></div></div>
<div class=lbl>Protection</div><div class=card>
<div class=row><span class=ck>&#10003;</span><div class=t>Ads, adult, gambling &amp; scams<small id=pList>Blocklist</small></div></div>
<div class=row><span class=ck>&#10003;</span><div class=t>SafeSearch<small>Google, YouTube and Bing</small></div></div>
<div class=row><label class=sw><input type=checkbox id=tRemote onchange="scamSet('remote',this)"><i></i></label><div class=t>Remote-control apps<small>AnyDesk, TeamViewer and others used by scam callers</small></div></div>
<div class=row><label class=sw><input type=checkbox id=tBank onchange="scamSet('bank',this)"><i></i></label><div class=t>Fake bank &amp; government sites<small>Copies of Krungthai, SCB, KBank, PromptPay, PEA&hellip;</small></div></div>
</div>
<div id=alertsW style=display:none><div class=lbl>Scams stopped</div><div class=card id=hits></div></div>
</section>

<section data-tab=activity>
<div class=bar2><select class=tx id=fDev><option value="">All devices</option></select>
<div class=seg id=fSeg><button data-f=all class=on>All</button><button data-f=blk>Blocked</button></div></div>
<div class=card id=logl><div class=empty>Loading&hellip;</div></div>
<p class="mut sm" style="margin:0 4px">The last 64 sites looked up since the box started. <b>Block</b> blocks that site and all its sub-sites.</p></section>

<section data-tab=devices><div class=card id=devs></div><p class="mut sm" style="margin:0 4px">Tap a name to rename it. Names are saved on this phone or computer.</p></section>

<section data-tab=sites><div class=card>
<form class=in id=addf><input class=tx id=dom placeholder="Website or link" autocomplete=off autocapitalize=off spellcheck=false><button class="b p">Block</button><button type=button class=b onclick=allowSite()>Allow</button></form></div>
<div class=seg id=sseg><button data-s=custom class=on>Blocked</button><button data-s=allow>Always allowed</button></div>
<div class=card id=slist style=margin-top:8px></div>
<p class="mut sm" style="margin:0 4px">Thai addresses like &#3619;&#3633;&#3585;.com work. Blocking a site also blocks its sub-sites. Allowed sites are never blocked by anything.</p></section>

<section data-tab=settings>
<div class=card><div class=kv id=sys></div></div>
<div class=lbl>Blocklist</div><div class=card>
<form class=in id=upf><input type=file id=blf accept=.bin><button class="b p">Upload</button></form><div class=prog id=upp><i></i></div>
<div class=row><div class=t>Auto-update<small id=ustat>&ndash;</small></div></div>
<form class=in id=updf style=padding-top:0><input class=tx id=uurl placeholder="https://&hellip;/blocklist.bin"><input class=tx id=uiv type=number min=1 style="flex:0 0 64px" title=hours><button class=b>Save</button></form></div>
<div class=lbl>Firmware</div><div class=card>
<form class=in id=fwf><input type=file id=fwb accept=.bin><button class="b p">Flash</button></form><div class=prog id=fwp><i></i></div></div>
<div class=lbl>WiFi</div><div class=card><div class=row><div class=t>Forget WiFi<small>Restarts into setup mode</small></div><button class="b r" onclick=forgetWifi()>Forget</button></div></div>
</section>
</div><div id=toast></div><script>
const $=id=>document.getElementById(id),H={'X-Requested-With':'esp-adblock'};let S=null,tt,list='custom',cur='home',LOG=null,flt='all',DN={};
function toast(m){let t=$('toast');t.textContent=m;t.classList.add('show');clearTimeout(tt);tt=setTimeout(()=>t.classList.remove('show'),2400)}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function fmt(n){return Number(n).toLocaleString()}
function short(n){return n>=1e6?(n/1e6).toFixed(1)+'M':n>=1e4?Math.round(n/1e3)+'k':fmt(n)}
function dur(s){let d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return d?d+'d '+h+'h':h?h+'h '+m+'m':m?m+'m':s+'s'}
function ago(s){return s<60?'just now':s<3600?Math.floor(s/60)+' min ago':s<86400?Math.floor(s/3600)+' h ago':Math.floor(s/86400)+' d ago'}
// punycode (RFC 3492) decode so Thai/IDN domains show in their own script
function pdec(s){try{let o=[],i=0,n=128,b=72,x=s.lastIndexOf('-');if(x>0)o=[...s.slice(0,x)];
for(let p=x>0?x+1:0;p<s.length;){let oi=i,w=1;for(let k=36;;k+=36){let c=s.charCodeAt(p++),d=c-48<10?c-22:c-65<26?c-65:c-97;
i+=d*w;let t=k<=b?1:k>=b+26?26:k-b;if(d<t)break;w*=36-t}let L=o.length+1,dl=i-oi;dl=oi==0?Math.floor(dl/700):dl>>1;dl+=Math.floor(dl/L);
let k=0;for(;dl>455;k+=36)dl=Math.floor(dl/35);b=k+Math.floor(36*dl/(dl+38));n+=Math.floor(i/L);i%=L;o.splice(i++,0,String.fromCodePoint(n))}
return o.join('')}catch(e){return s}}
function uni(d){return d.split('.').map(l=>l.startsWith('xn--')?pdec(l.slice(4)):l).join('.')}
function toHost(v){v=v.trim();if(!v)return'';if(!/^[a-z][a-z0-9+.-]*:\/\//i.test(v))v='http://'+v;try{return new URL(v).hostname.replace(/^www\./,'')}catch(e){return''}}
function base(d){let p=d.split('.'),n=p.length,cc=n>2&&p[n-1].length==2&&/^(co|or|go|ac|in|mi|com|net|org|gov|edu)$/.test(p[n-2]);return p.slice(cc?-3:-2).join('.')}
async function api(u,ok){try{let r=await fetch(u,{headers:H});if(r.status==401){toast('Password needed');return false}
if(!r.ok){toast('Failed ('+r.status+')');return false}if(ok)toast(ok);await load();return await r.text()}catch(e){toast('Box not reachable');return false}}
function names(){try{return JSON.parse(localStorage.getItem('devnames')||'{}')}catch(e){return{}}}
function setName(mac,n){let m=names();if(n)m[mac]=n;else delete m[mac];try{localStorage.setItem('devnames',JSON.stringify(m))}catch(e){}}
function tab(t){document.querySelectorAll('nav button').forEach(b=>b.classList.toggle('on',b.dataset.t==t));
document.querySelectorAll('section[data-tab]').forEach(s=>s.classList.toggle('on',s.dataset.tab==t));cur=t;try{sessionStorage.setItem('tab',t)}catch(e){}if(t=='activity')loadLog()}
$('nav').onclick=e=>{let b=e.target.closest('button');if(b)tab(b.dataset.t)};
$('sseg').onclick=e=>{let b=e.target.closest('button');if(!b)return;list=b.dataset.s;[...$('sseg').children].forEach(x=>x.classList.toggle('on',x==b));render()};
function pause(s){api('/pause?s='+s,'Paused for '+dur(s))}
function resume(){api('/resume','Protection is on')}
function scamSet(k,el){api('/scamset?'+k+'='+(el.checked?1:0),el.checked?'On':'Off')}
function site(path,msg){let h=toHost($('dom').value);if(!h||h.indexOf('.')<0){toast('Enter a website');return}
api(path+encodeURIComponent(h),msg+' '+uni(h)).then(r=>{if(r!==false)$('dom').value=''})}
$('addf').onsubmit=e=>{e.preventDefault();site('/addblock?d=','Blocked')};
function allowSite(){site('/allow?d=','Allowed')}
$('slist').onclick=e=>{let b=e.target.closest('[data-rm]');if(b)api((list=='custom'?'/unblock':'/unallow')+'?d='+encodeURIComponent(b.dataset.rm),'Removed')};
$('hits').onclick=e=>{let b=e.target.closest('[data-allow]');if(b&&confirm('Always allow '+uni(b.dataset.allow)+'? Only if you are sure it is real and safe.'))api('/allow?d='+encodeURIComponent(b.dataset.allow),'Allowed')};
$('devs').onclick=e=>{let b=e.target.closest('[data-ip]');if(b){let on=b.dataset.ban=='1';
if(on||confirm('Cut this device off the internet?'))api('/ban?ip='+b.dataset.ip,on?'Device allowed':'Device blocked')}
let n=e.target.closest('[data-mac]');if(n){let v=prompt('Device name (empty = automatic)',names()[n.dataset.mac]||n.dataset.def||'');if(v!==null){setName(n.dataset.mac,v.trim());render()}}};
$('updf').onsubmit=e=>{e.preventDefault();api('/setupdate?u='+encodeURIComponent($('uurl').value.trim())+'&h='+(parseInt($('uiv').value)||24),'Saved')};
function forgetWifi(){if(confirm('Forget WiFi and restart into setup mode?'))api('/forgetwifi','Restarting')}
function upload(form,file,url,bar,done){$(form).onsubmit=e=>{e.preventDefault();let f=$(file).files[0];if(!f){toast('Choose a file');return}
let x=new XMLHttpRequest(),p=$(bar),i=p.firstChild;p.style.display='block';i.style.width='0';x.open('POST',url);x.setRequestHeader('X-Requested-With','esp-adblock');
x.upload.onprogress=e=>{if(e.lengthComputable)i.style.width=(e.loaded/e.total*100)+'%'};
x.onload=()=>{p.style.display='none';toast(x.status==200?done:'Failed: '+x.responseText);$(file).value='';setTimeout(load,800)};
x.onerror=()=>{p.style.display='none';toast(url=='/update'?done:'Upload failed')};let d=new FormData();d.append('f',f);x.send(d)}}
upload('upf','blf','/upload','upp','Blocklist updated');upload('fwf','fwb','/update','fwp','Flashed — reload in 20 s');
const OS=['','Apple device','iPhone','iPad','Mac','Apple TV','Android','Android TV','Windows PC','Linux','Smart TV','PlayStation','Xbox','Nintendo'];
const IC={phone:'<rect x="7" y="2.5" width="10" height="19" rx="2.5"/><path d="M11 18.5h2"/>',tablet:'<rect x="4.5" y="2.5" width="15" height="19" rx="2.5"/><path d="M11 18.5h2"/>',
laptop:'<rect x="4" y="4.5" width="16" height="11" rx="1.5"/><path d="M2 19.5h20"/>',tv:'<rect x="2.5" y="4" width="19" height="13" rx="2"/><path d="M8 21h8M12 17v4"/>',
game:'<path d="M6 8h12a4 4 0 0 1 4 4v1a3 3 0 0 1-5.4 1.8L15 13H9l-1.6 1.8A3 3 0 0 1 2 13v-1a4 4 0 0 1 4-4z"/><path d="M7 11v2M6 12h2"/>',
other:'<circle cx="12" cy="12" r="8.5"/><path d="M12 8v4l2.5 2"/>'};
function icon(os){let k=[2,6].includes(os)?'phone':os==3?'tablet':[4,8,9].includes(os)?'laptop':[5,7,10].includes(os)?'tv':[11,12,13].includes(os)?'game':os==1?'phone':'other';
return`<span class=ico><svg viewBox="0 0 24 24">${IC[k]}</svg></span>`}
function devName(ip){return DN[ip]||ip}
$('fSeg').onclick=e=>{let b=e.target.closest('button');if(!b)return;flt=b.dataset.f;[...$('fSeg').children].forEach(x=>x.classList.toggle('on',x==b));renderLog()};
$('fDev').onchange=renderLog;
$('logl').onclick=e=>{let b=e.target.closest('[data-blk]');if(b){let d=b.dataset.blk;if(confirm('Block '+uni(d)+' and its sub-sites?'))api('/addblock?d='+encodeURIComponent(d),'Blocked '+uni(d)).then(loadLog)}
let a=e.target.closest('[data-alw]');if(a){let d=a.dataset.alw;if(confirm('Always allow '+uni(d)+'?'))api('/allow?d='+encodeURIComponent(d),'Allowed '+uni(d)).then(loadLog)}};
async function loadLog(){try{let r=await fetch('/log.json',{headers:H,cache:'no-store'});if(r.status==401){$('logl').innerHTML='<div class=empty>Enter the dashboard password to see activity.</div>';return}
LOG=await r.json();renderLog()}catch(e){}}
function renderLog(){if(!LOG)return;let dv=$('fDev').value,L=LOG.filter(e=>(!dv||e.ip==dv)&&(flt=='all'||e.s>0));
$('logl').innerHTML=L.map(e=>{let d=(e.t?'\u2026':'')+uni(e.d),bs=base(e.d);
return row(esc(d)+(e.s==2?'<span class=st2>Scam</span>':e.s==1?'<span class=st1>Blocked</span>':''),esc(devName(e.ip))+' \u00b7 '+ago(e.ago)+(e.n>1?' \u00b7 '+e.n+'\u00d7':''),
e.s?`<button class="b lnk" data-alw="${esc(bs)}">Allow</button>`:`<button class="b lnk" data-blk="${esc(bs)}">Block</button>`)}).join('')||'<div class=empty>Nothing yet.</div>'}
function row(t,sub,btn){return`<div class=row><div class=t>${t}${sub?`<small>${sub}</small>`:''}</div>${btn||''}</div>`}
function render(){if(!S)return;let s=S,on=s.blocking!==false,total=s.blocked+s.allowed,nm=names(),sc=s.scam||{hits:[]};
$('pill').className='pill'+(on?'':' off');$('pillT').textContent=on?'Protected':'Paused';
$('state').classList.toggle('off',!on);$('stateT').innerHTML='<span class=dot></span>'+(on?'Protected':s.resumeIn>0?'Paused · '+dur(s.resumeIn):'Paused');
$('pauseC').style.display=on?'':'none';$('resumeB').style.display=on?'none':'';
$('credwarn').style.display=s.defcreds?'block':'none';
$('nBlocked').textContent=fmt(s.blocked);$('nSub').textContent='requests blocked'+(total?' · '+Math.round(s.blocked*100/total)+'% of traffic':'');
$('nDev').textContent=s.clients.length;$('nDom').textContent=short(s.domains);$('nUp').textContent=dur(s.up);
$('pList').textContent=fmt(s.domains)+' sites on the blocklist';
$('tRemote').checked=!!sc.remote;$('tBank').checked=!!sc.bank;
let cs=s.clients.slice().sort((a,b)=>(b.blocked+b.allowed)-(a.blocked+a.allowed)),ipn=DN={};cs.forEach(c=>DN[c.ip]=nm[c.mac]||c.name||(OS[c.os]?OS[c.os]+' \u00b7 '+c.ip.split('.').pop():c.ip));
let fd=$('fDev'),fv=fd.value,opts='<option value="">All devices</option>'+cs.map(c=>`<option value="${esc(c.ip)}">${esc(DN[c.ip])}</option>`).join('');if(fd.dataset.o!=opts){fd.innerHTML=opts;fd.value=fv;fd.dataset.o=opts}
$('alertsW').style.display=sc.hits.length?'':'none';
$('hits').innerHTML=sc.hits.map(h=>row(esc(uni(h.d)),`<b class=k${h.k}>${h.k==1?'Remote-control app':'Fake bank site'}</b> · ${esc(ipn[h.ip]||h.ip)} · ${ago(h.ago)}`,`<button class="b lnk" data-allow="${esc(base(h.d))}">Allow</button>`)).join('');
$('devs').innerHTML=cs.map(c=>{let t=c.blocked+c.allowed,pc=t?Math.round(c.blocked*100/t):0,my=nm[c.mac],os=OS[c.os]||'',title=my||c.name||os||c.ip;
let sub=[title!=os&&os,title!=c.ip&&c.ip,fmt(c.blocked)+' of '+fmt(t)+' blocked'].filter(Boolean).join(' \u00b7 ');
return`<div class=row>${icon(c.os)}<div class=t><button class=name data-mac="${esc(c.mac)}" data-def="${esc(c.name||'')}">${esc(title)}</button>${c.banned?'<span class=tag>Blocked</span>':''}<small>${esc(sub)}</small><div class=bar><i style="width:${pc}%"></i></div></div>
<button class="b${c.banned?'':' lnk'}" data-ip="${esc(c.ip)}" data-ban="${c.banned?1:0}">${c.banned?'Unblock':'Block'}</button></div>`}).join('')||'<div class=empty>No devices yet. Set your router\'s DNS to '+esc(s.ip)+'.</div>';
let L=s[list]||[];[...$('sseg').children].forEach(b=>b.textContent=(b.dataset.s=='custom'?'Blocked':'Always allowed')+' '+(s[b.dataset.s]||[]).length);
$('slist').innerHTML=L.map(d=>row(esc(uni(d)),uni(d)!=d?esc(d):'',`<button class="b lnk" data-rm="${esc(d)}">Remove</button>`)).join('')||'<div class=empty>Nothing here yet.</div>';
$('sys').innerHTML=[['Address',s.ip],['WiFi',(s.ssid||'?')+' · '+s.rssi+' dBm'],['Memory',Math.round(s.heap/1024)+' KB free · '+(100-s.frag)+'% in one piece'],
['Uptime',dur(s.up)],['Last restart',s.boot],['Requests',fmt(total)]].map(r=>`<span>${r[0]}</span><span>${esc(r[1])}</span>`).join('');
$('ustat').textContent=(s.upurl?'Every '+s.upiv+' h · ':'Off · ')+'last: '+(s.upstat||'–');
if(document.activeElement!=$('uurl'))$('uurl').value=s.upurl||'';if(document.activeElement!=$('uiv'))$('uiv').value=s.upiv||24}
async function load(){try{let r=await fetch('/stats.json',{cache:'no-store'});S=await r.json();render();
if(!document.body.classList.contains('ready'))setTimeout(()=>document.body.classList.add('ready'),500)}
catch(e){$('pill').className='pill err';$('pillT').textContent='Offline'}}
try{let t=sessionStorage.getItem('tab');if(t)tab(t)}catch(e){}
load();setInterval(()=>{if(!document.hidden){load();if(cur=='activity')loadLog()}},3000);
</script></body></html>)HTML";
