#pragma once
// Dashboard HTML for the ESP8266 AdBlocker web UI, kept in its own header so the
// Arduino IDE preprocessor doesn't choke on the inlined markup.
// Mobile-first, follows the phone's light/dark setting. Device names are stored in the
// viewer's browser (localStorage), so the board spends no RAM on them.

const char PAGE[] PROGMEM = R"HTML(<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name=theme-color content="#0f172a"><title>Home AdBlock</title><style>
:root{--bg:#f1f5f9;--card:#fff;--text:#0f172a;--muted:#64748b;--line:#e2e8f0;--soft:#f8fafc;
--ok:#16a34a;--okbg:#dcfce7;--warn:#ea580c;--warnbg:#ffedd5;--bad:#dc2626;--badbg:#fee2e2;--acc:#2563eb;--accbg:#dbeafe}
@media(prefers-color-scheme:dark){:root{--bg:#0b1120;--card:#131c2e;--text:#e2e8f0;--muted:#94a3b8;--line:#22304a;--soft:#0f1729;
--ok:#4ade80;--okbg:#0f2e1c;--warn:#fb923c;--warnbg:#36200f;--bad:#f87171;--badbg:#3a1414;--acc:#60a5fa;--accbg:#13284a}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans Thai",sans-serif}
.wrap{max-width:960px;margin:auto;padding:16px 16px 40px}
header{display:flex;align-items:center;gap:10px;margin-bottom:14px}
header .logo{font-size:26px}header h1{margin:0;font-size:19px;flex:1}header small{display:block;color:var(--muted);font-weight:400;font-size:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:16px;margin-bottom:14px}
.card h2{margin:0 0 12px;font-size:15px;display:flex;align-items:center;gap:8px}.card h2 .n{margin-left:auto;color:var(--muted);font-weight:500;font-size:13px}
.hero{display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.ring{width:64px;height:64px;border-radius:50%;display:grid;place-items:center;font-size:30px;background:var(--okbg);flex:none}
.hero.off .ring{background:var(--warnbg)}
.hero .st{flex:1;min-width:170px}.hero .st b{font-size:20px;display:block;color:var(--ok)}.hero.off .st b{color:var(--warn)}
.hero .st span{color:var(--muted);font-size:13px}
.seg{display:flex;gap:8px;flex-wrap:wrap;width:100%}
button{font:inherit;border:1px solid var(--line);background:var(--soft);color:var(--text);border-radius:10px;padding:10px 14px;cursor:pointer;min-height:42px}
button:hover{border-color:var(--acc)}button:active{transform:scale(.98)}
button.pri{background:var(--acc);border-color:var(--acc);color:#fff;font-weight:600}
button.go{background:var(--ok);border-color:var(--ok);color:#fff;font-weight:600}
button.del{color:var(--bad)}button.sm{min-height:34px;padding:6px 11px;font-size:13px}
.seg button{flex:1;min-width:84px}
.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-bottom:14px}
@media(min-width:700px){.grid{grid-template-columns:repeat(4,1fr)}}
.stat{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:12px 14px}
.stat .v{font-size:22px;font-weight:700}.stat .l{color:var(--muted);font-size:12px}
.v.bad{color:var(--bad)}.v.ok{color:var(--ok)}
.chips{display:flex;flex-wrap:wrap;gap:8px}
.chip{background:var(--okbg);color:var(--ok);border-radius:99px;padding:5px 11px;font-size:13px;font-weight:600}
.row{display:flex;gap:8px}
input[type=text],input[type=number],input:not([type]){font:inherit;flex:1;min-width:0;padding:11px 12px;border-radius:10px;border:1px solid var(--line);background:var(--soft);color:var(--text)}
input:focus{outline:2px solid var(--acc);outline-offset:-1px}
.list{margin-top:10px}.item{display:flex;align-items:center;gap:10px;padding:10px 0;border-top:1px solid var(--line)}
.item:first-child{border-top:0}.item .t{flex:1;min-width:0;overflow-wrap:anywhere}.item .t small{display:block;color:var(--muted);font-size:12px}
.empty{color:var(--muted);font-size:14px;padding:6px 0}
.bar{height:6px;border-radius:9px;background:var(--line);overflow:hidden;margin-top:6px}.bar i{display:block;height:100%;background:var(--bad)}
.tag{font-size:11px;font-weight:700;background:var(--badbg);color:var(--bad);border-radius:6px;padding:1px 6px;margin-left:6px}
.dev .name{background:none;border:0;padding:0;min-height:0;font-weight:600;text-align:left;cursor:text}
details.card{padding:0}details.card summary{padding:16px;font-weight:600;cursor:pointer;list-style:none;display:flex;justify-content:space-between}
details.card summary::after{content:"\25BE";color:var(--muted)}details[open].card summary::after{content:"\25B4"}
details.card .in{padding:0 16px 16px}
.sec{border-top:1px solid var(--line);padding-top:14px;margin-top:14px}.sec:first-child{border:0;margin:0;padding:0}
.sec h3{margin:0 0 4px;font-size:14px}.hint{color:var(--muted);font-size:12.5px;margin:0 0 10px}
.kv{display:grid;grid-template-columns:auto 1fr;gap:4px 14px;font-size:13.5px}.kv span:nth-child(odd){color:var(--muted)}
input[type=file]{font-size:13px;max-width:100%}
.prog{height:6px;border-radius:9px;background:var(--line);overflow:hidden;margin-top:8px;display:none}.prog i{display:block;height:100%;width:0;background:var(--acc);transition:width .2s}
.alert{background:var(--badbg);color:var(--bad);border-radius:12px;padding:10px 14px;margin-bottom:14px;font-size:13.5px;display:none}
#toast{position:fixed;left:50%;bottom:22px;transform:translateX(-50%) translateY(30px);opacity:0;background:var(--text);color:var(--bg);padding:11px 18px;border-radius:12px;font-size:14px;transition:.25s;pointer-events:none;max-width:90vw;text-align:center;z-index:9}
#toast.show{opacity:1;transform:translateX(-50%) translateY(0)}

.tog{display:flex;gap:12px;align-items:flex-start;padding:10px 0;border-top:1px solid var(--line);cursor:pointer}
.tog:first-of-type{border-top:0;padding-top:0}.tog input{position:absolute;opacity:0;pointer-events:none}
.sw{flex:none;width:46px;height:28px;border-radius:99px;background:var(--line);position:relative;margin-top:2px}
.sw::after{content:"";position:absolute;top:3px;left:3px;width:22px;height:22px;border-radius:50%;background:#fff;box-shadow:0 1px 3px #0003}
.ready .sw,.ready .sw::after{transition:.2s}
.tog input:checked+.sw{background:var(--ok)}.tog input:checked+.sw::after{left:21px}
.tog input:focus-visible+.sw{outline:2px solid var(--acc);outline-offset:2px}
.tog small{display:block;color:var(--muted);font-size:12.5px;font-weight:400}
h3.sub{font-size:12px;color:var(--muted);margin:18px 0 0;text-transform:uppercase;letter-spacing:.05em}
.k1{color:var(--warn)}.k2{color:var(--bad)}
#offline{display:none;background:var(--warnbg);color:var(--warn);border-radius:12px;padding:10px 14px;margin-bottom:14px;font-size:13.5px}
</style></head><body><div class=wrap>
<header><span class=logo>&#128737;&#65039;</span><h1>Home AdBlock<small id=sub>connecting&hellip;</small></h1></header>
<div id=offline>Can't reach the AdBlock box. Retrying&hellip;</div>
<div class=alert id=credwarn>&#9888;&#65039; Default passwords are in use. Set WEB_PASS / OTA_PASS in <b>secrets.h</b> and reflash.</div>

<section class=card><div class=hero id=hero>
<div class=ring id=ring>&#128737;&#65039;</div>
<div class=st><b id=state>Protected</b><span id=stateSub>Ads, adult sites, gambling and scams are blocked</span></div>
<div class=seg id=pausebar>
<button onclick=pause(300)>Pause 5 min</button><button onclick=pause(1800)>Pause 30 min</button><button onclick=pause(3600)>Pause 1 hr</button></div>
<div class=seg id=resumebar style=display:none><button class=go onclick=resume()>Turn protection back on</button></div>
</div></section>

<div class=grid>
<div class=stat><div class="v bad" id=sBlocked>&ndash;</div><div class=l>Blocked since start</div></div>
<div class=stat><div class=v id=sRate>&ndash;</div><div class=l>Of all requests</div></div>
<div class=stat><div class="v ok" id=sDomains>&ndash;</div><div class=l>Sites on blocklist</div></div>
<div class=stat><div class=v id=sUp>&ndash;</div><div class=l>Running for</div></div>
</div>

<section class=card><h2>&#9989; What's blocked</h2><div class=chips>
<span class=chip>Ads &amp; trackers</span><span class=chip>Pop-ups</span><span class=chip>Adult / porn</span><span class=chip>Gambling &amp; casino</span>
<span class=chip>Scams &amp; phishing</span><span class=chip>Fake shops</span><span class=chip>Malware</span><span class=chip>SafeSearch (Google, YouTube, Bing)</span></div></section>

<section class=card><h2>&#128680; Scam protection<span class=n id=scamN></span></h2>
<label class=tog><input type=checkbox id=tRemote onchange="scamSet('remote',this)"><span class=sw></span><span><b>Block remote-control apps</b>
<small>AnyDesk, TeamViewer, RustDesk&hellip; Fake police or bank callers ask victims to install these, then empty the bank account.</small></span></label>
<label class=tog><input type=checkbox id=tBank onchange="scamSet('bank',this)"><span class=sw></span><span><b>Block fake bank &amp; government sites</b>
<small>Sites that copy names like Krungthai, SCB, KBank, PromptPay or PEA but aren't the real ones. Real .co.th / .go.th / .or.th sites are never blocked.</small></span></label>
<h3 class=sub>Recently stopped</h3><div class=list id=hits></div>
<h3 class=sub>Always allowed</h3><p class=hint style=margin-top:4px>Never blocked by anything. If a real app or website stops working, press <b>Allow</b> on it.</p><div class=list id=allowl></div></section>

<section class=card><h2>&#128683; Block a website<span class=n id=cCount></span></h2>
<p class=hint>Paste a link or type a name, e.g. <b>ads.example.com</b> or a Thai address like <b>&#3619;&#3633;&#3585;.com</b>. Its sub-sites are blocked too.</p>
<form class=row id=addf><input id=dom placeholder="website or link" autocomplete=off autocapitalize=off spellcheck=false><button class=pri>Block</button><button type=button onclick=allowSite()>Allow</button></form>
<div class=list id=custom></div></section>

<section class=card><h2>&#128241; Devices<span class=n id=dCount></span></h2>
<p class=hint>Tap a name to rename it (saved on this phone/computer only). &ldquo;Block all&rdquo; cuts a device off the internet.</p>
<div class=list id=devs></div></section>

<details class=card><summary>&#9881;&#65039; Settings &amp; advanced</summary><div class=in>
<div class=sec><h3>System</h3><div class=kv id=sys></div></div>
<div class=sec><h3>Upload a new blocklist</h3><p class=hint>A <b>blocklist.bin</b> made with <b>tools/build_blocklist.py</b>.</p>
<form id=upf class=row><input type=file id=blf accept=.bin><button class=pri>Upload</button></form><div class=prog id=upp><i></i></div></div>
<div class=sec><h3>Automatic blocklist update</h3><p class=hint>Download a prebuilt blocklist.bin on a schedule. Leave empty to keep the current list. Last: <span id=ustat>&ndash;</span></p>
<div class=row><input id=uurl placeholder="https://.../blocklist.bin"><input id=uiv type=number min=1 style="flex:0 0 76px" title="hours"></div>
<div class=row style=margin-top:8px><button onclick=saveUpd()>Save</button><button onclick=fetchNow()>Update now</button></div></div>
<div class=sec><h3>Firmware update</h3><p class=hint>Upload <b>.pio/build/nodemcuv2/firmware.bin</b>. The box restarts afterwards.</p>
<form id=fwf class=row><input type=file id=fwb accept=.bin><button class=pri>Flash</button></form><div class=prog id=fwp><i></i></div></div>
<div class=sec><h3>WiFi</h3><p class=hint>Forget the saved WiFi and restart into setup mode (open network &ldquo;ESP-AdBlock-&hellip;&rdquo;).</p>
<button class=del onclick=forgetWifi()>Forget WiFi</button></div>
</div></details>
</div><div id=toast></div><script>
const $=id=>document.getElementById(id),H={'X-Requested-With':'esp-adblock'};let S=null,tt;
function toast(m){let t=$('toast');t.textContent=m;t.classList.add('show');clearTimeout(tt);tt=setTimeout(()=>t.classList.remove('show'),2600)}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function fmt(n){return Number(n).toLocaleString()}
function dur(s){let h=Math.floor(s/3600),m=Math.floor(s%3600/60),x=s%60;return h?h+'h '+m+'m':m?m+'m '+String(x).padStart(2,'0')+'s':x+'s'}
// punycode (RFC 3492) decode so Thai/IDN domains show in their own script
function pdec(s){try{let o=[],i=0,n=128,b=72,x=s.lastIndexOf('-');if(x>0)o=[...s.slice(0,x)];
for(let p=x>0?x+1:0;p<s.length;){let oi=i,w=1;for(let k=36;;k+=36){let c=s.charCodeAt(p++),d=c-48<10?c-22:c-65<26?c-65:c-97;
i+=d*w;let t=k<=b?1:k>=b+26?26:k-b;if(d<t)break;w*=36-t}let L=o.length+1,dl=i-oi;dl=oi==0?Math.floor(dl/700):dl>>1;dl+=Math.floor(dl/L);
let k=0;for(;dl>455;k+=36)dl=Math.floor(dl/35);b=k+Math.floor(36*dl/(dl+38));n+=Math.floor(i/L);i%=L;o.splice(i++,0,String.fromCodePoint(n))}
return o.join('')}catch(e){return s}}
function uni(d){return d.split('.').map(l=>l.startsWith('xn--')?pdec(l.slice(4)):l).join('.')}
function toHost(v){v=v.trim();if(!v)return'';if(!/^[a-z][a-z0-9+.-]*:\/\//i.test(v))v='http://'+v;try{return new URL(v).hostname.replace(/^www\./,'')}catch(e){return''}}
async function api(u,ok){try{let r=await fetch(u,{headers:H});if(r.status==401){toast('Password needed');return false}
if(!r.ok){toast('Failed: '+r.status);return false}if(ok)toast(ok);await load();return await r.text()}catch(e){toast('Box not reachable');return false}}
function names(){try{return JSON.parse(localStorage.getItem('devnames')||'{}')}catch(e){return{}}}
function setName(mac,n){let m=names();if(n)m[mac]=n;else delete m[mac];try{localStorage.setItem('devnames',JSON.stringify(m))}catch(e){}}
function pause(s){api('/pause?s='+s,'Protection paused for '+dur(s))}
function resume(){api('/resume','Protection is back on')}
$('addf').onsubmit=e=>{e.preventDefault();let h=toHost($('dom').value);if(!h||h.indexOf('.')<0){toast('That doesn\'t look like a website');return}
api('/addblock?d='+encodeURIComponent(h),'Blocked '+uni(h)).then(r=>{if(r!==false)$('dom').value=''})};
$('custom').onclick=e=>{let b=e.target.closest('[data-d]');if(b)api('/unblock?d='+encodeURIComponent(b.dataset.d),'Unblocked '+uni(b.dataset.d))};
$('devs').onclick=e=>{let b=e.target.closest('[data-ip]');if(b){let on=b.dataset.ban=='1';
if(on||confirm('Block ALL internet for this device?'))api('/ban?ip='+b.dataset.ip,on?'Device allowed again':'Device blocked')}
let n=e.target.closest('[data-mac]');if(n){let v=prompt('Name for this device (empty = reset):',names()[n.dataset.mac]||'');if(v!==null){setName(n.dataset.mac,v.trim());render()}}};
function scamSet(k,el){api('/scamset?'+k+'='+(el.checked?1:0),el.checked?'Turned on':'Turned off \u2014 less protection')}
function ago(s){return s<60?'just now':s<3600?Math.floor(s/60)+' min ago':Math.floor(s/3600)+' h ago'}
function base(d){let p=d.split('.'),n=p.length,cc=n>2&&p[n-1].length==2&&/^(co|or|go|ac|in|mi|com|net|org|gov|edu)$/.test(p[n-2]);return p.slice(cc?-3:-2).join('.')}
function allowSite(){let h=toHost($('dom').value);if(!h||h.indexOf('.')<0){toast('That doesn\'t look like a website');return}
api('/allow?d='+encodeURIComponent(h),'Always allowed: '+uni(h)).then(r=>{if(r!==false)$('dom').value=''})}
$('hits').onclick=e=>{let b=e.target.closest('[data-allow]');if(b&&confirm('Allow '+uni(b.dataset.allow)+'? Only do this if you are sure it is a real, safe site.'))api('/allow?d='+encodeURIComponent(b.dataset.allow),'Always allowed: '+uni(b.dataset.allow))};
$('allowl').onclick=e=>{let b=e.target.closest('[data-un]');if(b)api('/unallow?d='+encodeURIComponent(b.dataset.un),'Removed '+uni(b.dataset.un))};
function saveUpd(){api('/setupdate?u='+encodeURIComponent($('uurl').value.trim())+'&h='+(parseInt($('uiv').value)||24),'Saved')}
function fetchNow(){$('ustat').textContent='downloading…';toast('Updating blocklist…');api('/fetchnow')}
function forgetWifi(){if(confirm('Forget WiFi and restart into setup mode?'))api('/forgetwifi','Restarting into setup mode')}
function upload(form,file,url,bar,done){form.onsubmit=e=>{e.preventDefault();let f=$(file).files[0];if(!f){toast('Choose a file first');return}
let x=new XMLHttpRequest(),p=$(bar),i=p.firstChild;p.style.display='block';i.style.width='0';x.open('POST',url);x.setRequestHeader('X-Requested-With','esp-adblock');
x.upload.onprogress=e=>{if(e.lengthComputable)i.style.width=(e.loaded/e.total*100)+'%'};
x.onload=()=>{p.style.display='none';toast(x.status==200?done:'Failed: '+x.responseText);$(file).value='';setTimeout(load,800)};
x.onerror=()=>{p.style.display='none';toast(url=='/update'?done:'Upload failed')};let d=new FormData();d.append('f',f);x.send(d)}}
upload($('upf'),'blf','/upload','upp','Blocklist updated');upload($('fwf'),'fwb','/update','fwp','Flashed — restarting, reload in 20 s');
function render(){if(!S)return;let s=S,on=s.blocking!==false,total=s.blocked+s.allowed,nm=names();
$('sub').textContent=s.ip+' · '+(s.ssid||'WiFi')+' · '+s.rssi+' dBm';
$('hero').classList.toggle('off',!on);$('ring').textContent=on?'\u{1F6E1}️':'⏸️';
$('state').textContent=on?'Protected':'Paused';
$('stateSub').textContent=on?'Ads, adult sites, gambling and scams are blocked':(s.resumeIn>0?'Protection turns back on in '+dur(s.resumeIn):'Protection is off until you turn it back on');
$('pausebar').style.display=on?'':'none';$('resumebar').style.display=on?'none':'';
$('credwarn').style.display=s.defcreds?'block':'none';
$('sBlocked').textContent=fmt(s.blocked);$('sRate').textContent=total?Math.round(s.blocked*100/total)+'%':'0%';
$('sDomains').textContent=fmt(s.domains);$('sUp').textContent=s.uptime;
$('cCount').textContent=s.custom.length?s.custom.length+' added':'';
$('custom').innerHTML=s.custom.map(d=>`<div class=item><div class=t>${esc(uni(d))}${uni(d)!=d?`<small>${esc(d)}</small>`:''}</div><button class="sm del" data-d="${esc(d)}">Unblock</button></div>`).join('')||'<div class=empty>Nothing added yet.</div>';
let cs=s.clients.slice().sort((a,b)=>(b.blocked+b.allowed)-(a.blocked+a.allowed));$('dCount').textContent=cs.length?cs.length+' seen':'';
$('devs').innerHTML=cs.map(c=>{let t=c.blocked+c.allowed,pc=t?Math.round(c.blocked*100/t):0,n=nm[c.mac];
return`<div class="item dev"><div class=t><button class=name data-mac="${esc(c.mac)}">${esc(n||c.ip)}</button>${c.banned?'<span class=tag>BLOCKED</span>':''}
<small>${n?esc(c.ip)+' · ':''}${fmt(c.blocked)} blocked of ${fmt(t)} (${pc}%)</small><div class=bar><i style="width:${pc}%"></i></div></div>
<button class="sm ${c.banned?'go':'del'}" data-ip="${esc(c.ip)}" data-ban="${c.banned?1:0}">${c.banned?'Allow':'Block all'}</button></div>`}).join('')||'<div class=empty>No devices use the box yet. Set your router\'s DNS to '+esc(s.ip)+'.</div>';
let sc=s.scam||{hits:[]},ipn={};cs.forEach(c=>ipn[c.ip]=nm[c.mac]||c.ip);
$('tRemote').checked=!!sc.remote;$('tBank').checked=!!sc.bank;$('scamN').textContent=sc.blocked?fmt(sc.blocked)+' stopped':'';
$('hits').innerHTML=sc.hits.map(h=>`<div class=item><div class=t>${esc(uni(h.d))}<small><b class=k${h.k}>${h.k==1?'Remote-control app':'Fake bank / government site'}</b> \u00b7 ${esc(ipn[h.ip]||h.ip)} \u00b7 ${ago(h.ago)}</small></div><button class=sm data-allow="${esc(base(h.d))}">Allow</button></div>`).join('')||'<div class=empty>Nothing stopped yet \u{1F44D}</div>';
$('allowl').innerHTML=(s.allow||[]).map(d=>`<div class=item><div class=t>${esc(uni(d))}</div><button class="sm del" data-un="${esc(d)}">Remove</button></div>`).join('')||'<div class=empty>None.</div>';
$('sys').innerHTML=[['Address','http://adblock.local · '+s.ip],['WiFi',(s.ssid||'?')+' ('+s.rssi+' dBm)'],['Free memory',Math.round(s.heap/1024)+' KB'],
['Last restart',s.boot],['Requests',fmt(total)]].map(r=>`<span>${r[0]}</span><span>${esc(r[1])}</span>`).join('');
if(document.activeElement!=$('uurl'))$('uurl').value=s.upurl||'';if(document.activeElement!=$('uiv'))$('uiv').value=s.upiv||24;$('ustat').textContent=s.upstat||'–'}
async function load(){try{let r=await fetch('/stats.json',{cache:'no-store'});S=await r.json();$('offline').style.display='none';render();if(!document.body.classList.contains('ready'))setTimeout(()=>document.body.classList.add('ready'),500)}catch(e){$('offline').style.display='block'}}
load();setInterval(()=>{if(!document.hidden)load()},3000);
</script></body></html>)HTML";
