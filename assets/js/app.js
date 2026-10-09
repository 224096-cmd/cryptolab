/* =====================================================================
   CryptoLab — 共通基盤 app.js
   ・グローバル名前空間 CL を1つだけ作り、各ステージはここに登録する
   ・ライブラリ非依存（素のJavaScript）。すべてブラウザ内で完結。
   ===================================================================== */
"use strict";
window.CL = window.CL || {};

/* ------------------------------------------------------------------
   DOM ヘルパー
------------------------------------------------------------------ */
CL.dom = (function(){
  function el(tag, attrs, children){
    var n = document.createElement(tag);
    if(attrs){
      for(var k in attrs){
        if(!attrs.hasOwnProperty(k)) continue;
        var v = attrs[k];
        if(v == null) continue;
        if(k === "class") n.className = v;
        else if(k === "html") n.innerHTML = v;
        else if(k === "text") n.textContent = v;
        else if(k === "dataset"){ for(var d in v){ n.dataset[d] = v[d]; } }
        else if(k.slice(0,2) === "on" && typeof v === "function"){ n.addEventListener(k.slice(2), v); }
        else n.setAttribute(k, v);
      }
    }
    if(children != null){
      if(!Array.isArray(children)) children = [children];
      children.forEach(function(c){
        if(c == null) return;
        n.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
      });
    }
    return n;
  }
  function clear(node){ while(node.firstChild) node.removeChild(node.firstChild); }
  function $(sel, root){ return (root||document).querySelector(sel); }
  function $all(sel, root){ return Array.prototype.slice.call((root||document).querySelectorAll(sel)); }
  return { el: el, clear: clear, $: $, $all: $all };
})();

/* ------------------------------------------------------------------
   数値の整形
------------------------------------------------------------------ */
CL.fmt = (function(){
  // 大きな整数を 1.23×10^18 の形で読みやすく（概数）
  function sci(n){
    // n は Number か BigInt
    var x = (typeof n === "bigint") ? Number(n) : n;
    if(!isFinite(x)) return "∞";
    if(x === 0) return "0";
    if(Math.abs(x) < 1e6) return Math.round(x).toLocaleString("en-US");
    var e = Math.floor(Math.log10(Math.abs(x)));
    var m = x / Math.pow(10, e);
    return m.toFixed(2) + "×10^" + e;
  }
  // 秒を「年・日・時間…」の人に読める形に
  function duration(sec){
    if(!isFinite(sec)) return "∞";
    if(sec < 1e-3) return (sec*1e6).toFixed(0) + " マイクロ秒";
    if(sec < 1) return (sec*1e3).toFixed(1) + " ミリ秒";
    if(sec < 60) return sec.toFixed(2) + " 秒";
    var units = [["年",31557600],["日",86400],["時間",3600],["分",60]];
    for(var i=0;i<units.length;i++){
      if(sec >= units[i][1]){
        var v = sec/units[i][1];
        if(units[i][0]==="年" && v > 1e4) return sci(v) + " 年";
        return v.toFixed(v<10?2:0) + " " + units[i][0];
      }
    }
    return sec.toFixed(0) + " 秒";
  }
  function pct(x){ return (x*100).toFixed(1) + "%"; }
  return { sci: sci, duration: duration, pct: pct };
})();

/* ------------------------------------------------------------------
   暗号ヘルパー（SHA-256 など）
------------------------------------------------------------------ */
CL.crypto = (function(){
  function hasSubtle(){ return !!(window.crypto && crypto.subtle && crypto.subtle.digest); }
  function bytesToHex(u8){
    var s = "";
    for(var i=0;i<u8.length;i++){ s += u8[i].toString(16).padStart(2,"0"); }
    return s;
  }
  // 文字列 → SHA-256（Uint8Array を返す Promise）
  function sha256Bytes(str){
    var data = new TextEncoder().encode(str);
    return crypto.subtle.digest("SHA-256", data).then(function(buf){ return new Uint8Array(buf); });
  }
  function sha256Hex(str){ return sha256Bytes(str).then(bytesToHex); }
  // バイト列を 0/1 のビット配列へ
  function bytesToBits(u8){
    var bits = [];
    for(var i=0;i<u8.length;i++){
      for(var b=7;b>=0;b--){ bits.push((u8[i]>>b)&1); }
    }
    return bits;
  }
  function popcount(x){ var c=0; while(x){ c += x&1; x>>>=1; } return c; }
  // 2つのバイト列で異なるビット数（ハミング距離）
  function hamming(a,b){
    var n = Math.min(a.length,b.length), d=0;
    for(var i=0;i<n;i++){ d += popcount(a[i]^b[i]); }
    return d;
  }
  return { hasSubtle:hasSubtle, bytesToHex:bytesToHex, sha256Bytes:sha256Bytes,
           sha256Hex:sha256Hex, bytesToBits:bytesToBits, popcount:popcount, hamming:hamming };
})();

/* ------------------------------------------------------------------
   数論ヘルパー（BigInt）: RSA で使う
------------------------------------------------------------------ */
CL.num = (function(){
  function abs(a){ return a<0n ? -a : a; }
  // a^e mod m（繰り返し二乗法）。途中経過を step に push できる
  function modpow(a, e, m, steps){
    a = ((a % m) + m) % m;
    var result = 1n, base = a, exp = e, bit = 0;
    while(exp > 0n){
      if(exp & 1n){
        result = (result * base) % m;
        if(steps) steps.push({bit:bit, use:true, base:base, result:result});
      } else {
        if(steps) steps.push({bit:bit, use:false, base:base, result:result});
      }
      exp >>= 1n;
      base = (base * base) % m;
      bit++;
    }
    return result;
  }
  // 拡張ユークリッド: ax+by=gcd を満たす {g,x,y}
  function egcd(a,b){
    var old_r=a, r=b, old_s=1n, s=0n, old_t=0n, t=1n;
    while(r !== 0n){
      var q = old_r / r;
      var tmp;
      tmp = old_r - q*r; old_r = r; r = tmp;
      tmp = old_s - q*s; old_s = s; s = tmp;
      tmp = old_t - q*t; old_t = t; t = tmp;
    }
    return { g:old_r, x:old_s, y:old_t };
  }
  function gcd(a,b){ a=abs(a); b=abs(b); while(b){ var t=a%b; a=b; b=t; } return a; }
  // mod 逆元: a·x ≡ 1 (mod m)。無ければ null
  function modinv(a, m){
    a = ((a % m) + m) % m;
    var r = egcd(a, m);
    if(r.g !== 1n) return null;
    return ((r.x % m) + m) % m;
  }
  // 小さい数の素数判定（試し割り）
  function isPrimeSmall(n){
    n = BigInt(n);
    if(n < 2n) return false;
    if(n < 4n) return true;
    if(n % 2n === 0n) return false;
    for(var i=3n; i*i <= n; i += 2n){ if(n % i === 0n) return false; }
    return true;
  }
  // 範囲内の素数一覧（エラトステネスのふるい）
  function primesUpTo(limit){
    var sieve = new Uint8Array(limit+1), out=[];
    for(var i=2;i<=limit;i++){
      if(!sieve[i]){ out.push(i); for(var j=i*i;j<=limit;j+=i){ sieve[j]=1; } }
    }
    return out;
  }
  function bitLength(n){ n = abs(BigInt(n)); return n.toString(2).length; }
  return { modpow:modpow, egcd:egcd, gcd:gcd, modinv:modinv,
           isPrimeSmall:isPrimeSmall, primesUpTo:primesUpTo, bitLength:bitLength, abs:abs };
})();

/* ------------------------------------------------------------------
   暗号の共通処理（送受信ページと各ステージで共用）
------------------------------------------------------------------ */
CL.cipher = (function(){
  var AZ="ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  var EN_FREQ={A:8.2,B:1.5,C:2.8,D:4.3,E:12.7,F:2.2,G:2.0,H:6.1,I:7.0,J:0.15,K:0.77,L:4.0,M:2.4,
    N:6.7,O:7.5,P:1.9,Q:0.095,R:6.0,S:6.3,T:9.1,U:2.8,V:0.98,W:2.4,X:0.15,Y:2.0,Z:0.074};
  function shiftChar(ch,k){ var c=ch.charCodeAt(0);
    if(c>=65&&c<=90)  return String.fromCharCode((c-65+k+2600)%26+65);
    if(c>=97&&c<=122) return String.fromCharCode((c-97+k+2600)%26+97);
    return ch; }
  function caesar(t,k){ var o=""; for(var i=0;i<t.length;i++) o+=shiftChar(t[i],k); return o; }
  function freq(text){ var f={},i; for(i=0;i<26;i++) f[AZ[i]]=0; var up=String(text).toUpperCase(); for(i=0;i<up.length;i++){ if(f[up[i]]!==undefined) f[up[i]]++; } return f; }
  function chiSquare(text){
    var c=freq(text), total=0, i; for(i=0;i<26;i++) total+=c[AZ[i]];
    if(total===0) return 1e9;
    var chi=0; for(i=0;i<26;i++){ var L=AZ[i], ex=total*EN_FREQ[L]/100, df=c[L]-ex; chi+=df*df/(ex||0.01); } return chi;
  }
  function randomKey(){ var a=AZ.split(""); for(var i=a.length-1;i>0;i--){ var j=Math.floor(Math.random()*(i+1)); var t=a[i]; a[i]=a[j]; a[j]=t; } var m={}; for(var k=0;k<26;k++) m[AZ[k]]=a[k]; return m; }
  function applyMap(text,map){ var o=""; for(var i=0;i<text.length;i++){ var c=text[i].toUpperCase(); o+=map[c]!==undefined?map[c]:text[i]; } return o; }
  return { AZ:AZ, EN_FREQ:EN_FREQ, caesar:caesar, freq:freq, chiSquare:chiSquare, randomKey:randomKey, applyMap:applyMap };
})();

/* ------------------------------------------------------------------
   リンク／コードへの符号化（端末間での問題の受け渡し）
------------------------------------------------------------------ */
CL.codec = (function(){
  function enc(obj){
    var bytes=new TextEncoder().encode(JSON.stringify(obj)), bin="";
    for(var i=0;i<bytes.length;i++) bin+=String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
  }
  function dec(str){
    try{ str=String(str).replace(/-/g,"+").replace(/_/g,"/"); while(str.length%4) str+="=";
      var bin=atob(str), b=new Uint8Array(bin.length); for(var i=0;i<bin.length;i++) b[i]=bin.charCodeAt(i);
      return JSON.parse(new TextDecoder().decode(b)); }catch(e){ return null; }
  }
  function queryParam(name){
    var h=location.hash||""; var qi=h.indexOf("?"); if(qi<0) return null;
    var qs=h.slice(qi+1).split("&");
    for(var i=0;i<qs.length;i++){ var kv=qs[i].split("="); if(decodeURIComponent(kv[0])===name) return decodeURIComponent(kv[1]||""); }
    return null;
  }
  function baseUrl(){ return location.origin + location.pathname; }
  // 入力が完全なURLでも生コードでも、payload文字列を取り出す
  function extract(input){
    input=String(input||"").trim(); if(!input) return "";
    var m=input.match(/[?&]d=([^&\s]+)/); if(m) return m[1];
    return input.replace(/^.*#\/?[a-z]*\??/i,"").replace(/^d=/,"");
  }
  return { enc:enc, dec:dec, queryParam:queryParam, baseUrl:baseUrl, extract:extract };
})();

/* ------------------------------------------------------------------
   ページ単位の状態保存（localStorage）
   各ステージの入力・途中経過をページを離れても保持する。
   「リセット」ボタンを押すまで消えない。
------------------------------------------------------------------ */
CL.pstate = function(name){
  var KEY = "cryptolab.state." + name;
  return {
    get: function(){ try{ var r=localStorage.getItem(KEY); return r?JSON.parse(r):null; }catch(e){ return null; } },
    set: function(obj){ try{ localStorage.setItem(KEY, JSON.stringify(obj)); }catch(e){} },
    clear: function(){ try{ localStorage.removeItem(KEY); }catch(e){} }
  };
};

/* ------------------------------------------------------------------
   モード（通常／研究）。研究モードはパスワードで解除。
   通常は授業向けにやさしく、研究モードでは高度な設定が開く。
------------------------------------------------------------------ */
CL.mode = (function(){
  var KEY="cryptolab.research", PW="224096", listeners=[];
  function isResearch(){ try{ return localStorage.getItem(KEY)==="1"; }catch(e){ return false; } }
  function setR(v){ try{ if(v) localStorage.setItem(KEY,"1"); else localStorage.removeItem(KEY); }catch(e){} notify(); }
  function unlock(pw){ if(String(pw)===PW){ setR(true); return true; } return false; }
  function lock(){ setR(false); }
  function onChange(fn){ listeners.push(fn); }
  function notify(){ listeners.forEach(function(f){ try{ f(); }catch(e){} }); }
  return { isResearch:isResearch, unlock:unlock, lock:lock, onChange:onChange };
})();

/* ------------------------------------------------------------------
   実験ログの保管（localStorage に自動保存）
   各レコードは「平たいオブジェクト」。CSV 化しやすいように。
------------------------------------------------------------------ */
CL.store = (function(){
  var KEY = "cryptolab.log.v1";
  var log = [];
  var listeners = [];
  function load(){
    try{
      var raw = localStorage.getItem(KEY);
      log = raw ? JSON.parse(raw) : [];
      if(!Array.isArray(log)) log = [];
    }catch(e){ log = []; }
  }
  function save(){
    try{ localStorage.setItem(KEY, JSON.stringify(log)); }catch(e){ /* 保存不可環境では無視 */ }
  }
  function add(stage, event, detail){
    var rec = { time: new Date().toISOString(), stage: stage, event: event };
    if(detail){ for(var k in detail){ if(detail.hasOwnProperty(k)) rec[k] = detail[k]; } }
    log.push(rec);
    save(); notify();
    return rec;
  }
  function all(){ return log.slice(); }
  function byStage(stage){ return log.filter(function(r){ return r.stage === stage; }); }
  function clear(){ log = []; save(); notify(); }
  function count(){ return log.length; }
  function onChange(fn){ listeners.push(fn); }
  function notify(){ listeners.forEach(function(fn){ try{ fn(); }catch(e){} }); }
  load();
  return { add:add, all:all, byStage:byStage, clear:clear, count:count, onChange:onChange };
})();

/* ------------------------------------------------------------------
   エクスポート（CSV / JSON / Markdown）とダウンロード
------------------------------------------------------------------ */
CL.export = (function(){
  function csvCell(v){
    if(v == null) return "";
    var s = String(v);
    if(/[",\n]/.test(s)) s = '"' + s.replace(/"/g,'""') + '"';
    return s;
  }
  // 平たいオブジェクトの配列 → CSV（列はキーの和集合）
  function toCSV(rows){
    if(!rows.length) return "";
    var cols = [];
    rows.forEach(function(r){ for(var k in r){ if(r.hasOwnProperty(k) && cols.indexOf(k)<0) cols.push(k); } });
    var lines = [cols.map(csvCell).join(",")];
    rows.forEach(function(r){ lines.push(cols.map(function(c){ return csvCell(r[c]); }).join(",")); });
    return "﻿" + lines.join("\r\n"); // BOM付き（Excelで文字化けしないように）
  }
  function toJSON(rows){ return JSON.stringify(rows, null, 2); }
  function toMarkdown(rows){
    if(!rows.length) return "_データがありません_\n";
    var cols = [];
    rows.forEach(function(r){ for(var k in r){ if(r.hasOwnProperty(k) && cols.indexOf(k)<0) cols.push(k); } });
    var esc = function(v){ return v==null ? "" : String(v).replace(/\|/g,"\\|"); };
    var out = "| " + cols.join(" | ") + " |\n| " + cols.map(function(){return "---";}).join(" | ") + " |\n";
    rows.forEach(function(r){ out += "| " + cols.map(function(c){ return esc(r[c]); }).join(" | ") + " |\n"; });
    return out;
  }
  function download(filename, text, mime){
    try{
      var blob = new Blob([text], { type: (mime||"text/plain") + ";charset=utf-8" });
      var url = URL.createObjectURL(blob);
      var a = document.createElement("a");
      a.href = url; a.download = filename;
      document.body.appendChild(a); a.click();
      setTimeout(function(){ document.body.removeChild(a); URL.revokeObjectURL(url); }, 500);
      return true;
    }catch(e){ return false; }
  }
  function copy(text){
    if(navigator.clipboard && navigator.clipboard.writeText){ return navigator.clipboard.writeText(text); }
    return Promise.reject();
  }
  return { toCSV:toCSV, toJSON:toJSON, toMarkdown:toMarkdown, download:download, copy:copy };
})();

/* ------------------------------------------------------------------
   モード切替：一般（授業用）/ 研究（パスワードで解錠）
   パスワードは平文で持たず、SHA-256 のハッシュ値で照合する。
------------------------------------------------------------------ */
CL.mode = (function(){
  var KEY="cryptolab.mode";
  var PW_HASH="bc7bca63a14c7cc1bb2ecd7774fb2ef713ae25d046c9b63d90a169052a49b3ab";
  var listeners=[];
  function get(){ try{ return localStorage.getItem(KEY)==="research" ? "research" : "learn"; }catch(e){ return "learn"; } }
  function isResearch(){ return get()==="research"; }
  function apply(){ try{ document.body.setAttribute("data-mode", get()); }catch(e){} }
  function setLearn(){ try{ localStorage.setItem(KEY,"learn"); }catch(e){} apply(); notify(); }
  function unlock(pw){
    return CL.crypto.sha256Hex(String(pw)).then(function(h){
      if(h===PW_HASH){ try{ localStorage.setItem(KEY,"research"); }catch(e){} apply(); notify(); return true; }
      return false;
    });
  }
  function onChange(fn){ listeners.push(fn); }
  function notify(){ listeners.forEach(function(f){ try{ f(get()); }catch(e){} }); }
  return { get:get, isResearch:isResearch, apply:apply, setLearn:setLearn, unlock:unlock, onChange:onChange };
})();

/* ------------------------------------------------------------------
   Web Worker ファクトリ
   関数本体の文字列から Blob で Worker を作る（別ファイル不要・file://でも動く）
------------------------------------------------------------------ */
CL.worker = (function(){
  function fromBody(body){
    var url = URL.createObjectURL(new Blob([body], { type:"text/javascript" }));
    var w = new Worker(url);
    w._revoke = function(){ try{ URL.revokeObjectURL(url); }catch(e){} };
    return w;
  }
  return { fromBody: fromBody };
})();

/* ------------------------------------------------------------------
   かんたん SVG 折れ線グラフ（計算量の可視化で使用）
   series: [{name, cls, points:[{x,y}]}], x は線形 / y は対数スケール
------------------------------------------------------------------ */
CL.chart = (function(){
  var el = CL.dom.el;
  var SVGNS = "http://www.w3.org/2000/svg";
  function s(tag, attrs){
    var n = document.createElementNS(SVGNS, tag);
    for(var k in attrs){ if(attrs.hasOwnProperty(k)) n.setAttribute(k, attrs[k]); }
    return n;
  }
  // opts: {xmin,xmax,ymin,ymax(対数の指数で指定),xlabel,ylabel,xticks,yticks}
  function logLine(series, opts){
    var W=680, H=360, padL=58, padR=18, padT=18, padB=46;
    var iw = W-padL-padR, ih = H-padT-padB;
    var svg = s("svg", { viewBox:"0 0 "+W+" "+H, class:"chart", role:"img" });
    var xmin=opts.xmin, xmax=opts.xmax;
    var ymin=opts.ymin, ymax=opts.ymax; // y は「10^ymin 〜 10^ymax 秒」の指数で渡す
    function X(x){ return padL + (x-xmin)/(xmax-xmin)*iw; }
    function Y(exp){ return padT + (ymax-exp)/(ymax-ymin)*ih; } // exp = log10(秒)
    // Y方向グリッド（10^k 秒）
    for(var e=ymin; e<=ymax; e++){
      var y = Y(e);
      svg.appendChild(s("line",{x1:padL,y1:y,x2:W-padR,y2:y,class:"gridln"}));
      var lab = (e===0)?"1秒":("10^"+e+"秒");
      svg.appendChild(s("text",{x:padL-6,y:y+3,"text-anchor":"end",class:"lbl"})).textContent = lab;
    }
    // X方向目盛り
    (opts.xticks||[]).forEach(function(t){
      var x = X(t);
      svg.appendChild(s("line",{x1:x,y1:padT,x2:x,y2:H-padB,class:"gridln"}));
      svg.appendChild(s("text",{x:x,y:H-padB+16,"text-anchor":"middle",class:"lbl"})).textContent = t;
    });
    // 軸
    svg.appendChild(s("line",{x1:padL,y1:padT,x2:padL,y2:H-padB,class:"axis"}));
    svg.appendChild(s("line",{x1:padL,y1:H-padB,x2:W-padR,y2:H-padB,class:"axis"}));
    // 軸ラベル
    var xl = s("text",{x:padL+iw/2,y:H-8,"text-anchor":"middle",class:"lbl ax"}); xl.textContent=opts.xlabel||""; svg.appendChild(xl);
    var yl = s("text",{x:16,y:padT+ih/2,"text-anchor":"middle",class:"lbl ax",transform:"rotate(-90 16 "+(padT+ih/2)+")"}); yl.textContent=opts.ylabel||""; svg.appendChild(yl);
    // 系列
    series.forEach(function(se){
      var d = "", first=true;
      se.points.forEach(function(p){
        if(p.y==null || !isFinite(p.y)) return;
        var exp = Math.log10(Math.max(p.y, Math.pow(10,ymin)/10));
        exp = Math.max(ymin, Math.min(ymax, exp));
        var px=X(p.x), py=Y(exp);
        d += (first?"M":"L") + px.toFixed(1) + " " + py.toFixed(1) + " ";
        first=false;
      });
      if(d) svg.appendChild(s("path",{d:d, class:se.cls}));
      if(se.dots){
        se.points.forEach(function(p){
          if(p.y==null||!isFinite(p.y)) return;
          var exp=Math.max(ymin,Math.min(ymax,Math.log10(p.y)));
          svg.appendChild(s("circle",{cx:X(p.x),cy:Y(exp),r:3,class:"dot"}));
        });
      }
    });
    return svg;
  }
  return { logLine: logLine };
})();

/* ------------------------------------------------------------------
   トースト（軽い通知）
------------------------------------------------------------------ */
CL.toast = function(msg){
  var t = CL.dom.el("div", { text: msg, style:
    "position:fixed;left:50%;bottom:24px;transform:translateX(-50%);"+
    "background:#27303f;color:#fff;padding:9px 16px;border-radius:8px;font-size:.88rem;"+
    "z-index:999;box-shadow:0 6px 20px rgba(0,0,0,.2);max-width:90vw;text-align:center" });
  document.body.appendChild(t);
  setTimeout(function(){ t.style.transition="opacity .4s"; t.style.opacity="0"; }, 1800);
  setTimeout(function(){ if(t.parentNode) t.parentNode.removeChild(t); }, 2300);
};

/* ------------------------------------------------------------------
   ルーター（ハッシュ #/xxx でページ切替。GitHub Pages で rewrite 不要）
------------------------------------------------------------------ */
CL.routes = {};   // 各ページが CL.routes["stage1"] = {title, render(container)} を登録
CL.route = function(name, def){ CL.routes[name] = def; };

CL.router = (function(){
  function current(){
    var h = location.hash.replace(/^#\/?/, "");
    h = h.split("?")[0];
    return h || "home";
  }
  function setActiveNav(name){
    CL.dom.$all("nav.main a").forEach(function(a){
      var target = (a.getAttribute("href")||"").replace(/^#\/?/, "") || "home";
      a.classList.toggle("active", target === name);
    });
  }
  function render(){
    var name = current();
    var def = CL.routes[name] || CL.routes["home"];
    var view = document.getElementById("view");
    CL.dom.clear(view);
    document.title = (def.title ? def.title + " — " : "") + "CryptoLab";
    setActiveNav(CL.routes[name] ? name : "home");
    try{
      def.render(view);
    }catch(e){
      view.appendChild(CL.dom.el("section",{class:"card"},[
        CL.dom.el("h2",{text:"表示エラー"}),
        CL.dom.el("p",{class:"muted",text:"このページの描画中に問題が発生しました。再読み込みしてください。"}),
        CL.dom.el("pre",{class:"mono-box",text:String(e && e.message || e)})
      ]));
    }
    window.scrollTo(0,0);
  }
  function start(){
    window.addEventListener("hashchange", render);
    render();
  }
  return { start:start, current:current, reload:render };
})();

/* 全ページ共通の UI 部品 ------------------------------------------ */
CL.ui = (function(){
  var el = CL.dom.el;
  // タブUI。tabs:[{id,label,n}] を受け取り、パネルの表示切替を返す
  function tabBar(tabs, onSelect){
    var bar = el("div",{class:"tabs",role:"tablist"});
    var btns = {};
    tabs.forEach(function(t,i){
      var b = el("button",{class:"tab",role:"tab","aria-selected": i===0?"true":"false",
        id:"tab-"+t.id, onclick:function(){ select(t.id); }},
        [ t.n ? el("span",{class:"n",text:t.n}) : null, document.createTextNode(t.label) ]);
      btns[t.id]=b; bar.appendChild(b);
    });
    function select(id){
      tabs.forEach(function(t){ btns[t.id].setAttribute("aria-selected", t.id===id?"true":"false"); });
      onSelect(id);
    }
    bar.select = select;
    return bar;
  }
  // ステージ共通の前後移動
  function stageNav(prev, next){
    var nav = el("div",{class:"stage-nav"});
    nav.appendChild(prev ? el("a",{class:"btn ghost sm",href:"#/"+prev.id},["← "+prev.label]) : el("span"));
    nav.appendChild(next ? el("a",{class:"btn ghost sm",href:"#/"+next.id},[next.label+" →"]) : el("span"));
    return nav;
  }
  function term(word, desc){
    return el("abbr",{class:"term",title:desc},[word]);
  }
  // ページのリセット操作（入力・途中経過を消して最初に戻す）
  function resetBar(label, onReset){
    var btn = el("button",{class:"btn quiet sm", onclick:function(){
      if(confirm("このページの入力と途中経過をすべて消して、最初の状態に戻します。よろしいですか？")) onReset();
    }},["↺ ", label||"このページをリセット"]);
    return el("div",{style:"display:flex;justify-content:flex-end;margin:-4px 0 12px"},[btn]);
  }
  // 解説を折りたたむ部品（説明を充実させつつ、長くなりすぎない）
  function details(summary, builder){
    var d = el("details",{class:"explain"});
    var s = el("summary",{},[summary]);
    d.appendChild(s);
    var body = el("div",{class:"explain-body"});
    builder(body);
    d.appendChild(body);
    return d;
  }
  return { tabBar:tabBar, stageNav:stageNav, term:term, resetBar:resetBar, details:details };
})();

/* 起動（すべての defer スクリプトが登録を終えてから走る） */
document.addEventListener("DOMContentLoaded", function(){
  CL.router.start();
  // ログ件数をヘッダーに反映
  function updateBadge(){
    var b = document.getElementById("logCount");
    if(b) b.textContent = CL.store.count();
  }
  CL.store.onChange(updateBadge); updateBadge();

  // 研究モードのロック／解除（ヘッダーのカギボタン＋常時バナー）
  var lockBtn=document.getElementById("lockBtn");
  var navResearch=document.getElementById("navResearch");
  var banner=document.getElementById("researchBanner");
  var exitBtn=document.getElementById("exitResearch");
  function applyMode(){
    var r=CL.mode.isResearch();
    if(lockBtn){ lockBtn.textContent=r?"🔬":"🔒"; lockBtn.classList.toggle("on",r);
      lockBtn.title=r?"研究モード：オン（クリックで終了）":"研究モードのロックを解除"; }
    if(navResearch) navResearch.hidden=!r;
    if(banner) banner.hidden=!r;
  }
  if(lockBtn){
    lockBtn.addEventListener("click",function(){
      if(CL.mode.isResearch()){
        if(confirm("研究モードを終了して、授業用（通常）モードに戻しますか？")) CL.mode.setLearn();
      } else {
        var pw=prompt("研究モードのパスワードを入力してください"); if(pw==null) return;
        CL.mode.unlock(pw).then(function(ok){ CL.toast(ok?"研究モードを有効にしました":"パスワードが違います"); });
      }
    });
  }
  if(exitBtn){ exitBtn.addEventListener("click",function(){ CL.mode.setLearn(); CL.toast("一般モードに戻りました"); }); }
  CL.mode.onChange(function(){ applyMode(); CL.router.reload(); });
  CL.mode.apply(); applyMode();
});
