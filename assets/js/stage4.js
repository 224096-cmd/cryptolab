/* =====================================================================
   Stage 4 — ミニRSA（公開鍵暗号）
   見る（鍵生成・暗号化の軌跡）→ 破る（素因数分解）→ なぜ破れない（計算量）
   入力・途中経過はページを離れても保持（リセットで最初に戻る）
   ===================================================================== */
"use strict";
(function(){
  var el=CL.dom.el, clear=CL.dom.clear, term=CL.ui.term, details=CL.ui.details, N=CL.num;
  var current={ n:null, e:null, c:null, m:null };

  var WORKER_BODY = `
'use strict';
function isPrimeNum(n){ if(n<2)return false; if(n%2===0)return n===2; for(var i=3;i*i<=n;i+=2){ if(n%i===0)return false; } return true; }
function randPrime(bits){ var lo=Math.pow(2,bits-1), hi=Math.pow(2,bits); for(;;){ var x=Math.floor(lo+Math.random()*(hi-lo)); x|=1; if(x<3)x=3; if(isPrimeNum(x)) return x; } }
function factorOnce(n){ if(n%2===0) return 2; var lim=Math.floor(Math.sqrt(n))+1; for(var d=3; d<=lim; d+=2){ if(n%d===0) return d; } return 0; }
onmessage=function(ev){
  var m=ev.data;
  if(m.cmd==="factor"){
    var n=m.n, started=Date.now(), ops=0;
    if(n%2===0){ postMessage({type:"factored",p:2,q:n/2,ops:1,elapsed:0}); return; }
    var lim=Math.floor(Math.sqrt(n))+1, found=0;
    for(var d=3; d<=lim; d+=2){
      ops++;
      if(n%d===0){ found=d; break; }
      if(ops%400000===0) postMessage({type:"progress",d:d,lim:lim,ops:ops,elapsed:(Date.now()-started)/1000});
    }
    if(found) postMessage({type:"factored",p:found,q:n/found,ops:ops,elapsed:(Date.now()-started)/1000,prime:false});
    else postMessage({type:"factored",p:n,q:1,ops:ops,elapsed:(Date.now()-started)/1000,prime:true});
  } else if(m.cmd==="bench"){
    var list=m.bits;
    for(var i=0;i<list.length;i++){
      var b=list[i], p=randPrime(Math.ceil(b/2)), q=randPrime(Math.floor(b/2)), Nn=p*q;
      var t0=Date.now(); factorOnce(Nn); var elp=(Date.now()-t0)/1000;
      postMessage({type:"point",bits:b,n:Nn,seconds:elp});
    }
    postMessage({type:"benchDone"});
  }
};
`;

  function randPrimeNum(bits){ var lo=Math.pow(2,bits-1), hi=Math.pow(2,bits); for(;;){ var x=Math.floor(lo+Math.random()*(hi-lo)); x|=1; if(x<3)x=3; if(N.isPrimeSmall(x)) return x; } }

  /* ========================= 見る ========================= */
  function panelSee(state, save){
    var wrap=el("div",{class:"panel"});
    wrap.appendChild(el("p",{html:
      "RSA は "+term("公開鍵暗号","暗号化の鍵（公開鍵）と復号の鍵（秘密鍵）が別。公開鍵は配ってよい")+
      "。かけ算は簡単でも、"+term("素因数分解","ある数を素数のかけ算に戻すこと。大きな数ほど非常に難しい")+
      "は難しい——その“差”を安全性に使います。"}));

    var primes=N.primesUpTo(320).filter(function(x){ return x>=11; });
    function primeSelect(def){ var s=el("select",{}); primes.forEach(function(p){ s.appendChild(el("option",{value:String(p),text:String(p),selected:p===def?"selected":null})); }); return s; }
    var selP=primeSelect(61), selQ=primeSelect(53), selE=el("select",{});
    if(state.see_p) selP.value=state.see_p;
    if(state.see_q) selQ.value=state.see_q;
    wrap.appendChild(el("div",{class:"row"},[
      el("div",{class:"col"},[el("label",{class:"field",text:"素数 p"}),selP]),
      el("div",{class:"col"},[el("label",{class:"field",text:"素数 q"}),selQ]),
      el("div",{class:"col"},[el("label",{class:"field",text:"公開指数 e"}),selE])
    ]));
    var keyBox=el("div",{style:"margin-top:12px"}); wrap.appendChild(keyBox);

    wrap.appendChild(el("hr",{class:"soft"}));
    wrap.appendChild(el("h3",{text:"暗号化してみる"}));
    var inM=el("input",{type:"number",min:"0",value:state.see_m!=null?state.see_m:"65"});
    var fromChar=el("button",{class:"btn quiet sm",text:"文字コードから（A=65…）"});
    wrap.appendChild(el("label",{class:"field",text:"数 m（n より小さい整数。文字なら文字コード）"}));
    wrap.appendChild(inM);
    wrap.appendChild(el("div",{class:"btn-row"},[fromChar, el("button",{class:"btn sm",text:"暗号化する",onclick:function(){ doEncrypt(); }})]));
    var encOut=el("div",{style:"margin-top:10px"}); wrap.appendChild(encOut);
    inM.addEventListener("input",function(){ state.see_m=inM.value; save(); });
    fromChar.addEventListener("click",function(){ var ch=prompt("1文字を入れてください（半角英数字）","A"); if(ch&&ch.length){ inM.value=ch.charCodeAt(0); state.see_m=inM.value; save(); doEncrypt(); } });

    var phi;
    function buildE(){
      var p=+selP.value, q=+selQ.value; selE.innerHTML="";
      if(p===q){ return; }
      phi=(p-1)*(q-1);
      var cands=[3,5,7,11,13,17,257,65537].filter(function(e){ return e<phi && N.gcd(BigInt(e),BigInt(phi))===1n; });
      if(!cands.length){ selE.appendChild(el("option",{value:"",text:"（なし）"})); return; }
      cands.forEach(function(e){ selE.appendChild(el("option",{value:String(e),text:String(e),selected:e===17?"selected":null})); });
      if(cands.indexOf(17)<0) selE.firstChild.selected=true;
    }
    function computeKey(){
      clear(keyBox); clear(encOut);
      var p=+selP.value, q=+selQ.value, e=+selE.value;
      if(p===q){ keyBox.appendChild(el("div",{class:"callout",html:"p と q は<b>別の</b>素数にしてください。"})); current.n=null; return; }
      if(!e){ keyBox.appendChild(el("div",{class:"callout",html:"この p, q では使える e がありません。別の素数を選んでください。"})); current.n=null; return; }
      var n=p*q; phi=(p-1)*(q-1); var d=N.modinv(BigInt(e),BigInt(phi));
      current={ n:n, e:e, c:null, m:null, p:p, q:q, d:d!=null?Number(d):null, phi:phi };
      var tbl=el("table",{class:"data"});
      function row(k,v){ tbl.appendChild(el("tr",{},[el("th",{text:k}),el("td",{class:"mono",text:v})])); }
      row("n = p × q", p+" × "+q+" = "+n+"　（公開）");
      row("φ(n) = (p−1)(q−1)", "("+(p-1)+")("+(q-1)+") = "+phi+"　（秘密）");
      row("公開鍵 (n, e)", "("+n+", "+e+")");
      row("秘密鍵 d（e·d ≡ 1 mod φ）", (d!=null? d+"　→ 秘密鍵 ("+n+", "+d+")" : "計算不可"));
      keyBox.appendChild(el("div",{class:"scrollx"},[tbl]));
      keyBox.appendChild(el("p",{class:"tiny muted",html:
        "e と d は "+term("mod 逆元","かけて φ で割った余りが 1 になる相手。拡張ユークリッドの互除法で求める")+
        "の関係。n を素因数分解して p,q が分かると φ がわかり、d が計算できてしまう＝破られる、という流れです。"}));
    }
    function doEncrypt(){
      clear(encOut);
      if(!current.n){ CL.toast("先に鍵を作ってください"); return; }
      var m=parseInt(inM.value,10);
      if(!(m>=0)){ CL.toast("0以上の整数を入れてください"); return; }
      if(m>=current.n){ encOut.appendChild(el("div",{class:"callout",html:"m は n（="+current.n+"）より小さくしてください。"})); return; }
      var steps=[]; var c=N.modpow(BigInt(m),BigInt(current.e),BigInt(current.n),steps);
      current.c=Number(c); current.m=m;
      var dec=current.d!=null?N.modpow(BigInt(current.c),BigInt(current.d),BigInt(current.n)):null;
      encOut.appendChild(el("div",{class:"callout ok",html:
        "暗号文 c = m<sup>e</sup> mod n = "+m+"<sup>"+current.e+"</sup> mod "+current.n+" = <b>"+current.c+"</b>"+
        (dec!=null? "　／　復号 c<sup>d</sup> mod n = <b>"+dec+"</b>（元に戻った！）" : "")}));
      encOut.appendChild(el("h3",{text:"計算の軌跡（繰り返し二乗法）"}));
      encOut.appendChild(el("p",{class:"tiny muted",html:
        "m<sup>e</sup> を一気に計算すると天文学的な桁になるので、途中で毎回 n で割った余りにして小さく保ちます。e を2進数にして下の位から処理します。"}));
      var tt=el("table",{class:"data"});
      tt.appendChild(el("tr",{},[el("th",{text:"eのビット"}),el("th",{text:"このビットを使う?"}),el("th",{text:"これまでの余り"})]));
      steps.forEach(function(s){ tt.appendChild(el("tr", s.use?{class:"hit"}:{}, [
        el("td",{class:"mono",text:String(s.bit)}), el("td",{text:s.use?"使う（×して余り）":"使わない"}), el("td",{class:"mono",text:String(s.result)})])); });
      encOut.appendChild(el("div",{class:"scrollx"},[tt]));
      encOut.appendChild(el("h3",{text:"“あまり”を円でみる（mod "+current.n+" 時計）"}));
      encOut.appendChild(modClock(current.n,current.c));
      encOut.appendChild(el("p",{class:"tiny muted",text:"0 から n−1 までを円に並べたときの、暗号文 c の位置。剰余（あまり）は「円をぐるぐる回った末にどこで止まるか」です。"}));
    }
    selP.addEventListener("change",function(){ state.see_p=selP.value; save(); buildE(); computeKey(); });
    selQ.addEventListener("change",function(){ state.see_q=selQ.value; save(); buildE(); computeKey(); });
    selE.addEventListener("change",function(){ state.see_e=selE.value; save(); computeKey(); });

    buildE();
    if(state.see_e){ for(var i=0;i<selE.options.length;i++){ if(selE.options[i].value===String(state.see_e)){ selE.value=state.see_e; break; } } }
    computeKey();

    wrap.appendChild(details("RSA のしくみ（公開鍵暗号の考え方）", function(b){
      b.appendChild(el("p",{html:"それまでの暗号は、送り手と受け手が<b>同じ鍵</b>を前もって秘密に共有する必要がありました（共通鍵）。"+
        "でも、会ったことのない相手と、どうやって安全に鍵を渡す？ この難問を解いたのが公開鍵暗号です。"}));
      b.appendChild(el("p",{html:"<b>鍵を2つに分ける</b>のがアイデア。<br>"+
        "・<b>公開鍵 (n, e)</b>：誰に配ってもよい。これで暗号化する。<br>"+
        "・<b>秘密鍵 (n, d)</b>：自分だけが持つ。これで復号する。<br>"+
        "公開鍵で鍵をかけると、秘密鍵を持つ本人しか開けられません。鍵を事前に共有しなくてよいのが革命的でした。"}));
      b.appendChild(el("h4",{text:"安全のよりどころ＝一方通行の計算"}));
      b.appendChild(el("p",{html:"2つの素数 p, q を<b>かけて n を作るのは簡単</b>。でも n から p, q を<b>当てる（素因数分解）のは難しい</b>。"+
        "この“戻りにくさ”が鍵を守ります。秘密鍵 d は φ(n) から作られ、φ(n) を知るには p, q が必要——"+
        "だから n を分解できないかぎり d は手に入りません。"}));
      b.appendChild(el("p",{class:"tiny muted",text:
        "※ この教材は仕組みを見るための簡易版です（パディングなし・小さな鍵）。本物の通信にそのまま使うものではありません。"}));
    }));
    return wrap;
  }

  function modClock(n,val){
    var NS="http://www.w3.org/2000/svg";
    function s(t,a){ var e=document.createElementNS(NS,t); for(var k in a) e.setAttribute(k,a[k]); return e; }
    var size=220,c=size/2,R=86;
    var svg=s("svg",{viewBox:"0 0 "+size+" "+size,width:size,height:size,role:"img","aria-label":"mod時計"});
    svg.appendChild(s("circle",{cx:c,cy:c,r:R,fill:"none",stroke:"#d9dde8","stroke-width":2}));
    [0,Math.floor(n/4),Math.floor(n/2),Math.floor(3*n/4)].forEach(function(v){
      var a=-Math.PI/2+v/n*2*Math.PI;
      svg.appendChild(s("line",{x1:c+(R-6)*Math.cos(a),y1:c+(R-6)*Math.sin(a),x2:c+R*Math.cos(a),y2:c+R*Math.sin(a),stroke:"#99a0ad","stroke-width":1}));
      var t=s("text",{x:c+(R+12)*Math.cos(a),y:c+(R+12)*Math.sin(a)+3,"text-anchor":"middle",class:"ring-letter"}); t.textContent=v; svg.appendChild(t);
    });
    var ang=-Math.PI/2+(val%n)/n*2*Math.PI, px=c+(R-10)*Math.cos(ang), py=c+(R-10)*Math.sin(ang);
    svg.appendChild(s("line",{x1:c,y1:c,x2:px,y2:py,stroke:"#c9372c","stroke-width":2.5}));
    svg.appendChild(s("circle",{cx:px,cy:py,r:4,fill:"#c9372c"}));
    var lab=s("text",{x:c,y:c+4,"text-anchor":"middle",class:"ring-letter cipher"}); lab.textContent="c="+val; svg.appendChild(lab);
    var host=el("div",{class:"ring-wrap"}); host.appendChild(svg); return host;
  }

  /* ========================= 破る ========================= */
  function panelBreak(state, save){
    var wrap=el("div",{class:"panel"});
    wrap.appendChild(el("p",{html:
      "公開鍵 (n, e) は誰でも見られます。もし n を"+term("素因数分解","n を p×q の形に戻す")+
      "できれば、φ(n) が分かり、秘密鍵 d が計算できて暗号が解けます。ここでは小さな n を実際に分解して破ります。"}));

    var inN=el("input",{type:"number",class:"mono"});
    var inE=el("input",{type:"number",class:"mono",value:"65537"});
    var inC=el("input",{type:"number",class:"mono"});
    wrap.appendChild(el("div",{class:"row"},[
      el("div",{class:"col"},[el("label",{class:"field",text:"公開鍵 n（合成数）"}),inN]),
      el("div",{class:"col"},[el("label",{class:"field",text:"公開指数 e"}),inE])
    ]));
    wrap.appendChild(el("label",{class:"field",text:"暗号文 c（任意：あれば復号します）"}));
    wrap.appendChild(inC);

    function persist(){ state.break_n=inN.value; state.break_e=inE.value; state.break_c=inC.value; state.break_m=inN.dataset.m||""; save(); }
    inN.addEventListener("input",persist); inE.addEventListener("input",persist); inC.addEventListener("input",persist);

    function newChallenge(bits){
      var half=Math.round(bits/2), p=randPrimeNum(half), q=randPrimeNum(bits-half); while(q===p) q=randPrimeNum(bits-half);
      var n=p*q, phi=(p-1)*(q-1), e=65537; if(N.gcd(BigInt(e),BigInt(phi))!==1n) e=5;
      var m=Math.floor(n*0.37), c=Number(N.modpow(BigInt(m),BigInt(e),BigInt(n)));
      inN.value=n; inE.value=e; inC.value=c; inN.dataset.m=m; persist();
    }
    var importBtn=el("button",{class:"btn quiet sm",text:"「見る」で作った鍵を取り込む"});
    var chBtn=el("button",{class:"btn quiet sm",text:"約36ビットの鍵に挑戦"});
    importBtn.addEventListener("click",function(){
      if(!current.n){ CL.toast("先に「見る」で鍵を作ってください"); return; }
      inN.value=current.n; inE.value=current.e; inC.value=(current.c!=null?current.c:""); delete inN.dataset.m; persist();
      CL.toast("取り込みました（n="+current.n+"）");
    });
    chBtn.addEventListener("click",function(){ newChallenge(36); CL.toast("新しい挑戦をつくりました"); });
    wrap.appendChild(el("div",{class:"btn-row"},[importBtn,chBtn]));

    var runBtn=el("button",{class:"btn",text:"素因数分解して鍵を復元"});
    var stopBtn=el("button",{class:"btn red",text:"中止",disabled:"disabled"});
    wrap.appendChild(el("div",{class:"btn-row"},[runBtn,stopBtn]));

    function stat(k,id,v){ return el("div",{class:"stat"},[el("div",{class:"k",text:k}),el("div",{class:"v",id:"f-"+id,text:v})]); }
    function setStat(id,v,red){ var n=document.getElementById("f-"+id); if(n){ n.textContent=v; n.classList.toggle("red",!!red); } }
    wrap.appendChild(el("div",{class:"stats"},[ stat("試した割り算","ops","0"), stat("経過時間","elapsed","0 秒"), stat("結果","verdict","待機中") ]));
    var meterBar=el("i"); wrap.appendChild(el("div",{class:"meter",style:"margin-top:4px"},[meterBar]));
    var out=el("div",{style:"margin-top:12px"}); wrap.appendChild(out);

    var worker=null;
    function finish(){ runBtn.disabled=false; stopBtn.disabled=true; if(worker){ worker.terminate(); if(worker._revoke)worker._revoke(); worker=null; } }
    runBtn.addEventListener("click",function(){
      var n=parseInt(inN.value,10), e=parseInt(inE.value,10);
      if(!(n>3)){ CL.toast("n に合成数を入れてください"); return; }
      if(n>=Math.pow(2,50)){ clear(out); out.appendChild(el("div",{class:"callout",html:"この教材の体験用には n が大きすぎます（約50ビット未満にしてください）。本物の RSA が破れないのは、まさにこの大きさのためです。"})); return; }
      clear(out); setStat("verdict","分解中…"); setStat("ops","0"); setStat("elapsed","0 秒"); meterBar.style.width="0%";
      runBtn.disabled=true; stopBtn.disabled=false;
      worker=CL.worker.fromBody(WORKER_BODY);
      worker.onmessage=function(ev){ onMsg(ev.data,n,e); };
      worker.onerror=function(){ setStat("verdict","エラー"); finish(); };
      worker.postMessage({cmd:"factor", n:n});
    });
    stopBtn.addEventListener("click",function(){ finish(); setStat("verdict","中止"); });

    function onMsg(m,n,e){
      if(m.type==="progress"){ setStat("ops",CL.fmt.sci(m.ops)); setStat("elapsed",m.elapsed.toFixed(1)+" 秒"); meterBar.style.width=Math.min(100,m.d/m.lim*100)+"%"; }
      else if(m.type==="factored"){
        finish(); meterBar.style.width="100%";
        setStat("ops",CL.fmt.sci(m.ops)); setStat("elapsed",CL.fmt.duration(m.elapsed));
        if(m.prime){ setStat("verdict","n は素数",false); out.appendChild(el("div",{class:"callout",html:"n = "+n+" は素数でした。RSA の n は<b>2つの素数の積</b>でなければなりません。"})); return; }
        setStat("verdict","鍵を復元！",true);
        var p=m.p,q=m.q,phi=(p-1)*(q-1),d=N.modinv(BigInt(e),BigInt(phi));
        var html="n を分解： <b>"+n+" = "+p+" × "+q+"</b>（"+CL.fmt.sci(m.ops)+" 回の割り算・"+CL.fmt.duration(m.elapsed)+"）<br>"+
                 "φ(n) = ("+(p-1)+")("+(q-1)+") = "+phi+"<br>"+
                 (d!=null? "秘密鍵 d = <b>"+d+"</b>（e·d ≡ 1 mod φ）" : "d を計算できません（e と φ が互いに素ではない）");
        var c=parseInt(inC.value,10), decLine="";
        if(d!=null && c>=0 && c<n){ var dec=N.modpow(BigInt(c),BigInt(d),BigInt(n)); decLine="<br>暗号文 c="+c+" を復号 → m = c<sup>d</sup> mod n = <b>"+dec+"</b>"; if(inN.dataset.m!==undefined && inN.dataset.m!=="") decLine+="（正解は "+inN.dataset.m+"）"; }
        out.appendChild(el("div",{class:"callout ok",html:html+decLine}));
        CL.store.add("stage4","RSA解読（素因数分解）",{n:n,p:p,q:q,e:e,秘密鍵d:(d!=null?Number(d):""),割り算回数:m.ops,所要秒:+m.elapsed.toFixed(4),ビット長:N.bitLength(n)});
        CL.toast("実験ノートに記録（解読成功）");
      }
    }

    // 復元：保存があればそれを、なければ新しい挑戦
    if(state.break_n){ inN.value=state.break_n; inE.value=state.break_e||"65537"; inC.value=state.break_c||""; if(state.break_m) inN.dataset.m=state.break_m; }
    else newChallenge(36);

    wrap.appendChild(details("試し割りと、本物の攻撃", function(b){
      b.appendChild(el("p",{html:"ここで使っているのは、3, 5, 7, 9… と順に割ってみる"+
        term("試し割り","小さい数から順に割れるか試す、最も素朴な素因数分解法")+"です。最も素朴なぶん遅く、"+
        "n のビット長が増えると時間が爆発します（次の「なぜ破れない？」で実測）。"}));
      b.appendChild(el("p",{html:"現実の攻撃者はもっと賢い方法（数体ふるい法など）を使いますが、それでも 2048 ビットの n は"+
        "現在のコンピュータでは分解できません。なお将来、<b>量子コンピュータ</b>が実用化すると RSA は破れる恐れがあり、"+
        "それに備えた“耐量子暗号”への移行が進められています。"}));
    }));
    return wrap;
  }

  /* ========================= なぜ破れない ========================= */
  function panelWhy(){
    var wrap=el("div",{class:"panel"});
    wrap.appendChild(el("p",{html:"n のビット長を少しずつ増やして、同じ素因数分解にかかる時間を実際に測ります。時間は <b>指数関数的</b>（対数グラフでまっすぐ右肩上がり）にふくれ上がります。"}));
    var runBtn=el("button",{class:"btn",text:"計算量を測る（数秒）"});
    var exportWrap=el("div",{class:"btn-row",style:"display:none"});
    var csvBtn=el("button",{class:"btn quiet sm",text:"測定データをCSV保存"});
    var jsonBtn=el("button",{class:"btn quiet sm",text:"JSON保存"});
    exportWrap.appendChild(csvBtn); exportWrap.appendChild(jsonBtn);
    wrap.appendChild(el("div",{class:"btn-row"},[runBtn]));
    var chartHost=el("div",{style:"margin-top:12px"}); wrap.appendChild(chartHost);
    var tableHost=el("div",{}); wrap.appendChild(tableHost);
    wrap.appendChild(exportWrap);
    var concl=el("div",{style:"margin-top:12px"}); wrap.appendChild(concl);

    var points=[];
    runBtn.addEventListener("click",function(){
      runBtn.disabled=true; runBtn.innerHTML='<span class="spin"></span> 測定中…'; points=[];
      clear(chartHost); clear(tableHost); clear(concl); exportWrap.style.display="none";
      var worker=CL.worker.fromBody(WORKER_BODY);
      worker.onmessage=function(ev){ var m=ev.data;
        if(m.type==="point"){ points.push(m); }
        else if(m.type==="benchDone"){ worker.terminate(); if(worker._revoke)worker._revoke(); runBtn.disabled=false; runBtn.textContent="もう一度測る"; draw(); } };
      worker.postMessage({cmd:"bench", bits:[16,20,24,28,32,36,40,44]});
    });

    function draw(){
      var big=points[points.length-1], ops=Math.sqrt(big.n), rate=ops/Math.max(big.seconds,1e-6);
      var theory=[]; for(var bb=16;bb<=64;bb+=2){ theory.push({x:bb, y:Math.pow(2,bb/2)/rate}); }
      var measured=points.map(function(p){ return {x:p.bits, y:Math.max(p.seconds,1e-6)}; });
      var svg=CL.chart.logLine(
        [ {cls:"series-theory", points:theory}, {cls:"series-measured", points:measured, dots:true} ],
        { xmin:16, xmax:64, ymin:-6, ymax:2, xlabel:"鍵の長さ n（ビット）", ylabel:"解読にかかる時間", xticks:[16,24,32,40,48,56,64] });
      chartHost.appendChild(svg);
      chartHost.appendChild(el("div",{class:"chart-legend"},[
        el("span",{},[el("span",{class:"ln"}),"実測（あなたのブラウザ）"]),
        el("span",{},[el("span",{class:"ln theory"}),"理論（2^(ビット/2)から計算）"]) ]));
      var tbl=el("table",{class:"data"});
      tbl.appendChild(el("tr",{},[el("th",{text:"ビット長"}),el("th",{text:"n"}),el("th",{text:"実測時間"})]));
      points.forEach(function(p){ tbl.appendChild(el("tr",{},[el("td",{class:"mono",text:p.bits}),el("td",{class:"mono",text:p.n}),el("td",{class:"mono",text:CL.fmt.duration(p.seconds)})])); });
      tableHost.appendChild(el("div",{class:"scrollx"},[tbl]));
      exportWrap.style.display="flex";

      function yearsLog10(bits){ return (bits/2)*Math.log10(2) - Math.log10(rate) - Math.log10(3.15576e7); }
      function fmtYears(bits){ var L=yearsLog10(bits); if(L<0) return "1年未満"; if(L<4) return Math.round(Math.pow(10,L)).toLocaleString("en-US")+" 年"; return "約 10^"+Math.round(L)+" 年"; }
      var L2048=yearsLog10(2048), universeLog=10.14;
      concl.appendChild(el("div",{class:"callout info",html:
        "<b>同じ素因数分解で本物の鍵を解くと（このブラウザの速度で外挿）：</b><br>"+
        "・512ビット："+fmtYears(512)+"<br>・1024ビット："+fmtYears(1024)+"<br>"+
        "・2048ビット（実際によく使われる鍵）：<b>"+fmtYears(2048)+"</b><br>"+
        "宇宙の年齢（約10^10年）の <b>10^"+Math.round(L2048-universeLog)+" 倍</b>。"+
        "だから RSA は、やり方が公開されていても現実には破れません。これが"+
        term("計算量的安全性","理屈の上では解けても、現実的な時間では終わらないことによる安全性")+"です。"}));
      concl.appendChild(el("p",{class:"tiny muted",text:"注：試し割りは最も素朴な分解法です。実際の攻撃はもっと速い方法を使いますが、それでも2048ビットは現実的な時間で解けません。"}));
      CL.store.add("stage4","計算量ベンチ(較正)",{推定速度_回每秒:Math.round(rate),測定点数:points.length});
    }
    csvBtn.addEventListener("click",function(){ CL.export.download("cryptolab_stage4_benchmark.csv", CL.export.toCSV(points.map(function(p){ return {ビット長:p.bits,n:p.n,実測秒:p.seconds}; })), "text/csv"); });
    jsonBtn.addEventListener("click",function(){ CL.export.download("cryptolab_stage4_benchmark.json", CL.export.toJSON(points), "application/json"); });
    return wrap;
  }

  CL.route("stage4",{
    title:"Stage 4 ミニRSA",
    render:function(view){
      var ps=CL.pstate("stage4"); var state=ps.get()||{};
      function save(){ ps.set(state); }
      view.appendChild(el("p",{class:"eyebrow",text:"STAGE 4 ／ 公開鍵暗号"}));
      view.appendChild(el("h1",{class:"page-title",text:"ミニRSAと計算量の壁"}));
      view.appendChild(el("p",{class:"page-lead",html:"小さな素数で RSA を作って<b>素因数分解で破り</b>、鍵を長くすると解読時間が爆発することを確かめます。"}));
      view.appendChild(CL.ui.resetBar("このページをリセット",function(){ ps.clear(); CL.router.reload(); }));
      var sec=el("section",{class:"card"});
      var see=panelSee(state,save), brk=panelBreak(state,save), why=panelWhy(); brk.hidden=true; why.hidden=true;
      var bar=CL.ui.tabBar(
        [{id:"see",label:"見る",n:"①"},{id:"break",label:"破る",n:"②"},{id:"why",label:"なぜ破れない？",n:"③"}],
        function(id){ see.hidden=(id!=="see"); brk.hidden=(id!=="break"); why.hidden=(id!=="why"); state.tab=id; save(); });
      sec.appendChild(bar); sec.appendChild(see); sec.appendChild(brk); sec.appendChild(why);
      view.appendChild(sec);
      if(state.tab) bar.select(state.tab);
      view.appendChild(CL.ui.stageNav({id:"stage3",label:"Stage 3"},{id:"data",label:"実験ノート（データ出力）"}));
    }
  });
})();
