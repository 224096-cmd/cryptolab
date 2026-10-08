/* =====================================================================
   Stage 3 — ハッシュ関数とパスワード
   見る（SHA-256・雪崩効果）→ 破る（辞書/総当たりをWorkerで）→ なぜ
   ===================================================================== */
"use strict";
(function(){
  var el=CL.dom.el, clear=CL.dom.clear, term=CL.ui.term;

  /* ---- 解読ワーカー本体（別スレッドで動く。純JSのSHA-256を内蔵） ----
     Blob から Worker を作るため、ここでは本体を文字列で持つ。          */
  var WORKER_BODY = `
'use strict';
// ---- SHA-256（純JavaScript実装） ----
var K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
function rotr(x,n){return (x>>>n)|(x<<(32-n));}
function sha256hex(bytes){
  var H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  var l=bytes.length; var bitLen=l*8;
  var withOne=l+1; var kpad=(56-(withOne%64)+64)%64; var total=withOne+kpad+8;
  var m=new Uint8Array(total); m.set(bytes); m[l]=0x80;
  var hi=Math.floor(bitLen/0x100000000), lo=bitLen>>>0;
  m[total-8]=(hi>>>24)&255; m[total-7]=(hi>>>16)&255; m[total-6]=(hi>>>8)&255; m[total-5]=hi&255;
  m[total-4]=(lo>>>24)&255; m[total-3]=(lo>>>16)&255; m[total-2]=(lo>>>8)&255; m[total-1]=lo&255;
  var w=new Uint32Array(64);
  for(var off=0; off<total; off+=64){
    for(var i=0;i<16;i++){ w[i]=(m[off+i*4]<<24)|(m[off+i*4+1]<<16)|(m[off+i*4+2]<<8)|(m[off+i*4+3]); }
    for(i=16;i<64;i++){
      var s0=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>>3);
      var s1=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>>10);
      w[i]=(w[i-16]+s0+w[i-7]+s1)|0;
    }
    var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
    for(i=0;i<64;i++){
      var S1=rotr(e,6)^rotr(e,11)^rotr(e,25);
      var ch=(e&f)^((~e)&g);
      var t1=(h+S1+ch+K[i]+w[i])|0;
      var S0=rotr(a,2)^rotr(a,13)^rotr(a,22);
      var maj=(a&b)^(a&c)^(b&c);
      var t2=(S0+maj)|0;
      h=g; g=f; f=e; e=(d+t1)|0; d=c; c=b; b=a; a=(t1+t2)|0;
    }
    H[0]=(H[0]+a)|0;H[1]=(H[1]+b)|0;H[2]=(H[2]+c)|0;H[3]=(H[3]+d)|0;
    H[4]=(H[4]+e)|0;H[5]=(H[5]+f)|0;H[6]=(H[6]+g)|0;H[7]=(H[7]+h)|0;
  }
  var hex="";
  for(i=0;i<8;i++){ hex += ("00000000"+(H[i]>>>0).toString(16)).slice(-8); }
  return hex;
}
function strBytes(s){ var b=new Uint8Array(s.length); for(var i=0;i<s.length;i++) b[i]=s.charCodeAt(i)&255; return b; }
var DICT=["password","123456","12345678","1234","qwerty","abc123","111111","letmein",
"admin","welcome","iloveyou","000000","monkey","dragon","sunshine","password1","1234567",
"football","princess","login","passw0rd","test","hello","root","guest","secret","master"];

onmessage=function(ev){
  var d=ev.data; var target=d.targetHex; var charset=d.charset; var maxLen=d.maxLen;
  var started=Date.now(); var tried=0; var stopEvery=20000;
  if(d.useDict){
    for(var i=0;i<DICT.length;i++){
      tried++;
      if(sha256hex(strBytes(DICT[i]))===target){
        postMessage({type:"found",password:DICT[i],via:"辞書",tried:tried,elapsed:(Date.now()-started)/1000});
        return;
      }
    }
  }
  var cs=charset.split(""); var n=cs.length;
  for(var len=1; len<=maxLen; len++){
    var idx=new Array(len); for(var j=0;j<len;j++) idx[j]=0;
    while(true){
      var s=""; for(j=0;j<len;j++) s+=cs[idx[j]];
      tried++;
      if(sha256hex(strBytes(s))===target){
        postMessage({type:"found",password:s,via:"総当たり",tried:tried,elapsed:(Date.now()-started)/1000});
        return;
      }
      if(tried%stopEvery===0){
        postMessage({type:"progress",tried:tried,elapsed:(Date.now()-started)/1000,sample:s});
      }
      var p=len-1;
      while(p>=0){ idx[p]++; if(idx[p]<n) break; idx[p]=0; p--; }
      if(p<0) break;
    }
  }
  postMessage({type:"exhausted",tried:tried,elapsed:(Date.now()-started)/1000});
};
`;

  function spaceSize(nChars, maxLen){
    var t=0, pow=1; for(var L=1;L<=maxLen;L++){ pow*=nChars; t+=pow; } return t;
  }
  function esc(s){ return String(s).replace(/[&<>]/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;"}[c];}); }

  /* ========================= 見る ========================= */
  function panelSee(){
    var wrap=el("div",{class:"panel"});
    wrap.appendChild(el("p",{html:
      term("ハッシュ関数","どんな長さのデータからも、決まった長さの“指紋”を作る一方向の計算。元に戻せない")+
      "（ここでは SHA-256）は、入力から 256ビット＝64桁の16進数の“指紋”を作ります。"+
      "同じ入力からは必ず同じ指紋。でも指紋から元の入力は<b>復元できません</b>。"}));

    var inH=el("input",{type:"text",value:"joho1",spellcheck:"false",autocomplete:"off"});
    var outH=el("div",{class:"mono-box"});
    inH.addEventListener("input",function(){ CL.crypto.sha256Hex(inH.value).then(function(h){ outH.textContent=h; }); });
    wrap.appendChild(el("label",{class:"field",text:"入力（なんでも）"}));
    wrap.appendChild(inH);
    wrap.appendChild(el("label",{class:"field",text:"SHA-256 ハッシュ値（64桁）"}));
    wrap.appendChild(outH);

    wrap.appendChild(el("hr",{class:"soft"}));
    wrap.appendChild(el("h3",{text:"雪崩（なだれ）効果をみる"}));
    wrap.appendChild(el("p",{html:"入力を1文字変えると、指紋の約<b>半分</b>のビットが反転します（"+
      term("雪崩効果","入力の小さな違いが出力全体に大きく広がる性質。アバランシェ効果")+"）。"}));

    var inA=el("input",{type:"text",value:"Hello",spellcheck:"false",autocomplete:"off"});
    var inB=el("input",{type:"text",value:"hello",spellcheck:"false",autocomplete:"off"});
    var hexA=el("div",{class:"hash-hex"}), hexB=el("div",{class:"hash-hex"});
    var grid=el("div",{class:"bitgrid cmp"});
    var cells=[]; for(var i=0;i<256;i++){ var cc=el("span",{class:"bit"}); cells.push(cc); grid.appendChild(cc); }
    var meterBar=el("i"); var diffStat=el("span",{style:"font-family:var(--mono);font-weight:700;color:#c9372c"});

    function toHexDiff(host, hex, other){
      clear(host);
      for(var i=0;i<hex.length;i++){
        var sp=el("span",{text:hex[i]});
        if(other.length===hex.length && hex[i]!==other[i]) sp.className="diff";
        host.appendChild(sp);
      }
    }
    function update(){
      Promise.all([CL.crypto.sha256Bytes(inA.value),CL.crypto.sha256Bytes(inB.value)]).then(function(r){
        var ua=r[0], ub=r[1];
        var ha=CL.crypto.bytesToHex(ua), hb=CL.crypto.bytesToHex(ub);
        toHexDiff(hexA,ha,hb); toHexDiff(hexB,hb,ha);
        var bitsA=CL.crypto.bytesToBits(ua), bitsB=CL.crypto.bytesToBits(ub), diff=0;
        for(var i=0;i<256;i++){
          var flip=bitsA[i]!==bitsB[i]; if(flip) diff++;
          cells[i].className="bit"+(bitsB[i]?" on":"")+(flip?" flip":"");
        }
        meterBar.style.width=(diff/256*100)+"%";
        diffStat.textContent="反転ビット "+diff+" / 256（"+(diff/256*100).toFixed(1)+"%）";
      }).catch(function(){});
    }
    inA.addEventListener("input",update); inB.addEventListener("input",update);

    wrap.appendChild(el("label",{class:"field",text:"入力A"})); wrap.appendChild(inA); wrap.appendChild(hexA);
    wrap.appendChild(el("label",{class:"field",text:"入力B"})); wrap.appendChild(inB); wrap.appendChild(hexB);
    wrap.appendChild(el("div",{class:"inline",style:"margin-top:12px"},[el("div",{class:"meter"},[meterBar]),diffStat]));
    wrap.appendChild(el("p",{class:"tiny muted",text:"下の赤いマスが、A と B で反転したビット（256個中）。"}));
    wrap.appendChild(grid);
    wrap.appendChild(el("div",{class:"legend"},[
      el("span",{},[el("span",{class:"sw",style:"background:#2b50c8"}),"Bのビット=1"]),
      el("span",{},[el("span",{class:"sw",style:"background:#e7ecf5"}),"Bのビット=0"]),
      el("span",{},[el("span",{class:"sw",style:"background:#c9372c"}),"A と B で反転"])
    ]));
    CL.crypto.sha256Hex(inH.value).then(function(h){ outH.textContent=h; });
    update();
    return wrap;
  }

  /* ========================= 破る ========================= */
  function panelBreak(){
    var wrap=el("div",{class:"panel"});
    wrap.appendChild(el("p",{html:
      "ハッシュは元に戻せません。でも「あやしいパスワードを片っぱしからハッシュして、"+
      "指紋が一致するか見る」なら解けます（"+term("辞書攻撃","よくあるパスワードの一覧を順に試す攻撃")+"・"+
      term("総当たり","考えうる文字の組合せを全部試す攻撃")+"）。弱いパスワードがいかに速く割れるかを見ます。"}));

    var inPw=el("input",{type:"text",value:"123",spellcheck:"false",autocomplete:"off"});
    var presets=el("div",{class:"btn-row"});
    ["1234","password","7k","q9z"].forEach(function(p){
      presets.appendChild(el("button",{class:"btn quiet sm",text:p,onclick:function(){ inPw.value=p; }}));
    });
    wrap.appendChild(el("label",{class:"field",text:"ねらうパスワード（英数字・短め。実在のものは入れないでください）"}));
    wrap.appendChild(inPw);
    wrap.appendChild(el("div",{class:"tiny muted",style:"margin:4px 0"},["例（押すと入ります）："]));
    wrap.appendChild(presets);

    var selCs=el("select",{},[
      el("option",{value:"0123456789",text:"数字のみ（0-9）"}),
      el("option",{value:"abcdefghijklmnopqrstuvwxyz",text:"小文字のみ（a-z）"}),
      el("option",{value:"abcdefghijklmnopqrstuvwxyz0123456789",text:"小文字＋数字（a-z,0-9）"})
    ]);
    var selLen=el("select",{});
    for(var L=2;L<=6;L++){ selLen.appendChild(el("option",{value:String(L),text:"最大 "+L+" 文字",selected:L===4?"selected":null})); }
    var chkDict=el("input",{type:"checkbox",checked:"checked"});
    wrap.appendChild(el("div",{class:"row"},[
      el("div",{class:"col"},[el("label",{class:"field",text:"ためす文字の種類"}),selCs]),
      el("div",{class:"col"},[el("label",{class:"field",text:"ためす長さの上限"}),selLen])
    ]));
    wrap.appendChild(el("label",{class:"inline",style:"margin-top:10px;font-size:.9rem"},[chkDict," まず辞書（よくあるパスワード）をためす"]));

    var spaceNote=el("p",{class:"tiny muted"});
    function updateSpace(){
      var n=selCs.value.length, maxL=parseInt(selLen.value,10);
      var total=spaceSize(n,maxL);
      spaceNote.innerHTML="この設定で試す組合せ：最大 <b>"+CL.fmt.sci(total)+"</b> 通り"+
        (total>5e6?"（<span style='color:#c9372c'>多め：数十秒かかることがあります</span>）":"");
    }
    selCs.addEventListener("change",updateSpace); selLen.addEventListener("change",updateSpace); updateSpace();
    wrap.appendChild(spaceNote);

    var startBtn=el("button",{class:"btn",text:"解読を開始"});
    var stopBtn=el("button",{class:"btn red",text:"中止",disabled:"disabled"});
    wrap.appendChild(el("div",{class:"btn-row"},[startBtn,stopBtn]));

    function stat(k,id,v){ return el("div",{class:"stat"},[el("div",{class:"k",text:k}),el("div",{class:"v",id:"st-"+id,text:v})]); }
    function setStat(id,v,red){ var n=document.getElementById("st-"+id); if(n){ n.textContent=v; n.classList.toggle("red",!!red); } }
    var stats=el("div",{class:"stats"},[
      stat("試した回数","tried","0"), stat("経過時間","elapsed","0 秒"),
      stat("1秒あたり","rate","— /秒"), stat("結果","verdict","待機中")
    ]);
    wrap.appendChild(stats);
    var meterBar=el("i"); wrap.appendChild(el("div",{class:"meter",style:"margin-top:4px"},[meterBar]));
    var found=el("div",{style:"margin-top:12px"}); wrap.appendChild(found);

    var worker=null, total=0, settings={};
    function finish(){ startBtn.disabled=false; stopBtn.disabled=true; if(worker){ worker.terminate(); if(worker._revoke) worker._revoke(); worker=null; } }

    startBtn.addEventListener("click",function(){
      var pw=inPw.value;
      if(!pw){ CL.toast("ねらうパスワードを入れてください"); return; }
      if(!/^[\x21-\x7e]+$/.test(pw)){ CL.toast("英数字・記号（半角・空白なし）にしてください"); return; }
      clear(found); setStat("verdict","解読中…"); meterBar.style.width="0%";
      setStat("tried","0"); setStat("elapsed","0 秒"); setStat("rate","— /秒");
      startBtn.disabled=true; stopBtn.disabled=false;
      settings={charset:selCs.value, maxLen:parseInt(selLen.value,10), useDict:chkDict.checked,
                csLabel:selCs.options[selCs.selectedIndex].text};
      total=spaceSize(settings.charset.length, settings.maxLen);
      CL.crypto.sha256Hex(pw).then(function(hex){
        worker=CL.worker.fromBody(WORKER_BODY);
        worker.onmessage=function(ev){ onMsg(ev.data, pw); };
        worker.onerror=function(e){ setStat("verdict","エラー"); CL.toast("解読中にエラー: "+e.message); finish(); };
        worker.postMessage({targetHex:hex, charset:settings.charset, maxLen:settings.maxLen, useDict:settings.useDict});
      });
    });
    stopBtn.addEventListener("click",function(){
      finish(); setStat("verdict","中止");
      CL.store.add("stage3","パスワード解読（中止）",{設定:settings.csLabel, 長さ上限:settings.maxLen});
    });

    function onMsg(m, pw){
      if(m.type==="progress"){
        setStat("tried",CL.fmt.sci(m.tried));
        setStat("elapsed",m.elapsed.toFixed(1)+" 秒");
        setStat("rate",CL.fmt.sci(m.tried/Math.max(m.elapsed,1e-6))+" /秒");
        if(total>0) meterBar.style.width=Math.min(100,m.tried/total*100)+"%";
      } else if(m.type==="found"){
        finish(); meterBar.style.width="100%";
        setStat("tried",CL.fmt.sci(m.tried)); setStat("elapsed",CL.fmt.duration(m.elapsed));
        setStat("rate",CL.fmt.sci(m.tried/Math.max(m.elapsed,1e-6))+" /秒");
        setStat("verdict","解読成功！",true);
        found.appendChild(el("div",{class:"callout ok",html:
          "パスワードは <b>「"+esc(m.password)+"」</b> でした（"+m.via+"／"+
          CL.fmt.sci(m.tried)+" 回目・"+CL.fmt.duration(m.elapsed)+"）。"}));
        CL.store.add("stage3","パスワード解読",{
          パスワード:pw, 文字数:pw.length, 発見方法:m.via, 試行回数:m.tried,
          所要秒:+m.elapsed.toFixed(4), 設定:settings.csLabel, 長さ上限:settings.maxLen, 解読成功:"はい"
        });
        CL.toast("実験ノートに記録（解読成功）");
      } else if(m.type==="exhausted"){
        finish(); setStat("tried",CL.fmt.sci(m.tried)); setStat("elapsed",CL.fmt.duration(m.elapsed));
        setStat("verdict","見つからず",false);
        found.appendChild(el("div",{class:"callout",html:
          "この設定（"+settings.csLabel+"・最大"+settings.maxLen+"文字）では見つかりませんでした。"+
          "<b>長さや文字の種類を増やすほど、解読に必要な時間は一気にふくれ上がります。</b>"}));
        CL.store.add("stage3","パスワード解読（失敗）",{
          パスワード:pw, 文字数:pw.length, 試行回数:m.tried, 所要秒:+m.elapsed.toFixed(4),
          設定:settings.csLabel, 長さ上限:settings.maxLen, 解読成功:"いいえ"
        });
      }
    }
    return wrap;
  }

  /* ========================= なぜ ========================= */
  function panelWhy(){
    var wrap=el("div",{class:"panel"});
    wrap.appendChild(el("p",{html:"同じ「1秒で100万回ハッシュを計算できる攻撃者」が、パスワードを総当たりする時間の目安："}));
    var rate=1e6;
    var charsets=[["数字(10)",10],["小文字(26)",26],["小文字＋数字(36)",36]];
    var tbl=el("table",{class:"data"});
    var head=el("tr",{},[el("th",{text:"文字数＼種類"})]);
    charsets.forEach(function(c){ head.appendChild(el("th",{text:c[0]})); });
    tbl.appendChild(head);
    [4,6,8,10].forEach(function(len){
      var tr=el("tr",{},[el("th",{text:len+" 文字"})]);
      charsets.forEach(function(c){ tr.appendChild(el("td",{class:"mono",text:CL.fmt.duration(Math.pow(c[1],len)/rate)})); });
      tbl.appendChild(tr);
    });
    wrap.appendChild(el("div",{class:"scrollx"},[tbl]));
    wrap.appendChild(el("p",{class:"tiny muted",text:"※ 1秒100万回という控えめな想定。実際はもっと速いこともありますが、長さを増やす効果は絶大です。"}));

    wrap.appendChild(el("div",{class:"callout info",html:
      "<b>わかること：</b> パスワードは<b>長さ</b>がいちばん効きます。1文字増やすだけで総当たりの手間が文字種の倍数（小文字なら26倍）にふくれ上がるからです。"}));
    wrap.appendChild(el("h3",{text:"ソルト（salt）という工夫"}));
    wrap.appendChild(el("p",{html:
      term("ソルト","各パスワードにつける使い捨ての追加文字列。保存するハッシュをユーザーごとに変える")+
      "を足すと、同じパスワードでも人によって指紋が変わり、「指紋表を作りだめして一気に照合する攻撃（レインボーテーブル）」が効かなくなります。"}));
    var saltDemo=el("div",{class:"mono-box"});
    Promise.all([CL.crypto.sha256Hex("password"),CL.crypto.sha256Hex("x7q!password")]).then(function(r){
      saltDemo.innerHTML="SHA-256(\"password\")        = "+r[0].slice(0,24)+"…<br>"+
                         "SHA-256(\"x7q!\"＋\"password\") = "+r[1].slice(0,24)+"…　←ソルトで別物に";
    });
    wrap.appendChild(saltDemo);
    wrap.appendChild(el("p",{class:"tiny muted",text:
      "補足：本物のシステムは、わざと計算の遅いハッシュ（bcrypt / Argon2 など）を使い、総当たりをさらに遅くしています。"}));
    return wrap;
  }

  CL.route("stage3",{
    title:"Stage 3 ハッシュとパスワード",
    render:function(view){
      view.appendChild(el("p",{class:"eyebrow",text:"STAGE 3 ／ ハッシュ関数"}));
      view.appendChild(el("h1",{class:"page-title",text:"ハッシュとパスワードを破る"}));
      view.appendChild(el("p",{class:"page-lead",html:"元に戻せない“指紋”＝ハッシュ。それでも<b>弱いパスワードは総当たりで割れる</b>ことを体験します。"}));
      var sec=el("section",{class:"card"});
      var see=panelSee(), brk=panelBreak(), why=panelWhy(); brk.hidden=true; why.hidden=true;
      var bar=CL.ui.tabBar(
        [{id:"see",label:"見る",n:"①"},{id:"break",label:"破る",n:"②"},{id:"why",label:"なぜ？",n:"③"}],
        function(id){ see.hidden=(id!=="see"); brk.hidden=(id!=="break"); why.hidden=(id!=="why"); });
      sec.appendChild(bar); sec.appendChild(see); sec.appendChild(brk); sec.appendChild(why);
      view.appendChild(sec);
      view.appendChild(CL.ui.stageNav({id:"stage2",label:"Stage 2"},{id:"stage4",label:"Stage 4 ミニRSA"}));
    }
  });
})();
