/* =====================================================================
   送受信 — 暗号を作って別の端末に送り、受け取った側が解読する
   ・サーバー不要：問題は「リンク／コード」に詰めて共有（1対多もOK）
   ・答えは平文ではなく SHA-256（先頭16桁）で照合するので、リンクに答えは出ない
   ===================================================================== */
"use strict";
(function(){
  var el=CL.dom.el, clear=CL.dom.clear, term=CL.ui.term, C=CL.cipher, codec=CL.codec;

  function sha16(s){ return CL.crypto.sha256Hex(String(s).toUpperCase()).then(function(h){ return h.slice(0,16); }); }
  function countAZ(s){ var n=0; s=String(s).toUpperCase(); for(var i=0;i<s.length;i++){ var c=s.charCodeAt(i); if(c>=65&&c<=90) n++; } return n; }
  function copyText(t){ CL.export.copy(t).then(function(){ CL.toast("コピーしました"); },function(){ CL.toast("コピーできませんでした（手動で選択してください）"); }); }

  // QRライブラリ（あれば使う。無ければQRは省略してリンク共有のみ）
  function drawQR(host, text){
    clear(host);
    if(typeof window.qrcode!=="function"){ host.style.display="none"; return; }
    try{
      var qr=window.qrcode(0,"M"); qr.addData(text); qr.make();
      host.style.display="flex";
      host.innerHTML=qr.createImgTag(4,8);
      var img=host.querySelector("img"); if(img){ img.alt="共有用QRコード"; img.style.width="200px"; img.style.height="200px"; }
    }catch(e){
      host.style.display="none"; // データが長すぎてQR化できない等
    }
  }

  /* ========================= 作って送る ========================= */
  function panelMake(){
    var wrap=el("div",{class:"panel"});
    wrap.appendChild(el("p",{html:
      "英字（ローマ字）のメッセージを暗号にして、<b>リンクやコード</b>で友だちの端末へ送れます。"+
      "同じリンクは<b>何人に送ってもOK</b>（1対多）。受け取った人が解読に挑戦します。"}));
    wrap.appendChild(el("div",{class:"hintline",html:"<b>やってみよう：</b>メッセージを英語（ローマ字）で書いて <b>「暗号を作る」</b>。出てきたリンクを LINE やメール、AirDrop などで送りましょう。"}));

    var inName=el("input",{type:"text",maxlength:"20",autocomplete:"off",placeholder:"例：たろう"});
    wrap.appendChild(el("label",{class:"field",text:"送り主の名前（任意・記録用）"}));
    wrap.appendChild(inName);

    var selType=el("select",{},[
      el("option",{value:"caesar",text:"シーザー暗号（やさしい・すぐ解ける）"}),
      el("option",{value:"subst",text:"換字式暗号（むずかしい・頻度分析で）"})
    ]);
    wrap.appendChild(el("label",{class:"field",text:"暗号の種類"}));
    wrap.appendChild(selType);

    var selShift=el("select",{}); selShift.appendChild(el("option",{value:"random",text:"ランダム（おまかせ）"}));
    for(var k=1;k<=25;k++) selShift.appendChild(el("option",{value:String(k),text:"ずらす数 = "+k}));
    var shiftWrap=el("div",{},[el("label",{class:"field",text:"ずらす数（鍵）"}),selShift]);
    wrap.appendChild(shiftWrap);
    selType.addEventListener("change",function(){ shiftWrap.style.display = selType.value==="caesar"?"":"none"; });

    var inMsg=el("textarea",{class:"mono",spellcheck:"false",placeholder:"MEET AT THE LIBRARY AT THREE"});
    inMsg.value="MEET AT THE LIBRARY AT THREE";
    wrap.appendChild(el("label",{class:"field",text:"メッセージ（英字／ローマ字で入力）"}));
    wrap.appendChild(inMsg);

    var makeBtn=el("button",{class:"btn",text:"暗号を作る"});
    wrap.appendChild(el("div",{class:"btn-row"},[makeBtn]));
    var out=el("div",{style:"margin-top:12px"}); wrap.appendChild(out);

    makeBtn.addEventListener("click",function(){
      var msg=inMsg.value;
      if(!msg.trim()){ CL.toast("メッセージを入れてください"); return; }
      if(countAZ(msg)<3){ CL.toast("英字（ローマ字）が少ないため、ほとんど暗号になりません"); }
      var t=selType.value, cipher, meta={};
      if(t==="caesar"){
        var k = selShift.value==="random" ? (1+Math.floor(Math.random()*25)) : parseInt(selShift.value,10);
        cipher=C.caesar(msg,k); meta.k=k;
      } else {
        var key=C.randomKey(); cipher=C.applyMap(msg,key);
      }
      sha16(msg).then(function(a){
        var payload={v:1,t:t,c:cipher,n:inName.value.trim(),a:a};
        var code=codec.enc(payload);
        var link=codec.baseUrl()+"#/exchange?d="+code;
        renderShare(out, link, code, cipher, t);
        CL.store.add("exchange","出題作成",{種類:t==="caesar"?"シーザー":"換字式",送り主:inName.value.trim()||"(無名)",文字数:msg.length});
      });
    });
    return wrap;
  }

  function renderShare(out, link, code, cipher, t){
    clear(out);
    out.appendChild(el("div",{class:"callout ok",html:"暗号ができました（"+(t==="caesar"?"シーザー":"換字式")+"）。下のリンクかコードを相手に送ってください。"}));
    out.appendChild(el("label",{class:"field",text:"暗号文"}));
    out.appendChild(el("div",{class:"mono-box",text:cipher}));

    out.appendChild(el("label",{class:"field",text:"共有リンク（タップで開くと解読画面に）"}));
    var linkIn=el("input",{type:"text",readonly:"readonly",value:link});
    var copyLink=el("button",{class:"btn sm",text:"リンクをコピー",onclick:function(){ copyText(link); }});
    out.appendChild(el("div",{class:"share-box"},[linkIn,copyLink]));

    var shareRow=el("div",{class:"btn-row"});
    if(navigator.share){
      shareRow.appendChild(el("button",{class:"btn sm ghost",text:"共有…（アプリで送る）",onclick:function(){
        navigator.share({title:"CryptoLab 暗号の挑戦",text:"この暗号を解読してみて！",url:link}).catch(function(){});
      }}));
    }
    out.appendChild(shareRow);

    out.appendChild(el("label",{class:"field",text:"コード（リンクが使えないとき、これを「受け取る」に貼り付け）"}));
    var codeTa=el("textarea",{class:"mono",readonly:"readonly",style:"min-height:3.2em"}); codeTa.value=code;
    out.appendChild(codeTa);
    out.appendChild(el("div",{class:"btn-row"},[el("button",{class:"btn sm quiet",text:"コードをコピー",onclick:function(){ copyText(code); }})]));

    var qr=el("div",{class:"qr-host"}); out.appendChild(qr); drawQR(qr, link);
    if(qr.style.display!=="none") out.appendChild(el("p",{class:"tiny muted",style:"text-align:center",text:"相手の端末の標準カメラでこのQRを読み取ってもOK"}));
    out.appendChild(el("p",{class:"tiny muted",text:"※ 答え（平文）はリンクに入っていません（正解照合用のハッシュだけ）。同じリンクを何人に送っても使えます。"}));
  }

  /* ========================= 受け取って解く ========================= */
  function panelSolve(preload){
    var wrap=el("div",{class:"panel"});
    var host=el("div"); // チャレンジ表示先

    if(!preload){
      wrap.appendChild(el("p",{html:"友だちから届いた<b>リンク</b>はタップするだけで解読画面になります。"+
        "うまく開けないときは、もらった<b>コード</b>（またはリンク）をここに貼って「読み込む」。"}));
      var inCode=el("textarea",{class:"mono",spellcheck:"false",placeholder:"ここにリンクかコードを貼り付け"});
      var loadBtn=el("button",{class:"btn",text:"読み込む"});
      wrap.appendChild(inCode);
      wrap.appendChild(el("div",{class:"btn-row"},[loadBtn]));
      loadBtn.addEventListener("click",function(){
        var p=codec.dec(codec.extract(inCode.value));
        if(!p||!p.t){ CL.toast("読み取れませんでした。リンクかコードをもう一度確認してください"); return; }
        clear(host); renderChallenge(host, p);
      });
    } else {
      renderChallenge(host, preload);
    }
    wrap.appendChild(host);
    return wrap;
  }

  function renderChallenge(host, p){
    clear(host);
    var from = p.n ? ("「"+p.n+"」さんからの挑戦") : "暗号の挑戦";
    host.appendChild(el("h3",{html:from+" <span class='recv-type'>"+(p.t==="caesar"?"シーザー暗号":"換字式暗号")+"</span>"}));
    host.appendChild(el("label",{class:"field",text:"あなたの名前（任意・記録用）"}));
    var solver=el("input",{type:"text",maxlength:"20",autocomplete:"off",placeholder:"例：はなこ"});
    host.appendChild(solver);
    host.appendChild(el("label",{class:"field",text:"暗号文"}));
    host.appendChild(el("div",{class:"mono-box",text:p.c}));
    var result=el("div",{style:"margin-top:10px"});

    function success(plain){
      result.innerHTML="";
      result.appendChild(el("div",{class:"callout ok",html:"<b>解読成功！</b> 平文は <b>「"+escapeHtml(plain)+"」</b> でした。"}));
      CL.store.add("exchange","受信解読",{種類:p.t==="caesar"?"シーザー":"換字式",送り主:p.n||"(無名)",解答者:solver.value.trim()||"(無名)",文字数:String(p.c).length,解読:"成功"});
      CL.toast("実験ノートに記録（解読成功）");
    }

    if(p.t==="caesar"){ renderCaesar(host, p, result, success); }
    else { renderSubst(host, p, result, success); }
    host.appendChild(result);
  }

  function renderCaesar(host, p, result, success){
    host.appendChild(el("div",{class:"hintline",html:"<b>やってみよう：</b>「25通りを全部ためす」を押して、意味の通る行の「これだ！」を押しましょう。"}));
    var btn=el("button",{class:"btn",text:"25通りを全部ためす"});
    host.appendChild(el("div",{class:"btn-row"},[btn]));
    var tblHost=el("div",{style:"margin-top:10px"}); host.appendChild(tblHost);
    btn.addEventListener("click",function(){
      clear(tblHost);
      var rows=[],best=-1,bestChi=1e18;
      for(var k=1;k<=25;k++){ var dec=C.caesar(p.c,-k), chi=C.chiSquare(dec); rows.push({k:k,dec:dec,chi:chi}); if(chi<bestChi){ bestChi=chi; best=k; } }
      var tbl=el("table",{class:"data"});
      tbl.appendChild(el("tr",{},[el("th",{text:"鍵"}),el("th",{text:"復号結果"}),el("th",{text:""})]));
      rows.forEach(function(r){
        var pick=el("button",{class:"btn quiet sm",text:"これだ！",onclick:function(){
          sha16(r.dec).then(function(h){ if(h===p.a) success(r.dec); else CL.toast("まだ違うようです。別の行を試してみて"); });
        }});
        tbl.appendChild(el("tr", r.k===best?{class:"hit"}:{}, [el("td",{class:"mono",text:String(r.k)}),el("td",{class:"mono",text:r.dec}),el("td",{},[pick])]));
      });
      tblHost.appendChild(el("div",{class:"scrollx"},[tbl]));
    });
  }

  function renderSubst(host, p, result, success){
    host.appendChild(el("div",{class:"hintline",html:"<b>やってみよう：</b>「頻度順にまず仮あて」を押し、出てきた文を手がかりに下のマスの文字を直していきましょう。全部正しく当たると自動で判定します。"}));
    var cipher=p.c, guess={}, seq=0;
    // 頻度バー
    var f=C.freq(cipher), maxf=1;
    var order=C.AZ.split("").sort(function(a,b){ return f[b]-f[a]; });
    order.forEach(function(L){ if(f[L]>maxf) maxf=f[L]; });
    var fg=el("div",{class:"freq",style:"margin-top:8px"});
    order.forEach(function(L){ if(f[L]===0) return;
      fg.appendChild(el("span",{class:"lab",text:L}));
      fg.appendChild(el("span",{class:"bar",style:"width:"+(f[L]/maxf*100)+"%"}));
      fg.appendChild(el("span",{class:"val",text:f[L]})); });
    host.appendChild(el("p",{class:"tiny muted",style:"margin-top:8px",html:"英語で多い順：E T A O I N S H R D L …"}));
    host.appendChild(fg);

    var btns=el("div",{class:"btn-row"});
    var hintBtn=el("button",{class:"btn ghost sm",text:"頻度順にまず仮あて"});
    var clearBtn=el("button",{class:"btn quiet sm",text:"ぜんぶ消す"});
    btns.appendChild(hintBtn); btns.appendChild(clearBtn); host.appendChild(btns);

    var grid=el("div",{class:"mapgrid"}); var inputs={};
    order.forEach(function(L){ if(f[L]===0) return;
      var inp=el("input",{type:"text",maxlength:"1"});
      inputs[L]=inp;
      inp.addEventListener("input",function(){ var v=inp.value.toUpperCase().replace(/[^A-Z]/g,""); inp.value=v; if(v) guess[L]=v; else delete guess[L]; refresh(); });
      grid.appendChild(el("div",{class:"mapcell"},[el("div",{class:"from",text:L}),el("div",{class:"arr",text:"↓"}),inp]));
    });
    host.appendChild(grid);
    var decoded=el("div",{class:"decoded mono-box"}); host.appendChild(el("label",{class:"field",text:"今の復号結果"})); host.appendChild(decoded);

    var EN_ORDER="ETAOINSHRDLCUMWFGYPBVKJXQZ";
    hintBtn.addEventListener("click",function(){
      var oc=C.AZ.split("").filter(function(L){return f[L]>0;}).sort(function(a,b){return f[b]-f[a];});
      for(var L in guess) delete guess[L];
      oc.forEach(function(L,i){ var pl=EN_ORDER[i]||""; if(pl){ guess[L]=pl; if(inputs[L]) inputs[L].value=pl; } });
      refresh();
    });
    clearBtn.addEventListener("click",function(){ for(var L in guess) delete guess[L]; for(var k in inputs) inputs[k].value=""; refresh(); });

    var solved=false;
    function refresh(){
      var used={},dup={}; for(var c in guess){ var g=guess[c]; if(used[g]) dup[g]=true; used[g]=1; }
      for(var L in inputs){ var v=inputs[L].value.toUpperCase(); inputs[L].style.borderColor=(v&&dup[v])?"#c9372c":""; inputs[L].style.background=(v&&dup[v])?"#fdeeec":""; }
      clear(decoded);
      var cand="";
      for(var i=0;i<cipher.length;i++){ var ch=cipher[i];
        if(ch>="A"&&ch<="Z"){ var g2=guess[ch]; if(g2){ decoded.appendChild(el("span",{class:"known",text:g2})); cand+=g2; } else { decoded.appendChild(el("span",{class:"unknown",text:"·"})); cand+="?"; } }
        else if(ch>="a"&&ch<="z"){ var up=ch.toUpperCase(); var g3=guess[up]; if(g3){ decoded.appendChild(el("span",{class:"known",text:g3.toLowerCase()})); cand+=g3; } else { decoded.appendChild(el("span",{class:"unknown",text:"·"})); cand+="?"; } }
        else { decoded.appendChild(document.createTextNode(ch)); cand+=ch; }
      }
      if(solved) return;
      if(cand.indexOf("?")<0){
        var my=++seq;
        sha16(cand).then(function(h){ if(my===seq && !solved && h===p.a){ solved=true; success(cand); } });
      }
    }
    refresh();
  }

  function escapeHtml(s){ return String(s).replace(/[&<>]/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;"}[c];}); }

  /* ========================= ルート ========================= */
  CL.route("exchange",{
    title:"送受信",
    render:function(view){
      view.appendChild(el("p",{class:"eyebrow",text:"暗号を送る・受け取る"}));
      view.appendChild(el("h1",{class:"page-title",text:"暗号を送受信する"}));
      view.appendChild(el("p",{class:"page-lead",html:"別の端末どうしで暗号を送り合って解読できます。<b>サーバーは使いません</b>——問題はリンクやコードに入れて届けます。"}));

      // 保険：古いファイルがキャッシュされている等で基盤が未読込なら、赤いエラーではなく案内を出す
      if(!codec || !C){
        view.appendChild(el("section",{class:"card"},[
          el("h2",{text:"ページを再読み込みしてください"}),
          el("p",{html:"読み込みが最新になっていないようです。ブラウザを<b>強制再読み込み（Windows：Ctrl+F5）</b>してから、もう一度開いてください。"})
        ]));
        return;
      }

      var incoming = codec.queryParam("d");
      var preload = incoming ? codec.dec(incoming) : null;

      var sec=el("section",{class:"card"});
      var make=panelMake();
      var solve=panelSolve(preload && preload.t ? preload : null);
      make.hidden=false; solve.hidden=true;
      var bar=CL.ui.tabBar(
        [{id:"make",label:"作って送る",n:"✎"},{id:"solve",label:"受け取って解く",n:"🔍"}],
        function(id){ make.hidden=(id!=="make"); solve.hidden=(id!=="solve"); });
      sec.appendChild(bar); sec.appendChild(make); sec.appendChild(solve);
      view.appendChild(sec);
      if(preload && preload.t){ bar.select("solve"); }

      view.appendChild(CL.ui.stageNav({id:"home",label:"ホーム"},{id:"stage1",label:"暗号の基本（Stage 1）"}));
    }
  });
})();
