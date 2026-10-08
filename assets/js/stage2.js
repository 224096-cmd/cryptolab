/* =====================================================================
   Stage 2 — 換字式（かえじしき）暗号と頻度分析
   見る（鍵は26!通り）→ 破る（頻度分析＋対話的マッピング）→ なぜ破れる
   ===================================================================== */
"use strict";
(function(){
  var el = CL.dom.el, clear = CL.dom.clear, term = CL.ui.term;
  var AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  var EN_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"; // 英語で多い順

  // 解読用の例題（英語・自作。頻度分析が効くよう少し長め）
  var PLAIN =
    "A SECRET MESSAGE IS ONLY AS STRONG AS ITS KEY. "+
    "IF THE KEY CAN BE GUESSED OR SEARCHED QUICKLY, THE MESSAGE WILL NOT STAY SECRET FOR LONG. "+
    "GOOD SECURITY DOES NOT HIDE THE METHOD. IT MAKES THE KEY SO HARD TO FIND THAT NO ONE HAS ENOUGH TIME TO TRY.";

  function randomKey(){
    var a = AZ.split("");
    for(var i=a.length-1;i>0;i--){ var j=Math.floor(Math.random()*(i+1)); var t=a[i]; a[i]=a[j]; a[j]=t; }
    var map={}; for(var k=0;k<26;k++){ map[AZ[k]]=a[k]; } return map; // 平文→暗号
  }
  function applyMap(text, map){
    var out=""; for(var i=0;i<text.length;i++){ var c=text[i].toUpperCase(); out += map[c]!==undefined?map[c]:text[i]; } return out;
  }
  function freq(text){
    var f={}, i; for(i=0;i<26;i++) f[AZ[i]]=0;
    var up=text.toUpperCase(); for(i=0;i<up.length;i++){ if(f[up[i]]!==undefined) f[up[i]]++; }
    return f;
  }

  /* ========================= 見る ========================= */
  function panelSee(){
    var wrap=el("div",{class:"panel"});
    wrap.appendChild(el("p",{html:
      "各文字を、重ならないように別の文字へ置きかえます（A→Q, B→M…）。"+
      "この対応表そのものが<b>鍵</b>。並べ方は "+term("26!","26×25×24×…×1。26個のものを一列に並べる並べ方の総数（階乗）")+
      " ＝ 約 4×10²⁶ 通りもあります。"}));

    var key = randomKey();
    var tbl = el("table",{class:"data"});
    var r1=el("tr",{},[el("th",{text:"平文"})]), r2=el("tr",{},[el("th",{text:"暗号"})]);
    for(var i=0;i<26;i++){ r1.appendChild(el("td",{class:"mono",text:AZ[i]})); r2.appendChild(el("td",{class:"mono",text:key[AZ[i]],style:"color:#c9372c;font-weight:700"})); }
    tbl.appendChild(r1); tbl.appendChild(r2);
    wrap.appendChild(el("div",{class:"scrollx"},[tbl]));

    var inT=el("input",{type:"text",value:"ATTACK AT DAWN",maxlength:"40",spellcheck:"false",autocomplete:"off"});
    var out=el("div",{class:"mono-box"});
    var reroll=el("button",{class:"btn quiet sm",text:"別の鍵（対応表）にする"});
    function draw(){ out.textContent = applyMap(inT.value,key) || "（暗号文）"; }
    inT.addEventListener("input",draw);
    reroll.addEventListener("click",function(){ key=randomKey();
      for(var i=0;i<26;i++){ r2.children[i+1].textContent=key[AZ[i]]; } draw(); });
    wrap.appendChild(el("label",{class:"field",text:"平文"}));
    wrap.appendChild(inT);
    wrap.appendChild(el("div",{class:"btn-row"},[reroll]));
    wrap.appendChild(el("label",{class:"field",text:"暗号文"}));
    wrap.appendChild(out);
    wrap.appendChild(el("div",{class:"callout info",html:
      "鍵が 4×10²⁶ 通り——1秒で1兆個ためしても、全部試すには"+
      "宇宙の年齢よりずっと長い時間がかかります。総当たりでは <b>絶対に無理</b>に見えます。"+
      "<br>でも、次の「破る」で<b>総当たりを使わずに</b>解けてしまいます。"}));
    draw();
    return wrap;
  }

  /* ========================= 破る ========================= */
  function panelBreak(){
    var wrap=el("div",{class:"panel"});
    var answerKey = randomKey();                 // 出題の真の鍵（平文→暗号）
    var cipher = applyMap(PLAIN, answerKey);     // 出題の暗号文
    // 逆引き（暗号→平文）＝答え
    var answerInv={}; for(var p in answerKey){ answerInv[answerKey[p]]=p; }
    var guess={};                                // 生徒の推測（暗号→平文）

    wrap.appendChild(el("p",{html:
      "下の長い暗号文には、英語の文章がかくれています。鍵は 4×10²⁶ 通り——でも "+
      term("頻度分析","文字の出現回数のかたよりを手がかりに置きかえを推理する解読法")+
      " で解けます。英語で一番多い文字は <b>E</b>、次に <b>T, A, O…</b>。"+
      "暗号文で一番多い文字は、たぶん E です。"}));

    wrap.appendChild(el("label",{class:"field",text:"暗号文"}));
    wrap.appendChild(el("div",{class:"mono-box",text:cipher}));

    // 頻度バー（暗号文）
    wrap.appendChild(el("h3",{text:"暗号文の文字ひん度（多い順）"}));
    var f=freq(cipher), maxf=1;
    var order = AZ.split("").sort(function(a,b){ return f[b]-f[a]; });
    order.forEach(function(L){ if(f[L]>maxf) maxf=f[L]; });
    var fg=el("div",{class:"freq"});
    order.forEach(function(L){ if(f[L]===0) return;
      fg.appendChild(el("span",{class:"lab",text:L}));
      fg.appendChild(el("span",{class:"bar",style:"width:"+(f[L]/maxf*100)+"%"}));
      fg.appendChild(el("span",{class:"val",text:f[L]}));
    });
    wrap.appendChild(fg);
    wrap.appendChild(el("p",{class:"tiny muted",html:"参考：英語で多い順は "+EN_ORDER.split("").join(" ")}));

    // 対話的マッピング
    wrap.appendChild(el("h3",{text:"置きかえを推理する"}));
    var hintBtn=el("button",{class:"btn ghost sm",text:"頻度順にまず仮あて"});
    var clearBtn=el("button",{class:"btn quiet sm",text:"ぜんぶ消す"});
    var checkBtn=el("button",{class:"btn sm",text:"答え合わせ＆記録"});
    wrap.appendChild(el("div",{class:"btn-row"},[hintBtn,clearBtn,checkBtn]));

    var grid=el("div",{class:"mapgrid"});
    var inputs={};
    // 暗号文に出てくる文字を頻度順に並べて入力欄を作る
    order.forEach(function(L){ if(f[L]===0) return;
      var inp=el("input",{type:"text",maxlength:"1",value:""});
      inputs[L]=inp;
      inp.addEventListener("input",function(){
        var v=inp.value.toUpperCase().replace(/[^A-Z]/g,""); inp.value=v;
        if(v) guess[L]=v; else delete guess[L];
        refresh();
      });
      grid.appendChild(el("div",{class:"mapcell"},[
        el("div",{class:"from",text:L}), el("div",{class:"arr",text:"↓"}), inp
      ]));
    });
    wrap.appendChild(grid);

    var decoded=el("div",{class:"decoded mono-box"});
    wrap.appendChild(el("h3",{text:"今の復号結果"}));
    wrap.appendChild(decoded);
    var status=el("div",{style:"margin-top:10px"});
    wrap.appendChild(status);

    function refresh(){
      // 重複（同じ平文に2つ割り当て）を検出
      var used={}, dup={};
      for(var c in guess){ var p=guess[c]; if(used[p]) { dup[p]=true; } used[p]=(used[p]||0)+1; }
      for(var L in inputs){
        var v=inputs[L].value.toUpperCase();
        inputs[L].style.borderColor = (v && dup[v]) ? "#c9372c" : "";
        inputs[L].style.background   = (v && dup[v]) ? "#fdeeec" : "";
      }
      // 復号結果を描画
      clear(decoded);
      for(var i=0;i<cipher.length;i++){
        var ch=cipher[i];
        if(ch>="A"&&ch<="Z"){
          if(guess[ch]) decoded.appendChild(el("span",{class:"known",text:guess[ch]}));
          else decoded.appendChild(el("span",{class:"unknown",text:"·"}));
        } else decoded.appendChild(document.createTextNode(ch));
      }
    }

    hintBtn.addEventListener("click",function(){
      // 暗号文の頻度順 → 英語の頻度順 に仮あて
      var oc = AZ.split("").filter(function(L){return f[L]>0;}).sort(function(a,b){return f[b]-f[a];});
      guess={};
      oc.forEach(function(L,idx){ var p=EN_ORDER[idx]||""; if(p){ guess[L]=p; if(inputs[L]) inputs[L].value=p; } });
      refresh();
      CL.toast("頻度順に仮あてしました。ここから手で直していきます");
    });
    clearBtn.addEventListener("click",function(){ guess={}; for(var L in inputs) inputs[L].value=""; refresh(); });

    checkBtn.addEventListener("click",function(){
      // 正解と比較（文字のみ）
      var correct=0, totalLetters=0, mapped=0;
      for(var L in inputs){ if(inputs[L].value) mapped++; }
      for(var c in answerInv){ if(f[c]>0){ totalLetters++; if(guess[c]===answerInv[c]) correct++; } }
      var solved = (correct===totalLetters);
      clear(status);
      status.appendChild(el("div",{class:"callout "+(solved?"ok":"info"),html:
        (solved ? "<b>正解！</b> すべての置きかえを当てました。総当たりではなく、統計の力で破れました。"
                : "正しく当てた文字：<b>"+correct+" / "+totalLetters+"</b>。もう少しです——意味の通る単語を手がかりに直してみましょう。")
      }));
      CL.store.add("stage2","頻度分析",{
        暗号文の長さ:cipher.length, 当たった文字数:correct, 出現文字種:totalLetters,
        記入済み:mapped, 解読成功:solved?"はい":"いいえ"
      });
      if(solved) CL.toast("実験ノートに記録（解読成功）");
      else CL.toast("実験ノートに記録（途中経過）");
    });

    refresh();
    return wrap;
  }

  /* ========================= なぜ破れる ========================= */
  function panelWhy(){
    var wrap=el("div",{class:"panel"});
    wrap.appendChild(el("div",{class:"stats"},[
      el("div",{class:"stat"},[el("div",{class:"k",text:"鍵の数（総当たりの壁）"}),el("div",{class:"v",html:"4×10²⁶ <small>通り</small>"})]),
      el("div",{class:"stat"},[el("div",{class:"k",text:"頻度分析で必要な作業"}),el("div",{class:"v red",html:"数十分 <small>（人の手でも）</small>"})])
    ]));
    wrap.appendChild(el("div",{class:"callout info",html:
      "<b>大事な教訓：</b> 鍵がどれだけ多くても、暗号文に<b>かたより（規則性）</b>が残ると破られます。"+
      "換字式では「文字の出現回数のかたより」が平文の情報を漏らしてしまいました。"+
      "<br>よい暗号は、鍵の数が多いだけでなく、<b>出力にかたよりを残さない</b>ことが必要です。"}));
    wrap.appendChild(el("p",{html:
      "次の Stage 3 では、入力が1文字変わるだけで出力ががらっと変わる"+
      term("ハッシュ関数","データから固定長の“指紋”を作る一方向の計算。SHA-256など")+
      "を扱います。かたよりを残さない仕組み（雪崩効果）と、それでも弱いパスワードは破られることを見ます。"}));
    return wrap;
  }

  CL.route("stage2", {
    title:"Stage 2 換字式暗号",
    render:function(view){
      view.appendChild(el("p",{class:"eyebrow",text:"STAGE 2 ／ 古典暗号"}));
      view.appendChild(el("h1",{class:"page-title",text:"換字式暗号を頻度分析で破る"}));
      view.appendChild(el("p",{class:"page-lead",html:"鍵は約 <b>4×10²⁶ 通り</b>。総当たりは不可能でも、文字のかたよりから解けます。"}));
      var sec=el("section",{class:"card"});
      var see=panelSee(), brk=panelBreak(), why=panelWhy(); brk.hidden=true; why.hidden=true;
      var bar=CL.ui.tabBar(
        [{id:"see",label:"見る",n:"①"},{id:"break",label:"破る",n:"②"},{id:"why",label:"なぜ破れる？",n:"③"}],
        function(id){ see.hidden=(id!=="see"); brk.hidden=(id!=="break"); why.hidden=(id!=="why"); });
      sec.appendChild(bar); sec.appendChild(see); sec.appendChild(brk); sec.appendChild(why);
      view.appendChild(sec);
      view.appendChild(CL.ui.stageNav({id:"stage1",label:"Stage 1"},{id:"stage3",label:"Stage 3 ハッシュ"}));
    }
  });
})();
