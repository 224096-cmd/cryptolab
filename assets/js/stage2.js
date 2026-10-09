/* =====================================================================
   Stage 2 — 換字式（かえじしき）暗号と頻度分析
   見る → 破る（頻度分析＋対話的マッピング）→ なぜ破れる
   同じ問題・途中の推理はページを離れても保持（リセットで新しい問題）
   ===================================================================== */
"use strict";
(function(){
  var el=CL.dom.el, clear=CL.dom.clear, term=CL.ui.term, details=CL.ui.details;
  var AZ="ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  var EN_ORDER="ETAOINSHRDLCUMWFGYPBVKJXQZ";

  var PLAIN=
    "A SECRET MESSAGE IS ONLY AS STRONG AS ITS KEY. "+
    "IF THE KEY CAN BE GUESSED OR SEARCHED QUICKLY, THE MESSAGE WILL NOT STAY SECRET FOR LONG. "+
    "GOOD SECURITY DOES NOT HIDE THE METHOD. IT MAKES THE KEY SO HARD TO FIND THAT NO ONE HAS ENOUGH TIME TO TRY.";

  function randomKey(){
    var a=AZ.split("");
    for(var i=a.length-1;i>0;i--){ var j=Math.floor(Math.random()*(i+1)); var t=a[i]; a[i]=a[j]; a[j]=t; }
    var map={}; for(var k=0;k<26;k++){ map[AZ[k]]=a[k]; } return map;
  }
  function applyMap(text,map){ var o=""; for(var i=0;i<text.length;i++){ var c=text[i].toUpperCase(); o+=map[c]!==undefined?map[c]:text[i]; } return o; }
  function freq(text){ var f={},i; for(i=0;i<26;i++) f[AZ[i]]=0; var up=text.toUpperCase(); for(i=0;i<up.length;i++){ if(f[up[i]]!==undefined) f[up[i]]++; } return f; }

  /* ========================= 見る ========================= */
  function panelSee(state, save){
    var wrap=el("div",{class:"panel"});
    wrap.appendChild(el("p",{html:
      "各文字を、重ならないように別の文字へ置きかえます（A→Q, B→M…）。この対応表そのものが<b>鍵</b>です。"+
      "並べ方は "+term("26!","26×25×24×…×1。26個のものを一列に並べる並べ方の総数（階乗）")+" ＝ 約 4×10²⁶ 通りもあります。"}));

    var key = state.see_key ? state.see_key : randomKey();
    state.see_key=key;
    var tbl=el("table",{class:"data"});
    var r1=el("tr",{},[el("th",{text:"平文"})]), r2=el("tr",{},[el("th",{text:"暗号"})]);
    for(var i=0;i<26;i++){ r1.appendChild(el("td",{class:"mono",text:AZ[i]})); r2.appendChild(el("td",{class:"mono",text:key[AZ[i]],style:"color:#c9372c;font-weight:700"})); }
    tbl.appendChild(r1); tbl.appendChild(r2);
    wrap.appendChild(el("div",{class:"scrollx"},[tbl]));

    var inT=el("input",{type:"text",maxlength:"40",spellcheck:"false",autocomplete:"off",value:state.see_text!=null?state.see_text:"ATTACK AT DAWN"});
    var out=el("div",{class:"mono-box"});
    var reroll=el("button",{class:"btn quiet sm",text:"別の鍵（対応表）にする"});
    function draw(){ out.textContent=applyMap(inT.value,key)||"（暗号文）"; state.see_text=inT.value; save(); }
    inT.addEventListener("input",draw);
    reroll.addEventListener("click",function(){ key=randomKey(); state.see_key=key; for(var i=0;i<26;i++){ r2.children[i+1].textContent=key[AZ[i]]; } draw(); });
    wrap.appendChild(el("label",{class:"field",text:"平文"}));
    wrap.appendChild(inT);
    wrap.appendChild(el("div",{class:"btn-row"},[reroll]));
    wrap.appendChild(el("label",{class:"field",text:"暗号文"}));
    wrap.appendChild(out);

    wrap.appendChild(details("くわしい仕組みと「26!」の大きさ", function(b){
      b.appendChild(el("p",{html:"シーザー暗号は「表を丸ごとずらす」ので鍵は25通りでした。換字式は<b>1文字ごとに自由に</b>行き先を決められるので、"+
        "鍵は「アルファベットの並べ替え方」すべて＝26! 通りになります。"}));
      b.appendChild(el("div",{class:"example-box",html:
        "26! = 403,291,461,126,605,635,584,000,000<br>　 ≒ 4×10²⁶ 通り"}));
      b.appendChild(el("p",{html:"どれくらい大きいか——1秒間に1兆（10¹²）個の鍵を試せる超高速コンピュータでも、"+
        "全部試し終えるには <b>約1200万年</b>かかります。総当たりは事実上不可能です。"}));
      b.appendChild(el("h4",{text:"でも、ここに弱点がある"}));
      b.appendChild(el("p",{html:"この方式は「同じ文字はいつも同じ文字に化ける」（"+
        term("単一換字","1つの平文文字がつねに同じ暗号文字に対応する方式。だから頻度のかたよりが保たれる")+
        "）。つまり<b>文字の出現回数のかたよりが、そっくり暗号文に残ってしまう</b>のです。次の「破る」で、ここを突きます。"}));
    }));
    draw();
    return wrap;
  }

  /* ========================= 破る ========================= */
  function panelBreak(state, save){
    var wrap=el("div",{class:"panel"});
    var answerKey = state.break_key ? state.break_key : randomKey();
    state.break_key=answerKey; save();
    var cipher=applyMap(PLAIN,answerKey);
    var answerInv={}; for(var p in answerKey){ answerInv[answerKey[p]]=p; }
    var guess = state.break_guess ? state.break_guess : {};
    state.break_guess=guess;

    wrap.appendChild(el("p",{html:
      "下の長い暗号文には英語の文章がかくれています。鍵は 4×10²⁶ 通り——でも "+
      term("頻度分析","文字の出現回数のかたよりを手がかりに置きかえを推理する解読法")+
      " で解けます。英語で一番多い文字は <b>E</b>、次に <b>T, A, O…</b>。暗号文で一番多い文字は、たぶん E です。"}));

    wrap.appendChild(el("label",{class:"field",text:"暗号文"}));
    wrap.appendChild(el("div",{class:"mono-box",text:cipher}));

    wrap.appendChild(el("h3",{text:"暗号文の文字ひん度（多い順）"}));
    var f=freq(cipher),maxf=1;
    var order=AZ.split("").sort(function(a,b){ return f[b]-f[a]; });
    order.forEach(function(L){ if(f[L]>maxf) maxf=f[L]; });
    var fg=el("div",{class:"freq"});
    order.forEach(function(L){ if(f[L]===0) return;
      fg.appendChild(el("span",{class:"lab",text:L}));
      fg.appendChild(el("span",{class:"bar",style:"width:"+(f[L]/maxf*100)+"%"}));
      fg.appendChild(el("span",{class:"val",text:f[L]})); });
    wrap.appendChild(fg);
    wrap.appendChild(el("p",{class:"tiny muted",html:"参考：英語で多い順は "+EN_ORDER.split("").join(" ")}));

    wrap.appendChild(el("h3",{text:"置きかえを推理する"}));
    var hintBtn=el("button",{class:"btn ghost sm",text:"頻度順にまず仮あて"});
    var clearBtn=el("button",{class:"btn quiet sm",text:"ぜんぶ消す"});
    var newBtn=el("button",{class:"btn quiet sm",text:"別の問題にする"});
    var checkBtn=el("button",{class:"btn sm",text:"答え合わせ＆記録"});
    wrap.appendChild(el("div",{class:"btn-row"},[hintBtn,clearBtn,newBtn,checkBtn]));

    var grid=el("div",{class:"mapgrid"});
    var inputs={};
    order.forEach(function(L){ if(f[L]===0) return;
      var inp=el("input",{type:"text",maxlength:"1",value:guess[L]||""});
      inputs[L]=inp;
      inp.addEventListener("input",function(){
        var v=inp.value.toUpperCase().replace(/[^A-Z]/g,""); inp.value=v;
        if(v) guess[L]=v; else delete guess[L];
        state.break_guess=guess; save(); refresh();
      });
      grid.appendChild(el("div",{class:"mapcell"},[el("div",{class:"from",text:L}),el("div",{class:"arr",text:"↓"}),inp]));
    });
    wrap.appendChild(grid);

    var decoded=el("div",{class:"decoded mono-box"});
    wrap.appendChild(el("h3",{text:"今の復号結果"})); wrap.appendChild(decoded);
    var status=el("div",{style:"margin-top:10px"}); wrap.appendChild(status);

    function refresh(){
      var used={},dup={};
      for(var c in guess){ var p=guess[c]; if(used[p]) dup[p]=true; used[p]=1; }
      for(var L in inputs){ var v=inputs[L].value.toUpperCase();
        inputs[L].style.borderColor=(v&&dup[v])?"#c9372c":""; inputs[L].style.background=(v&&dup[v])?"#fdeeec":""; }
      clear(decoded);
      for(var i=0;i<cipher.length;i++){ var ch=cipher[i];
        if(ch>="A"&&ch<="Z"){ if(guess[ch]) decoded.appendChild(el("span",{class:"known",text:guess[ch]})); else decoded.appendChild(el("span",{class:"unknown",text:"·"})); }
        else decoded.appendChild(document.createTextNode(ch)); }
    }
    hintBtn.addEventListener("click",function(){
      var oc=AZ.split("").filter(function(L){return f[L]>0;}).sort(function(a,b){return f[b]-f[a];});
      for(var L in guess) delete guess[L];
      oc.forEach(function(L,idx){ var p=EN_ORDER[idx]||""; if(p){ guess[L]=p; if(inputs[L]) inputs[L].value=p; } });
      state.break_guess=guess; save(); refresh();
      CL.toast("頻度順に仮あてしました。ここから手で直していきます");
    });
    clearBtn.addEventListener("click",function(){ for(var L in guess) delete guess[L]; for(var k in inputs) inputs[k].value=""; state.break_guess=guess; save(); refresh(); });
    newBtn.addEventListener("click",function(){ delete state.break_key; delete state.break_guess; save(); CL.router.reload(); });
    checkBtn.addEventListener("click",function(){
      var correct=0,total=0,mapped=0;
      for(var L in inputs){ if(inputs[L].value) mapped++; }
      for(var c in answerInv){ if(f[c]>0){ total++; if(guess[c]===answerInv[c]) correct++; } }
      var solved=(correct===total);
      clear(status);
      status.appendChild(el("div",{class:"callout "+(solved?"ok":"info"),html:
        solved ? "<b>正解！</b> すべての置きかえを当てました。総当たりではなく、統計の力で破れました。"
               : "正しく当てた文字：<b>"+correct+" / "+total+"</b>。もう少しです——意味の通る単語を手がかりに直してみましょう。"}));
      CL.store.add("stage2","頻度分析",{暗号文の長さ:cipher.length,当たった文字数:correct,出現文字種:total,記入済み:mapped,解読成功:solved?"はい":"いいえ"});
      CL.toast(solved?"実験ノートに記録（解読成功）":"実験ノートに記録（途中経過）");
    });

    wrap.appendChild(details("解読のコツ（頻度分析のテクニック）", function(b){
      b.appendChild(el("p",{html:"頻度分析は、9世紀のアラブの学者"+
        term("アル・キンディー","9世紀バグダードの学者。文字の出現頻度を使う暗号解読法を世界で初めて書き残したとされる")+
        "が初めて体系化したと言われます。千年以上前から換字式暗号は“破れる暗号”でした。"}));
      b.appendChild(el("h4",{text:"手がかりの例"}));
      b.appendChild(el("p",{html:
        "・一番多い文字 → ほぼ <b>E</b>。次に多いのは <b>T, A, O</b> あたり。<br>"+
        "・1文字だけの単語 → 英語なら <b>A</b> か <b>I</b>。<br>"+
        "・3文字で一番よく出る単語 → <b>THE</b> の可能性大。<br>"+
        "・同じ文字が2つ連続（LL, SS, EE など）→ よくあるペアから推測。<br>"+
        "・いくつか当てて単語の形が見えてきたら、残りは“穴うめ”で一気に進みます。"}));
      b.appendChild(el("p",{class:"tiny muted",text:"※ 短い文章ほど頻度のかたよりが安定せず、解読は難しくなります。"}));
    }));
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
      "換字式では「文字の出現回数のかたより」が平文の情報を漏らしてしまいました。"}));
    wrap.appendChild(details("もっと知る：よい暗号の条件と、その後の歴史", function(b){
      b.appendChild(el("p",{html:"この弱点を補うため、歴史上はいろいろな工夫が生まれました。たとえば"+
        term("多表式暗号","複数の換字表を切り替えて使う方式。同じ文字が別の文字に化けるので頻度が平らに近づく。ヴィジュネル暗号など")+
        "は、場所によって換字表を切り替えることで頻度のかたよりを隠そうとしました。"}));
      b.appendChild(el("p",{html:"現代の暗号・ハッシュが目指すのは、<b>出力に統計的なかたよりを一切残さない</b>こと。"+
        "入力を少し変えただけで出力が完全にランダムに見えるように設計されています。"}));
      b.appendChild(el("p",{html:"<b>次のステージへ：</b> その“かたよりを残さない”性質の代表が、ハッシュ関数の"+
        term("雪崩効果","入力の小さな違いが出力全体に大きく広がる性質")+"です。Stage 3 で実際に目で見てみましょう。"}));
    }));
    return wrap;
  }

  CL.route("stage2",{
    title:"Stage 2 換字式暗号",
    render:function(view){
      var ps=CL.pstate("stage2"); var state=ps.get()||{};
      function save(){ ps.set(state); }
      view.appendChild(el("p",{class:"eyebrow",text:"STAGE 2 ／ 古典暗号"}));
      view.appendChild(el("h1",{class:"page-title",text:"換字式暗号を頻度分析で破る"}));
      view.appendChild(el("p",{class:"page-lead",html:"鍵は約 <b>4×10²⁶ 通り</b>。総当たりは不可能でも、文字のかたよりから解けます。"}));
      view.appendChild(CL.ui.resetBar("このページをリセット（新しい問題）",function(){ ps.clear(); CL.router.reload(); }));

      var sec=el("section",{class:"card"});
      var see=panelSee(state,save), brk=panelBreak(state,save), why=panelWhy();
      brk.hidden=true; why.hidden=true;
      var bar=CL.ui.tabBar(
        [{id:"see",label:"見る",n:"①"},{id:"break",label:"破る",n:"②"},{id:"why",label:"なぜ破れる？",n:"③"}],
        function(id){ see.hidden=(id!=="see"); brk.hidden=(id!=="break"); why.hidden=(id!=="why"); state.tab=id; save(); });
      sec.appendChild(bar); sec.appendChild(see); sec.appendChild(brk); sec.appendChild(why);
      view.appendChild(sec);
      if(state.tab) bar.select(state.tab);
      view.appendChild(CL.ui.stageNav({id:"stage1",label:"Stage 1"},{id:"stage3",label:"Stage 3 ハッシュ"}));
    }
  });
})();
