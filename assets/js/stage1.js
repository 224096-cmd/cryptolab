/* =====================================================================
   Stage 1 — シーザー暗号（文字をずらす暗号）
   見る → 破る（総当たり）→ なぜ弱い（鍵空間）
   入力・途中経過はページを離れても保持（リセットで消える）
   ===================================================================== */
"use strict";
(function(){
  var el=CL.dom.el, clear=CL.dom.clear, term=CL.ui.term, details=CL.ui.details;
  var AZ="ABCDEFGHIJKLMNOPQRSTUVWXYZ";

  function shiftChar(ch,k){
    var c=ch.charCodeAt(0);
    if(c>=65&&c<=90)  return String.fromCharCode((c-65+k+26*4)%26+65);
    if(c>=97&&c<=122) return String.fromCharCode((c-97+k+26*4)%26+97);
    return ch;
  }
  function caesar(text,k){ var o=""; for(var i=0;i<text.length;i++) o+=shiftChar(text[i],k); return o; }

  var EN_FREQ={A:8.2,B:1.5,C:2.8,D:4.3,E:12.7,F:2.2,G:2.0,H:6.1,I:7.0,J:0.15,K:0.77,L:4.0,M:2.4,
    N:6.7,O:7.5,P:1.9,Q:0.095,R:6.0,S:6.3,T:9.1,U:2.8,V:0.98,W:2.4,X:0.15,Y:2.0,Z:0.074};
  function chiSquare(text){
    var counts={},total=0,i; for(i=0;i<26;i++) counts[AZ[i]]=0;
    var up=text.toUpperCase(); for(i=0;i<up.length;i++){ if(counts[up[i]]!==undefined){ counts[up[i]]++; total++; } }
    if(total===0) return 1e9;
    var chi=0; for(i=0;i<26;i++){ var L=AZ[i],ex=total*EN_FREQ[L]/100,df=counts[L]-ex; chi+=df*df/(ex||0.01); }
    return chi;
  }
  var DEFAULT_CIPHER = caesar("MEET ME AT THE OLD BRIDGE AT DAWN", 10);

  /* ========================= 見る ========================= */
  function panelSee(state, save){
    var wrap=el("div",{class:"panel"});
    wrap.appendChild(el("p",{html:
      "紀元前のローマで、軍司令官ユリウス・カエサル（英語読みでシーザー）が使ったと伝わる暗号です。"+
      "アルファベットを決まった数だけうしろへ「ずらす」だけ。ずらす数が<b>鍵（かぎ）</b>で、"+
      "カエサルは 3 ずらし（A→D, B→E…）を好んだとされます。"}));

    var inText=el("input",{type:"text",maxlength:"40",autocomplete:"off",spellcheck:"false",value:state.seeText!=null?state.seeText:"HELLO"});
    var slider=el("input",{type:"range",min:"0",max:"25",value:state.seeShift!=null?state.seeShift:3,style:"width:100%"});
    var kview=el("span",{class:"gloss"});
    var out=el("div",{class:"mono-box"});
    var ringHost=el("div",{class:"ring-wrap"});

    function draw(){
      var k=parseInt(slider.value,10); kview.textContent=k;
      out.textContent=caesar(inText.value,k)||"（ここに暗号文が出ます）";
      drawRing(ringHost,k,(inText.value.toUpperCase().replace(/[^A-Z]/g,"")[0])||"A");
      state.seeText=inText.value; state.seeShift=k; save();
    }
    inText.addEventListener("input",draw); slider.addEventListener("input",draw);

    wrap.appendChild(el("label",{class:"field",text:"もとの文（平文：ひらぶん）"}));
    wrap.appendChild(inText);
    wrap.appendChild(el("label",{class:"field"},["ずらす数（鍵）：",kview]));
    wrap.appendChild(slider);
    wrap.appendChild(ringHost);
    wrap.appendChild(el("label",{class:"field",text:"暗号文（あんごうぶん）"}));
    wrap.appendChild(out);

    wrap.appendChild(details("くわしい仕組み（タップで開く）", function(b){
      b.appendChild(el("p",{html:"各文字を、アルファベット表の上で <b>鍵の数だけ右へ移動</b>させます。表の端（Z）まで来たら、先頭（A）へ輪のように戻ります。"}));
      b.appendChild(el("h4",{text:"例：鍵 = 3 のとき"}));
      b.appendChild(el("div",{class:"example-box",html:
        "H → K　（H から 3つうしろ）<br>E → H<br>L → O<br>L → O<br>O → R<br>-------------------------<br>HELLO → KHOOR"}));
      b.appendChild(el("p",{html:"復号（元にもどす）は、同じ数だけ<b>左へ</b>戻すだけ。暗号化と復号で同じ鍵を使うので、"+
        term("共通鍵暗号","暗号化と復号に同じ鍵を使う方式。鍵を相手とどう安全に共有するかが課題になる")+"の仲間です。"}));
      b.appendChild(el("h4",{text:"ROT13 という身近な例"}));
      b.appendChild(el("p",{html:"鍵を 13 に固定したものは「ROT13」と呼ばれ、ネット掲示板などで"+
        "「答え」や「ネタバレ」を隠すのに今も使われます。13ずらしを2回かけると元に戻る（13+13=26）のが特徴です。"}));
      b.appendChild(el("p",{class:"tiny muted",text:"※ 数字・空白・記号はずらさずそのまま残します（英字だけが対象）。"}));
    }));
    draw();
    return wrap;
  }

  function drawRing(host,k,highlight){
    clear(host);
    var NS="http://www.w3.org/2000/svg";
    function s(t,a){ var n=document.createElementNS(NS,t); for(var x in a) n.setAttribute(x,a[x]); return n; }
    var size=260,c=size/2,Ro=112,Ri=84;
    var svg=s("svg",{viewBox:"0 0 "+size+" "+size,width:size,height:size,role:"img","aria-label":"シーザー暗号のダイヤル"});
    svg.appendChild(s("circle",{cx:c,cy:c,r:Ro+14,fill:"none",stroke:"#e7ecf5","stroke-width":1}));
    svg.appendChild(s("circle",{cx:c,cy:c,r:Ri-14,fill:"none",stroke:"#e7ecf5","stroke-width":1}));
    for(var i=0;i<26;i++){
      var a=-Math.PI/2+i*(2*Math.PI/26);
      var ox=c+Ro*Math.cos(a),oy=c+Ro*Math.sin(a);
      if(AZ[i]===highlight) svg.appendChild(s("circle",{cx:ox,cy:oy-4,r:11,fill:"#eef2fd",stroke:"#2b50c8"}));
      var to=s("text",{x:ox,y:oy+4,"text-anchor":"middle",class:"ring-letter plain"}); to.textContent=AZ[i];
      if(AZ[i]===highlight) to.setAttribute("font-size","14");
      svg.appendChild(to);
      var ix=c+Ri*Math.cos(a),iy=c+Ri*Math.sin(a);
      var ti=s("text",{x:ix,y:iy+4,"text-anchor":"middle",class:"ring-letter cipher"}); ti.textContent=AZ[(i+k)%26];
      if(AZ[i]===highlight) ti.setAttribute("font-size","14");
      svg.appendChild(ti);
    }
    svg.appendChild(s("polygon",{points:(c-5)+",6 "+(c+5)+",6 "+c+",16",fill:"#6d7686"}));
    host.appendChild(svg);
  }

  /* ========================= 破る ========================= */
  function panelBreak(state, save){
    var wrap=el("div",{class:"panel"});
    wrap.appendChild(el("p",{html:
      "シーザー暗号の鍵は <b>1〜25 の 25通り</b>しかありません（0は変化なし）。"+
      "だから「全部ためす」だけで必ず解けます。これを"+
      term("総当たり","考えられる鍵をかたっぱしから全部ためす解読法。英語でブルートフォース（brute force）")+"といいます。"}));
    wrap.appendChild(el("div",{class:"hintline",html:"<b>やってみよう：</b>下の暗号文のまま <b>「25通りを全部ためす」</b> を押して、意味の通る行をさがしてみましょう。"}));

    var inC=el("textarea",{class:"mono",spellcheck:"false"});
    inC.value = state.breakCipher!=null ? state.breakCipher : DEFAULT_CIPHER;
    inC.addEventListener("input",function(){ state.breakCipher=inC.value; save(); });

    wrap.appendChild(el("label",{class:"field",text:"暗号文（英語）。自由に書き換えてOK"}));
    wrap.appendChild(inC);
    var btn=el("button",{class:"btn",text:"25通りを全部ためす"});
    var resetBtn=el("button",{class:"btn quiet sm",text:"例題にもどす"});
    wrap.appendChild(el("div",{class:"btn-row"},[btn,resetBtn]));
    var result=el("div",{style:"margin-top:14px"}); wrap.appendChild(result);

    resetBtn.addEventListener("click",function(){ inC.value=DEFAULT_CIPHER; state.breakCipher=DEFAULT_CIPHER; save(); clear(result); });

    function run(){
      clear(result);
      var text=inC.value; if(!text.trim()){ CL.toast("暗号文を入れてください"); return; }
      var t0=performance.now(), rows=[], best=-1, bestChi=1e18;
      for(var k=1;k<=25;k++){ var dec=caesar(text,-k), chi=chiSquare(dec); rows.push({k:k,dec:dec,chi:chi}); if(chi<bestChi){ bestChi=chi; best=k; } }
      var ms=performance.now()-t0;
      result.appendChild(el("div",{class:"callout ok",html:
        "25通りすべて計算しました（所要 <b>"+ms.toFixed(2)+" ミリ秒</b>）。"+
        "自動採点では <b>鍵 "+best+"</b> が一番英語らしいと判定。下の表で意味の通る行をさがしてください。"}));
      var tbl=el("table",{class:"data"});
      tbl.appendChild(el("tr",{},[el("th",{text:"鍵"}),el("th",{text:"復号結果"}),el("th",{text:"英語らしさ"}),el("th",{text:""})]));
      rows.forEach(function(r){
        var pick=el("button",{class:"btn quiet sm",text:"これだ！",onclick:function(){
          CL.store.add("stage1","解読成功",{暗号文の長さ:text.length,選んだ鍵:r.k,復号結果:r.dec,自動判定鍵:best,所要ミリ秒:+ms.toFixed(3)});
          CL.toast("実験ノートに記録しました（鍵 "+r.k+"）");
        }});
        tbl.appendChild(el("tr", r.k===best?{class:"hit"}:{}, [
          el("td",{class:"mono",text:String(r.k)}), el("td",{class:"mono",text:r.dec}),
          el("td",{class:"mono",text:r.chi.toFixed(0)}), el("td",{},[pick])]));
      });
      result.appendChild(el("div",{class:"scrollx"},[tbl]));
      result.appendChild(el("p",{class:"tiny muted",html:
        "「英語らしさ」は数字が小さいほど英語らしい（各文字の出現割合が英語の標準にどれだけ近いかを"+
        term("カイ二乗","観測した度数と理論上の度数のズレを測る統計量。小さいほどよく一致している")+"で測った値）。"+
        "この自動判定も、コンピュータが統計で“あたり”をつける解読の一種です。"}));
    }
    btn.addEventListener("click",run);
    return wrap;
  }

  /* ========================= なぜ弱い ========================= */
  function panelWhy(){
    var wrap=el("div",{class:"panel"});
    wrap.appendChild(el("p",{html:"暗号の強さの第一歩は、鍵の種類の多さ＝"+
      term("鍵空間","ありえる鍵の総数。これが小さいと総当たりで破られる")+"の大きさです。"}));
    wrap.appendChild(el("div",{class:"stats"},[
      el("div",{class:"stat"},[el("div",{class:"k",text:"シーザー暗号の鍵の数"}),el("div",{class:"v red",text:"25 通り"})]),
      el("div",{class:"stat"},[el("div",{class:"k",text:"人が全部試す時間"}),el("div",{class:"v",html:"数分 <small>（紙と鉛筆でも）</small>"})]),
      el("div",{class:"stat"},[el("div",{class:"k",text:"次：換字式の鍵"}),el("div",{class:"v",html:"26! ≈ 4×10²⁶ <small>通り</small>"})])
    ]));
    wrap.appendChild(el("div",{class:"callout info",html:
      "<b>わかること：</b> 鍵がたった25通りなら、総当たりで一瞬で破れます。"+
      "「やり方を秘密にしているから安全」ではなく、<b>鍵の数</b>が安全性を決めるのです。"}));

    wrap.appendChild(details("もっと知る：ケルクホフスの原理", function(b){
      b.appendChild(el("p",{html:"19世紀の暗号学者ケルクホフスは「暗号は、<b>やり方（アルゴリズム）が敵に知られても</b>、"+
        "鍵さえ秘密なら安全であるべきだ」と唱えました。これを"+
        term("ケルクホフスの原理","暗号の安全性は方式の秘密ではなく鍵の秘密だけに依存すべき、という考え方")+"といいます。"}));
      b.appendChild(el("p",{html:"シーザー暗号は「ずらす」というやり方が知られると、鍵が25通りしかないので即破られます。"+
        "この教材でも、すべての暗号の“やり方”は公開したうえで「鍵を見つけられるか」を試しています。"}));
      b.appendChild(el("p",{html:"<b>次のステージへ：</b> では鍵を爆発的に増やせば安全でしょうか？ 換字式暗号は鍵が 4×10²⁶ 通りにもなりますが、"+
        "それでも<b>別の弱点</b>で破れてしまいます。"}));
    }));
    wrap.appendChild(el("p",{class:"tiny muted",html:
      "ことばの整理：<b>平文</b>＝もとの文、<b>暗号文</b>＝暗号化した文、<b>鍵</b>＝暗号化／復号のときの秘密の数や対応表。"}));
    return wrap;
  }

  CL.route("stage1",{
    title:"Stage 1 シーザー暗号",
    render:function(view){
      var ps=CL.pstate("stage1"); var state=ps.get()||{};
      function save(){ ps.set(state); }

      view.appendChild(el("p",{class:"eyebrow",text:"STAGE 1 ／ 古典暗号"}));
      view.appendChild(el("h1",{class:"page-title",text:"シーザー暗号を破る"}));
      view.appendChild(el("p",{class:"page-lead",html:"文字をずらすだけの最も古い暗号。<b>総当たり</b>で一瞬で解けることを体験します。"}));
      view.appendChild(CL.ui.resetBar("このページをリセット",function(){ ps.clear(); CL.router.reload(); }));

      var sec=el("section",{class:"card"});
      var see=panelSee(state,save), brk=panelBreak(state,save), why=panelWhy();
      brk.hidden=true; why.hidden=true;
      var bar=CL.ui.tabBar(
        [{id:"see",label:"見る",n:"①"},{id:"break",label:"破る",n:"②"},{id:"why",label:"なぜ弱い？",n:"③"}],
        function(id){ see.hidden=(id!=="see"); brk.hidden=(id!=="break"); why.hidden=(id!=="why"); state.tab=id; save(); });
      sec.appendChild(bar); sec.appendChild(see); sec.appendChild(brk); sec.appendChild(why);
      view.appendChild(sec);
      if(state.tab) bar.select(state.tab);

      view.appendChild(CL.ui.stageNav({id:"home",label:"ホーム"},{id:"stage2",label:"Stage 2 換字式暗号"}));
    }
  });
})();
