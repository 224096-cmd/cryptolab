/* =====================================================================
   Stage 1 — シーザー暗号（文字をずらす暗号）
   見る → 破る（総当たり）→ なぜ弱い（鍵空間）
   ===================================================================== */
"use strict";
(function(){
  var el = CL.dom.el, clear = CL.dom.clear, term = CL.ui.term;
  var AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

  /* --- 暗号そのもの --- */
  function shiftChar(ch, k){
    var c = ch.charCodeAt(0);
    if(c>=65 && c<=90)  return String.fromCharCode((c-65+k+26*4)%26+65); // A-Z
    if(c>=97 && c<=122) return String.fromCharCode((c-97+k+26*4)%26+97); // a-z
    return ch; // 英字以外はそのまま
  }
  function caesar(text, k){
    var out=""; for(var i=0;i<text.length;i++) out += shiftChar(text[i], k); return out;
  }

  /* --- 英語らしさの採点（カイ二乗が小さいほど英語らしい） --- */
  var EN_FREQ = {A:8.2,B:1.5,C:2.8,D:4.3,E:12.7,F:2.2,G:2.0,H:6.1,I:7.0,J:0.15,K:0.77,
    L:4.0,M:2.4,N:6.7,O:7.5,P:1.9,Q:0.095,R:6.0,S:6.3,T:9.1,U:2.8,V:0.98,W:2.4,X:0.15,Y:2.0,Z:0.074};
  function chiSquare(text){
    var counts={}, total=0, i;
    for(i=0;i<AZ.length;i++) counts[AZ[i]]=0;
    var up = text.toUpperCase();
    for(i=0;i<up.length;i++){ if(counts[up[i]]!==undefined){ counts[up[i]]++; total++; } }
    if(total===0) return 1e9;
    var chi=0;
    for(i=0;i<AZ.length;i++){
      var L=AZ[i], expected=total*EN_FREQ[L]/100;
      var diff=counts[L]-expected;
      chi += diff*diff/(expected||0.01);
    }
    return chi;
  }

  /* ========================= 見る ========================= */
  function panelSee(){
    var wrap = el("div",{class:"panel",role:"tabpanel"});
    wrap.appendChild(el("p",{html:
      "アルファベットを決まった数だけ「ずらす」暗号です。ずらす数が"+
      "<b>鍵（かぎ）</b>。たとえば鍵=3 なら A→D, B→E… となります。"}));

    var inText = el("input",{type:"text",value:"HELLO",maxlength:"40",autocomplete:"off",spellcheck:"false"});
    var slider = el("input",{type:"range",min:"0",max:"25",value:"3",style:"width:100%"});
    var kview  = el("span",{class:"gloss",text:"3"});
    var out    = el("div",{class:"mono-box"});
    var ringHost = el("div",{class:"ring-wrap"});

    function draw(){
      var k = parseInt(slider.value,10); kview.textContent=k;
      out.textContent = caesar(inText.value, k) || "（ここに暗号文が出ます）";
      drawRing(ringHost, k, (inText.value.toUpperCase().replace(/[^A-Z]/g,"")[0])||"A");
    }
    inText.addEventListener("input",draw);
    slider.addEventListener("input",draw);

    wrap.appendChild(el("label",{class:"field",text:"もとの文（平文：ひらぶん）"}));
    wrap.appendChild(inText);
    wrap.appendChild(el("label",{class:"field"},["ずらす数（鍵）：",kview]));
    wrap.appendChild(slider);
    wrap.appendChild(ringHost);
    wrap.appendChild(el("label",{class:"field",text:"暗号文（あんごうぶん）"}));
    wrap.appendChild(out);
    wrap.appendChild(el("p",{class:"tiny muted",html:
      "外側の青い輪が平文の文字、内側の赤い輪がずらした先の暗号文の文字。"+
      "輪を回すイメージで、文字が対応づけ（置きかえ）られます。英字以外（空白・数字）はそのまま残ります。"}));
    draw();
    return wrap;
  }

  // シーザーの「ダイヤル」をSVGで描く
  function drawRing(host, k, highlight){
    clear(host);
    var SVGNS="http://www.w3.org/2000/svg";
    function s(t,a){ var n=document.createElementNS(SVGNS,t); for(var x in a) n.setAttribute(x,a[x]); return n; }
    var size=260, c=size/2, Ro=112, Ri=84;
    var svg=s("svg",{viewBox:"0 0 "+size+" "+size,width:size,height:size,role:"img","aria-label":"シーザー暗号のダイヤル"});
    svg.appendChild(s("circle",{cx:c,cy:c,r:Ro+14,fill:"none",stroke:"#e7ecf5","stroke-width":1}));
    svg.appendChild(s("circle",{cx:c,cy:c,r:Ri-14,fill:"none",stroke:"#e7ecf5","stroke-width":1}));
    for(var i=0;i<26;i++){
      var aOuter = -Math.PI/2 + i*(2*Math.PI/26);
      var ox=c+Ro*Math.cos(aOuter), oy=c+Ro*Math.sin(aOuter);
      var to=s("text",{x:ox,y:oy+4,"text-anchor":"middle",class:"ring-letter plain"}); to.textContent=AZ[i];
      if(AZ[i]===highlight){ to.setAttribute("font-size","14"); svg.appendChild(s("circle",{cx:ox,cy:oy-4,r:11,fill:"#eef2fd",stroke:"#2b50c8"})); }
      svg.appendChild(to);
      // 内側：平文iの位置に、暗号文(i+k)を置く
      var ix=c+Ri*Math.cos(aOuter), iy=c+Ri*Math.sin(aOuter);
      var ti=s("text",{x:ix,y:iy+4,"text-anchor":"middle",class:"ring-letter cipher"}); ti.textContent=AZ[(i+k)%26];
      if(AZ[i]===highlight){ ti.setAttribute("font-size","14"); }
      svg.appendChild(ti);
    }
    // 12時の目印
    svg.appendChild(s("polygon",{points:(c-5)+",6 "+(c+5)+",6 "+c+",16",fill:"#6d7686"}));
    host.appendChild(svg);
  }

  /* ========================= 破る ========================= */
  function panelBreak(){
    var wrap = el("div",{class:"panel",role:"tabpanel"});
    wrap.appendChild(el("p",{html:
      "シーザー暗号の鍵は <b>0〜25 の 25通り</b>（0は変化なし）しかありません。"+
      "だから「全部ためす」だけで必ず解けます。これを"+
      term("総当たり","考えられる鍵をかたっぱしから全部ためす解読法。英語でブルートフォース（brute force）")+
      "といいます。"}));

    var sample = caesar("MEET ME AT THE OLD BRIDGE AT DAWN", 10); // 例題（鍵=10で暗号化済み）
    var inC = el("textarea",{class:"mono",spellcheck:"false"}); inC.value = sample;
    wrap.appendChild(el("label",{class:"field",text:"暗号文（英語）。自由に書き換えてOK"}));
    wrap.appendChild(inC);

    var btn = el("button",{class:"btn",text:"25通りを全部ためす"});
    var resetBtn = el("button",{class:"btn quiet sm",text:"例題にもどす"});
    wrap.appendChild(el("div",{class:"btn-row"},[btn, resetBtn]));

    var result = el("div",{style:"margin-top:14px"});
    wrap.appendChild(result);

    resetBtn.addEventListener("click",function(){ inC.value = sample; clear(result); });

    btn.addEventListener("click",function(){
      clear(result);
      var text = inC.value;
      if(!text.trim()){ CL.toast("暗号文を入れてください"); return; }
      var t0 = performance.now();
      var rows=[], best=-1, bestChi=1e18;
      for(var k=1;k<=25;k++){
        var dec = caesar(text, -k);          // 復号は逆向きにずらす
        var chi = chiSquare(dec);
        rows.push({k:k, dec:dec, chi:chi});
        if(chi<bestChi){ bestChi=chi; best=k; }
      }
      var ms = performance.now()-t0;

      result.appendChild(el("div",{class:"callout ok",html:
        "25通りすべて計算しました（所要 <b>"+ms.toFixed(2)+" ミリ秒</b>）。"+
        "自動採点では <b>鍵 "+best+"</b> が一番英語らしい、と判定。下の表で意味の通る行をさがしてください。"}));

      var tbl = el("table",{class:"data"});
      tbl.appendChild(el("tr",{},[el("th",{text:"鍵"}),el("th",{text:"復号結果"}),el("th",{text:"英語らしさ"}),el("th",{text:""})]));
      rows.forEach(function(r){
        var pick = el("button",{class:"btn quiet sm",text:"これだ！"});
        pick.addEventListener("click",function(){
          CL.store.add("stage1","解読成功",{
            暗号文の長さ:text.length, 選んだ鍵:r.k, 復号結果:r.dec, 自動判定鍵:best, 所要ミリ秒:+ms.toFixed(3)
          });
          CL.toast("実験ノートに記録しました（鍵 "+r.k+"）");
        });
        var tr = el("tr", r.k===best?{class:"hit"}:{}, [
          el("td",{class:"mono",text:String(r.k)}),
          el("td",{class:"mono",text:r.dec}),
          el("td",{class:"mono",text:r.chi.toFixed(0)}),
          el("td",{},[pick])
        ]);
        tbl.appendChild(tr);
      });
      result.appendChild(el("div",{class:"scrollx"},[tbl]));
      result.appendChild(el("p",{class:"tiny muted",html:
        "「英語らしさ」は数字が小さいほど英語らしい（各文字の出現割合が英語の標準にどれだけ近いかを"+
        term("カイ二乗","観測した度数と理論上の度数のズレを測る統計量。小さいほどよく一致している")+
        "で測った値）。この自動判定も、コンピュータが統計で“あたり”をつける解読の一種です。"}));
    });

    return wrap;
  }

  /* ========================= なぜ弱い ========================= */
  function panelWhy(){
    var wrap = el("div",{class:"panel",role:"tabpanel"});
    wrap.appendChild(el("p",{html:
      "暗号の強さの第一歩は、鍵の種類の多さ＝"+term("鍵空間","ありえる鍵の総数。これが小さいと総当たりで破られる")+
      "の大きさです。"}));
    var stats = el("div",{class:"stats"},[
      el("div",{class:"stat"},[el("div",{class:"k",text:"シーザー暗号の鍵の数"}),el("div",{class:"v red",text:"25 通り"})]),
      el("div",{class:"stat"},[el("div",{class:"k",text:"人が全部試す時間"}),el("div",{class:"v",html:"数分 <small>（手作業でも）</small>"})]),
      el("div",{class:"stat"},[el("div",{class:"k",text:"次のステージ：換字式の鍵"}),el("div",{class:"v",html:"26! ≈ 4×10²⁶ <small>通り</small>"})])
    ]);
    wrap.appendChild(stats);
    wrap.appendChild(el("div",{class:"callout info",html:
      "<b>わかること：</b> 鍵がたった25通りなら、総当たりで一瞬で破れます。"+
      "「秘密のやり方」を使っていても、鍵の数が少なければ安全ではありません。"+
      "<br>では鍵を爆発的に増やせば安全？——次の<b>換字式暗号</b>で、"+
      "鍵が 4×10²⁶ 通りあっても別の弱点で破れることを確かめます。"}));
    wrap.appendChild(el("p",{class:"tiny muted",html:
      "ことばの整理：<b>平文</b>＝もとの文、<b>暗号文</b>＝暗号化した文、<b>鍵</b>＝暗号化／復号のときの秘密の数や対応表。"}));
    return wrap;
  }

  /* --- ページ登録 --- */
  CL.route("stage1", {
    title: "Stage 1 シーザー暗号",
    render: function(view){
      view.appendChild(el("p",{class:"eyebrow",text:"STAGE 1 ／ 古典暗号"}));
      view.appendChild(el("h1",{class:"page-title",text:"シーザー暗号を破る"}));
      view.appendChild(el("p",{class:"page-lead",html:"文字をずらすだけの最も古い暗号。<b>総当たり</b>で一瞬で解けることを体験します。"}));

      var sec = el("section",{class:"card"});
      var see=panelSee(), brk=panelBreak(), why=panelWhy();
      brk.hidden=true; why.hidden=true;
      var bar = CL.ui.tabBar(
        [{id:"see",label:"見る",n:"①"},{id:"break",label:"破る",n:"②"},{id:"why",label:"なぜ弱い？",n:"③"}],
        function(id){ see.hidden=(id!=="see"); brk.hidden=(id!=="break"); why.hidden=(id!=="why"); }
      );
      sec.appendChild(bar); sec.appendChild(see); sec.appendChild(brk); sec.appendChild(why);
      view.appendChild(sec);

      view.appendChild(CL.ui.stageNav({id:"home",label:"ホーム"}, {id:"stage2",label:"Stage 2 換字式暗号"}));
    }
  });
})();
