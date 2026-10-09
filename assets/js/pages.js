/* =====================================================================
   ホーム / 実験ノート(データ出力) / 研究について
   ===================================================================== */
"use strict";
(function(){
  var el=CL.dom.el, clear=CL.dom.clear, term=CL.ui.term;

  var STAGES=[
    {id:"stage1",no:"1",t:"シーザー暗号を破る",d:"文字をずらすだけの暗号を、総当たりで一瞬で解読。",tags:["古典暗号","総当たり"]},
    {id:"stage2",no:"2",t:"換字式暗号を破る",d:"鍵は4×10²⁶通り。それでも文字のかたより（頻度分析）で解読。",tags:["古典暗号","頻度分析"]},
    {id:"stage3",no:"3",t:"ハッシュとパスワード",d:"一方向の“指紋”＝ハッシュ。弱いパスワードを総当たりで割る。",tags:["ハッシュ","雪崩効果"]},
    {id:"stage4",no:"4",t:"ミニRSAと計算量の壁",d:"公開鍵暗号を素因数分解で破り、鍵長と解読時間の爆発を体感。",tags:["公開鍵","計算量"]}
  ];

  /* ========================= ホーム ========================= */
  CL.route("home",{
    title:"",
    render:function(view){
      view.appendChild(el("p",{class:"eyebrow",text:"暗号解読で学ぶ情報セキュリティ"}));
      view.appendChild(el("h1",{class:"page-title",text:"CryptoLab へようこそ"}));
      view.appendChild(el("p",{class:"page-lead",html:
        "暗号は「作る」より<b>「破る」</b>と仕組みがよく見えます。4つのステージで実際に暗号を解読しながら、"+
        "なぜ現代の暗号が安全なのかを確かめましょう。"}));

      var grid=el("div",{class:"stage-cards"});
      STAGES.forEach(function(s){
        var card=el("a",{class:"stage-card",href:"#/"+s.id});
        card.appendChild(el("div",{class:"no",text:s.no}));
        card.appendChild(el("h3",{text:s.t}));
        card.appendChild(el("p",{text:s.d}));
        var tags=el("div",{class:"tags"}); s.tags.forEach(function(t){ tags.appendChild(el("span",{class:"badge blue",text:t})); });
        card.appendChild(tags);
        grid.appendChild(card);
      });
      view.appendChild(grid);

      var exch=el("section",{class:"card"});
      exch.appendChild(el("h2",{text:"友だちと暗号を送り合う"}));
      exch.appendChild(el("p",{html:"学んだ暗号で、<b>別の端末の友だち</b>に暗号メッセージを送り、解読し合えます。1人が<b>何人にも</b>同じ問題を出せます。"}));
      exch.appendChild(el("div",{class:"btn-row"},[el("a",{class:"btn",href:"#/exchange"},["暗号を送る・受け取る →"])]));
      view.appendChild(exch);

      var how=el("section",{class:"card"});
      how.appendChild(el("h2",{text:"使い方"}));
      how.appendChild(el("p",{html:"各ステージは <b>①見る → ②破る → ③なぜ</b> の順。上のタブで切り替えます。"+
        "「破る」で得た結果は「記録」ボタンで"+el("a",{href:"#/data"},["実験ノート"]).outerHTML+"にたまり、"+
        "CSV・JSON・Markdown で書き出せます（卒論の記録用）。"}));
      how.appendChild(el("div",{class:"callout info",html:
        "<b>プライバシー：</b> すべての計算はあなたのブラウザの中だけで動きます。入力やハッシュがどこかへ"+
        "送信されることはありません。スマートフォンでも、一度開けばオフラインで動きます。"}));
      view.appendChild(how);

      // 環境チェック
      var envc=el("section",{class:"card"});
      envc.appendChild(el("h2",{text:"動作チェック"}));
      envc.appendChild(el("p",{class:"small muted",text:"この教材に必要な機能が、お使いのブラウザで動くかの確認です。"}));
      var ul=el("ul",{class:"checks"});
      function li(id,name,desc){ return el("li",{},[
        el("span",{class:"st",id:id,text:"判定中"}),
        el("div",{},[el("b",{text:name}),el("small",{text:desc})])]); }
      ul.appendChild(li("e1","HTTPS 接続","ハッシュ計算API（WebCrypto）の前提"));
      ul.appendChild(li("e2","BigInt","RSA の大きな整数の計算に使用"));
      ul.appendChild(li("e3","WebCrypto","SHA-256 ハッシュの計算に使用"));
      ul.appendChild(li("e4","Web Worker","総当たり・素因数分解を裏で実行"));
      envc.appendChild(ul);
      view.appendChild(envc);
      runEnvCheck();

      view.appendChild(el("div",{class:"stage-nav"},[
        el("span"), el("a",{class:"btn ghost sm",href:"#/about"},["この研究について →"])
      ]));
    }
  });

  function runEnvCheck(){
    function set(id,ok){ var n=document.getElementById(id); if(!n)return; n.textContent=ok?"OK":"NG"; n.className="st "+(ok?"ok":"ng"); }
    set("e1", !!window.isSecureContext);
    var big=false; try{ big=(typeof BigInt==="function") && (CL.num.modpow(7n,5n,13n)===11n); }catch(e){} set("e2",big);
    if(CL.crypto.hasSubtle()){
      CL.crypto.sha256Hex("abc").then(function(h){ set("e3", h.indexOf("ba7816bf")===0); }).catch(function(){ set("e3",false); });
    } else set("e3",false);
    try{
      var w=CL.worker.fromBody("onmessage=function(e){postMessage(e.data*2)}");
      var done=false, t=setTimeout(function(){ if(!done){done=true;set("e4",false);w.terminate();} },2500);
      w.onmessage=function(e){ if(!done){done=true;clearTimeout(t);set("e4",e.data===42);w.terminate();if(w._revoke)w._revoke();} };
      w.onerror=function(){ if(!done){done=true;set("e4",false);} };
      w.postMessage(21);
    }catch(e){ set("e4",false); }
  }

  /* ========================= 実験ノート（データ出力） ========================= */
  CL.route("data",{
    title:"実験ノート",
    render:function(view){
      view.appendChild(el("p",{class:"eyebrow",text:"データ出力"}));
      view.appendChild(el("h1",{class:"page-title",text:"実験ノート"}));
      view.appendChild(el("p",{class:"page-lead",html:"各ステージの「記録」でたまった結果の一覧です。卒論に使えるよう <b>CSV / JSON / Markdown</b> で書き出せます。"}));

      var sec=el("section",{class:"card"});
      var summary=el("div",{class:"stats"}); sec.appendChild(summary);

      var exp=el("div",{class:"btn-row"});
      exp.appendChild(el("button",{class:"btn sm",text:"CSVで保存",onclick:function(){ dl("csv"); }}));
      exp.appendChild(el("button",{class:"btn sm ghost",text:"JSONで保存",onclick:function(){ dl("json"); }}));
      exp.appendChild(el("button",{class:"btn sm ghost",text:"Markdownで保存",onclick:function(){ dl("md"); }}));
      exp.appendChild(el("button",{class:"btn sm quiet",text:"クリップボードにコピー(CSV)",onclick:function(){
        CL.export.copy(CL.export.toCSV(CL.store.all())).then(function(){ CL.toast("CSVをコピーしました"); },function(){ CL.toast("コピーできませんでした"); }); }}));
      exp.appendChild(el("button",{class:"btn sm red",text:"すべて消去",onclick:function(){
        if(confirm("記録をすべて消去します。よろしいですか？")){ CL.store.clear(); refresh(); CL.toast("消去しました"); } }}));
      sec.appendChild(exp);

      var tableHost=el("div",{style:"margin-top:14px"}); sec.appendChild(tableHost);
      view.appendChild(sec);

      function dl(kind){
        var rows=CL.store.all();
        if(!rows.length){ CL.toast("記録がありません"); return; }
        if(kind==="csv") CL.export.download("cryptolab_log.csv", CL.export.toCSV(rows), "text/csv");
        else if(kind==="json") CL.export.download("cryptolab_log.json", CL.export.toJSON(rows), "application/json");
        else CL.export.download("cryptolab_log.md", CL.export.toMarkdown(rows), "text/markdown");
      }

      function refresh(){
        clear(summary); clear(tableHost);
        var all=CL.store.all();
        var byStage={}; all.forEach(function(r){ byStage[r.stage]=(byStage[r.stage]||0)+1; });
        summary.appendChild(statTile("記録の合計", all.length+" 件"));
        [["stage1","Stage1"],["stage2","Stage2"],["stage3","Stage3"],["stage4","Stage4"]].forEach(function(s){
          summary.appendChild(statTile(s[1], (byStage[s[0]]||0)+" 件"));
        });
        if(!all.length){ tableHost.appendChild(el("p",{class:"muted",text:"まだ記録がありません。各ステージの「破る」で実験して、「記録」ボタンを押すとここにたまります。"})); return; }

        var tbl=el("table",{class:"data"});
        tbl.appendChild(el("tr",{},[el("th",{text:"時刻"}),el("th",{text:"ステージ"}),el("th",{text:"できごと"}),el("th",{text:"内容"})]));
        all.slice().reverse().slice(0,80).forEach(function(r){
          var detail=Object.keys(r).filter(function(k){ return ["time","stage","event"].indexOf(k)<0; })
            .map(function(k){ return k+"="+r[k]; }).join("  ");
          var t=new Date(r.time); var ts=isNaN(t)?r.time:(t.toLocaleString("ja-JP"));
          tbl.appendChild(el("tr",{},[
            el("td",{class:"tiny mono",text:ts}),
            el("td",{text:r.stage}),
            el("td",{text:r.event}),
            el("td",{class:"tiny mono",text:detail})
          ]));
        });
        tableHost.appendChild(el("div",{class:"scrollx"},[tbl]));
        if(all.length>80) tableHost.appendChild(el("p",{class:"tiny muted",text:"※ 新しい80件のみ表示（書き出しは全件）。"}));
      }
      function statTile(k,v){ return el("div",{class:"stat"},[el("div",{class:"k",text:k}),el("div",{class:"v",text:v})]); }
      refresh();
    }
  });

  /* ========================= 研究について ========================= */
  CL.route("about",{
    title:"この研究について",
    render:function(view){
      view.appendChild(el("p",{class:"eyebrow",text:"About"}));
      view.appendChild(el("h1",{class:"page-title",text:"この研究について"}));

      var s1=el("section",{class:"card"});
      s1.appendChild(el("h2",{text:"題目（仮）"}));
      s1.appendChild(el("p",{html:"<b>暗号解読の体験を通して情報セキュリティを学ぶ Web 教材「CryptoLab」の開発</b><br>"+
        "<span class='muted'>— 中学校技術科・高等学校「情報Ⅰ」対応 —</span>"}));
      view.appendChild(s1);

      var s2=el("section",{class:"card"});
      s2.appendChild(el("h2",{text:"目的と特徴"}));
      s2.appendChild(el("ul",{class:"tidy"},[
        el("li",{html:"「入力したら暗号文が出るだけ」のブラックボックスを避け、<b>解読の過程</b>を手で動かして学べる。"}),
        el("li",{html:"古典暗号（シーザー・換字式）から現代の<b>ハッシュ・RSA</b>まで、難しさが増していく流れを体験。"}),
        el("li",{html:"<b>完全ローカル動作</b>：サーバー不要・API不要・費用0円。入力は外部に送信しない。"}),
        el("li",{html:"スマートフォンでも動作。実験結果は CSV/JSON/Markdown で書き出し可能。"})
      ]));
      view.appendChild(s2);

      var s3=el("section",{class:"card"});
      s3.appendChild(el("h2",{text:"対応する学習内容"}));
      s3.appendChild(el("p",{html:"<b>中学校技術科「D 情報の技術」：</b> 情報セキュリティの必要性、安全な情報の取り扱い（パスワード・ハッシュ）。"}));
      s3.appendChild(el("p",{html:"<b>高等学校「情報Ⅰ」：</b> 情報セキュリティ、暗号化のしくみ、公開鍵暗号、アルゴリズムと計算量。"}));
      s3.appendChild(el("p",{class:"small muted",text:"導入（Stage1-2）は中学でも扱いやすく、Stage3-4 は高校の発展的内容として使えます。"}));
      view.appendChild(s3);

      var s4=el("section",{class:"card"});
      s4.appendChild(el("h2",{text:"用語集"}));
      var dl=el("div",{class:"small"});
      [["平文（ひらぶん）","暗号化する前の、もとの文。"],
       ["暗号文","暗号化したあとの文。"],
       ["鍵（かぎ）","暗号化・復号に使う秘密の数や対応表。"],
       ["鍵空間","ありえる鍵の総数。小さいと総当たりで破られる。"],
       ["総当たり（ブルートフォース）","考えられる鍵や文字の組合せを全部ためす解読法。"],
       ["頻度分析","文字の出現回数のかたよりから推理する解読法。"],
       ["ハッシュ関数","データから固定長の“指紋”を作る一方向の計算（例：SHA-256）。元に戻せない。"],
       ["雪崩効果","入力の小さな違いが出力全体に大きく広がる性質。"],
       ["ソルト","各パスワードにつける使い捨ての追加文字列。保存するハッシュを人ごとに変える。"],
       ["公開鍵暗号","暗号化の鍵（公開）と復号の鍵（秘密）が別になっている方式（例：RSA）。"],
       ["素因数分解","数を素数のかけ算に戻すこと。大きな数ほど非常に難しい。"],
       ["剰余演算（mod）","割り算の“あまり”を使う計算。RSA の計算の中心。"],
       ["計算量的安全性","理屈の上では解けても、現実的な時間では終わらないことによる安全性。"]
      ].forEach(function(p){
        dl.appendChild(el("p",{style:"margin:.3em 0"},[el("b",{text:p[0]}),document.createTextNode("："+p[1])]));
      });
      s4.appendChild(dl);
      view.appendChild(s4);

      var s5=el("section",{class:"card"});
      s5.appendChild(el("h2",{text:"技術・公開方法"}));
      s5.appendChild(el("p",{html:"HTML / CSS / JavaScript のみ（QR生成の小さなMITライブラリのみ同梱、それ以外は外部ライブラリ非依存）。"+
        "重い計算は Web Worker で別スレッド実行。端末間の受け渡しはリンク／コードで行い、サーバーは使いません。GitHub Pages で静的サイトとして公開。"}));
      s5.appendChild(el("p",{class:"small muted",html:"ソースコード： "+
        el("a",{href:"https://github.com/224096-cmd/cryptolab"},["github.com/224096-cmd/cryptolab"]).outerHTML}));
      view.appendChild(s5);

      view.appendChild(el("div",{class:"stage-nav"},[
        el("a",{class:"btn ghost sm",href:"#/home"},["← ホーム"]),
        el("a",{class:"btn ghost sm",href:"#/stage1"},["Stage 1 からはじめる →"])
      ]));
    }
  });

  /* ========================= 研究（研究モード限定） ========================= */
  function analysisCard(title, note, points, xlabel){
    var card=el("section",{class:"card"});
    card.appendChild(el("h2",{text:title}));
    card.appendChild(el("p",{class:"small muted",text:note}));
    if(points.length<1){ card.appendChild(el("p",{class:"muted",text:"まだデータがありません。各ステージの「破る」で実験すると、ここに自動でたまります。"})); return card; }
    var xs=points.map(function(p){return p.x;});
    var xmin=Math.min.apply(null,xs), xmax=Math.max.apply(null,xs);
    if(xmin===xmax){ xmin-=1; xmax+=1; }
    var lo=Infinity,hi=-Infinity;
    points.forEach(function(p){ var e=Math.log10(Math.max(p.y,1e-9)); if(e<lo)lo=e; if(e>hi)hi=e; });
    lo=Math.floor(lo)-1; hi=Math.ceil(hi)+1; if(hi-lo<2) hi=lo+2;
    var ticks=[]; var step=Math.max(1,Math.round((xmax-xmin)/6));
    for(var t=xmin;t<=xmax;t+=step) ticks.push(t);
    var svg=CL.chart.logLine([{cls:"series-measured", points:points.slice().sort(function(a,b){return a.x-b.x;}), dots:true}],
      { xmin:xmin, xmax:xmax, ymin:lo, ymax:hi, xlabel:xlabel, ylabel:"所要時間", xticks:ticks });
    card.appendChild(svg);
    // 表
    var tbl=el("table",{class:"data"});
    tbl.appendChild(el("tr",{},[el("th",{text:xlabel}),el("th",{text:"所要時間"})]));
    points.slice().sort(function(a,b){return a.x-b.x;}).forEach(function(p){
      tbl.appendChild(el("tr",{},[el("td",{class:"mono",text:p.x}),el("td",{class:"mono",text:CL.fmt.duration(p.y)})]));
    });
    card.appendChild(el("div",{class:"scrollx"},[tbl]));
    return card;
  }

  CL.route("research",{
    title:"研究",
    render:function(view){
      view.appendChild(el("p",{class:"eyebrow",text:"研究モード"}));
      view.appendChild(el("h1",{class:"page-title",text:"研究ノート・分析"}));
      if(!CL.mode.isResearch()){
        view.appendChild(el("section",{class:"card"},[
          el("h2",{text:"ロックされています"}),
          el("p",{html:"このページは研究モードでのみ利用できます。画面右上の <b>🔒</b> からパスワードを入力して解除してください。"})
        ]));
        return;
      }
      view.appendChild(el("p",{class:"page-lead",html:"各ステージの「破る」で集めた実測データをまとめて分析・書き出しできます。鍵の長さ・文字数と解読時間の関係から、<b>計算量</b>を自分のデータで確かめましょう。"}));

      var all=CL.store.all();
      var s3=all.filter(function(r){ return r.stage==="stage3" && r.event==="パスワード解読" && r.文字数!=null && r.所要秒!=null; })
                .map(function(r){ return {x:+r.文字数, y:Math.max(+r.所要秒,1e-6)}; });
      var s4=all.filter(function(r){ return r.stage==="stage4" && r.ビット長!=null && r.所要秒!=null; })
                .map(function(r){ return {x:+r.ビット長, y:Math.max(+r.所要秒,1e-6)}; });
      view.appendChild(analysisCard("パスワード解読：文字数 → 解読時間","Stage3 の「解読成功」記録から。右へ行くほど（長いほど）時間が急増します。", s3, "パスワードの文字数"));
      view.appendChild(analysisCard("RSA解読：鍵のビット長 → 解読時間","Stage4 の素因数分解の記録から。対数グラフでほぼ直線＝指数関数的な増加です。", s4, "鍵のビット長"));

      // 詳細な書き出し
      var exp=el("section",{class:"card"});
      exp.appendChild(el("h2",{text:"詳細データの書き出し"}));
      exp.appendChild(el("p",{class:"small muted",text:"全ステージの記録（"+all.length+" 件）をまとめて保存します。卒論・レポートの分析用。"}));
      var row=el("div",{class:"btn-row"});
      row.appendChild(el("button",{class:"btn sm",text:"CSVで保存",onclick:function(){ dl("csv"); }}));
      row.appendChild(el("button",{class:"btn sm ghost",text:"JSONで保存",onclick:function(){ dl("json"); }}));
      row.appendChild(el("button",{class:"btn sm ghost",text:"Markdownで保存",onclick:function(){ dl("md"); }}));
      exp.appendChild(row);
      view.appendChild(exp);
      function dl(kind){
        var rows=CL.store.all(); if(!rows.length){ CL.toast("記録がありません"); return; }
        if(kind==="csv") CL.export.download("cryptolab_log.csv", CL.export.toCSV(rows), "text/csv");
        else if(kind==="json") CL.export.download("cryptolab_log.json", CL.export.toJSON(rows), "application/json");
        else CL.export.download("cryptolab_log.md", CL.export.toMarkdown(rows), "text/markdown");
      }

      // 全消去
      var dz=el("section",{class:"card"});
      dz.appendChild(el("h2",{text:"データの全消去"}));
      dz.appendChild(el("p",{class:"small muted",text:"各ページの途中経過と、実験ノートの記録をすべて消します（授業のリセット用）。"}));
      dz.appendChild(el("div",{class:"btn-row"},[el("button",{class:"btn sm red",text:"すべて消去",onclick:function(){
        if(!confirm("各ページの途中経過と実験記録を、すべて消去します。よろしいですか？")) return;
        try{ var ks=[]; for(var i=0;i<localStorage.length;i++){ var k=localStorage.key(i); if(k&&k.indexOf("cryptolab.state.")===0) ks.push(k); } ks.forEach(function(k){ localStorage.removeItem(k); }); }catch(e){}
        CL.store.clear(); CL.toast("すべて消去しました"); CL.router.reload();
      }})]));
      view.appendChild(dz);

      view.appendChild(CL.ui.stageNav({id:"data",label:"実験ノート"},{id:"home",label:"ホーム"}));
    }
  });
})();
