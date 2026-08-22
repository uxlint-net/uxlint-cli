//! Fix-preview pass (ON by default; --no-previews / UXLINT_NO_PREVIEWS skips). After an audit,
//! every finding with an on-screen rect gets an annotated "before" crop; findings whose fix is a
//! deterministic, element-local CSS change also get the fix applied live and an "after" — the
//! before/after pair the report shows side by side.

use anyhow::{Context, Result};
use headless_chrome::protocol::cdp::Page::{CaptureScreenshotFormatOption, Viewport};
use headless_chrome::{Browser, LaunchOptions};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::worker::{base_chrome_flags, missing_browser_message};
use crate::{AuditArgs, Cli};

/// The JS body that applies a lint's fix to the element bound as `el`. None for rules without a
/// clean element-local visual fix.
fn patch_body(rule: &str) -> Option<String> {
    // Turn the in-page section nav bound as `navc` into the recommended mobile pattern: a sticky,
    // collapsible "On this page" control (shown expanded so the full-width, easy-to-tap rows are
    // visible) whose header names the current section — i.e. a dropdown that tracks scroll.
    // Idempotent (built once) so applying it per-target doesn't stack duplicates.
    let dropdown = r##"if(document.getElementById('__uxrtoc'))return; var _ls=Array.prototype.slice.call(navc.querySelectorAll('a[href^="#"]')); if(!_ls.length)return; var _cur=(_ls[0].textContent||'On this page').trim(); var _d=document.createElement('details'); _d.id='__uxrtoc'; _d.open=true; _d.style.cssText='position:sticky;top:0;z-index:50;background:#12151d;border:1px solid #2a2f3a;border-radius:10px;margin:0 0 12px 0;overflow:hidden;font:500 14px system-ui,sans-serif'; var _s=document.createElement('summary'); _s.style.cssText='list-style:none;cursor:pointer;padding:12px 14px;color:#e6e8ee;display:flex;justify-content:space-between;align-items:center'; _s.innerHTML='<span>On this page — <b style="color:#8ab4f8">'+_cur+'</b></span><span style="color:#8ab4f8">▾</span>'; _d.appendChild(_s); var _l=document.createElement('div'); _l.style.cssText='display:flex;flex-direction:column;padding:4px 6px 10px'; _ls.forEach(function(a){var _i=document.createElement('a');_i.href=a.getAttribute('href')||'#';_i.textContent=(a.textContent||'').trim();_i.style.cssText='display:block;padding:11px 10px;color:#cbd5e1;text-decoration:none;border-radius:6px';_l.appendChild(_i);}); _d.appendChild(_l); navc.parentNode.insertBefore(_d,navc); navc.style.display='none';"##;
    // Grow the tap area WITHOUT disturbing layout. A full-width list-row link (display:block, or a
    // flex child) already spans its row: forcing it to inline-flex + min-width:44px collapses it to
    // content width, kills its truncation, and shoves whatever sits beside it (a Delete button) —
    // the fix rendered WORSE than the original. So only inline targets get the centred 44px box;
    // block/flex targets just gain vertical padding + min-height, which is all a dense list needs.
    let pad = "var t=el.closest('a,button,[role=button],input,select,summary')||el; var d=getComputedStyle(t).display; t.style.setProperty('min-height','44px','important'); t.style.setProperty('padding-top','10px','important'); t.style.setProperty('padding-bottom','10px','important'); if(d==='inline'||d==='inline-block'){ t.style.setProperty('display','inline-flex','important'); t.style.setProperty('align-items','center','important'); t.style.setProperty('justify-content','center','important'); t.style.setProperty('min-width','44px','important'); t.style.setProperty('padding-left','12px','important'); t.style.setProperty('padding-right','12px','important'); }";
    // Reveal text hidden by a line-clamp / ellipsis / nowrap overflow — lets the full copy render.
    let unclamp = "var s=[['overflow','visible'],['-webkit-line-clamp','unset'],['display','block'],['white-space','normal'],['text-overflow','clip'],['max-height','none']]; for(var i=0;i<s.length;i++) el.style.setProperty(s[i][0],s[i][1],'important');";
    Some(match rule {
        "link-color-only" => "var a=el.closest('a')||el; a.style.setProperty('text-decoration','underline','important');".into(),
        "tiny-text" => "el.style.setProperty('font-size','16px','important'); el.style.setProperty('line-height','1.5','important');".into(),
        // tap-target does not fire on navs (that's section-nav-not-sticky's job) — just grow the
        // hit area for genuine standalone small targets.
        "tap-target" => pad.into(),
        "aspect-distortion" => "el.style.setProperty('object-fit','contain','important');".into(),
        "misaligned-text" => "el.style.setProperty('margin-left','0','important'); el.style.setProperty('padding-left','0','important');".into(),
        "breadcrumbs-missing" => "var main=document.querySelector('main')||document.body; var h1=main.querySelector('h1')||document.querySelector('h1'); if(!h1) return; if(document.querySelector('nav[aria-label=Breadcrumb]')) return; var segs=location.pathname.split('/').filter(Boolean); var trail=['Home'].concat(segs.map(function(s){return s.replace(/[-_]/g,' ').replace(/\\b\\w/g,function(c){return c.toUpperCase();});})); var nav=document.createElement('nav'); nav.setAttribute('aria-label','Breadcrumb'); nav.style.cssText='display:flex;gap:8px;align-items:center;font:500 13px system-ui,sans-serif;margin:0 0 14px 0;padding:0'; nav.innerHTML=trail.map(function(t,i){return i<trail.length-1?'<a href=\"#\" style=\"color:#8ab4f8;text-decoration:none\">'+t+'</a>':'<span style=\"color:#9aa4b2\">'+t+'</span>';}).join(' <span style=\"color:#556;opacity:.7\">\\u203a</span> '); h1.parentNode.insertBefore(nav,h1);".into(),
        "line-length" => "var t=el.closest('p,li,dd,blockquote')||el; t.style.setProperty('max-width','65ch','important');".into(),
        "contrast" => "function L(c){var m=(c||'').match(/[0-9.]+/g)||['255','255','255'];var a=[m[0],m[1],m[2]].map(function(v){v/=255;return v<=0.03928?v/12.92:Math.pow((v+0.055)/1.055,2.4);});return 0.2126*a[0]+0.7152*a[1]+0.0722*a[2];}var n=el,bg='rgb(255,255,255)';while(n){var b=getComputedStyle(n).backgroundColor;if(b&&b!=='rgba(0, 0, 0, 0)'&&b!=='transparent'){bg=b;break;}n=n.parentElement;}el.style.setProperty('color',L(bg)>0.4?'#111111':'#ffffff','important');".into(),
        // The recommended pattern for an in-page section nav on mobile.
        "section-nav-not-sticky" => format!(r##"var navc=el.closest('nav,[role="navigation"],aside,ul,ol')||el; {dropdown}"##, dropdown = dropdown),
        // Remove the account/settings item from the primary nav; the green suggestion shows where
        // it belongs (the avatar/name). Applied per account item.
        "settings-in-primary-nav" => "var t=el.closest('a,li,[role=menuitem],button')||el; t.style.setProperty('display','none','important');".into(),
        // Promote the placeholder to a persistent, visible <label> above the field (and clear the
        // placeholder so the before/after difference is obvious). Idempotent per field.
        "placeholder-as-label" => "var inp=el.closest('input,textarea,select')||el; var ph=inp.getAttribute('placeholder')||inp.getAttribute('aria-label'); if(!ph)return; var prev=inp.previousElementSibling; if(prev&&prev.getAttribute&&prev.getAttribute('data-uxrlbl'))return; var lb=document.createElement('label'); lb.setAttribute('data-uxrlbl','1'); lb.textContent=ph; lb.style.cssText='display:block;font:600 13px system-ui,sans-serif;color:inherit;opacity:.85;margin:0 0 6px 0'; inp.parentNode.insertBefore(lb,inp); inp.setAttribute('placeholder','');".into(),
        // Truncated/clipped text: unclamp it so the full copy is visible.
        "content-truncated" | "text-clipping" | "clipped-content" => unclamp.into(),
        // A short control label forced onto two lines — keep it on one.
        "unwanted-wrap" => "var t=el.closest('a,button,[role=button],label,span')||el; t.style.setProperty('white-space','nowrap','important');".into(),
        // iOS force-zooms inputs under 16px on focus — bump the field to 16px.
        "ios-input-zoom" => "var inp=el.closest('input,textarea,select')||el; inp.style.setProperty('font-size','16px','important');".into(),
        _ => return None,
    })
}

/// A layout-regression probe at the fix's target points: returns the page's scrollWidth and how
/// many targets currently overlap a sibling element. Run BEFORE and AFTER a fix — if the "after"
/// grew the page's horizontal overflow or made a control collide with its neighbour, the fix made
/// things WORSE, and a worse preview is worse than none.
const REGRESSION_JS: &str = r#"(function(){
  var cs=__CENTERS__;
  var over=0;
  for(var i=0;i<cs.length;i++){
    var el=document.elementFromPoint(cs[i][0],cs[i][1]); if(!el) continue;
    var t=el.closest('a,button,[role=button],input,select,summary,li')||el;
    var r=t.getBoundingClientRect(); var p=t.parentElement; if(!p) continue;
    for(var j=0;j<p.children.length;j++){
      var c=p.children[j]; if(c===t) continue;
      var q=c.getBoundingClientRect(); if(q.width<1||q.height<1) continue;
      var ox=Math.min(r.right,q.right)-Math.max(r.left,q.left);
      var oy=Math.min(r.bottom,q.bottom)-Math.max(r.top,q.top);
      if(ox>2&&oy>2) over++;
    }
  }
  return document.documentElement.scrollWidth + '|' + over;
})()"#;

/// (scrollWidth, sibling-overlap count) at the target points, or None if it can't be measured.
fn measure(tab: &headless_chrome::Tab, centers: &[(f64, f64)]) -> Option<(f64, f64)> {
    let pts = centers
        .iter()
        .map(|&(x, y)| format!("[{x:.0},{y:.0}]"))
        .collect::<Vec<_>>()
        .join(",");
    let js = REGRESSION_JS.replace("__CENTERS__", &format!("[{pts}]"));
    let s = tab.evaluate(&js, false).ok()?.value?.as_str()?.to_string();
    let mut it = s.split('|');
    Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
}

/// Apply the fix to EVERY affected element — one target point per mark. Resolve them all up front
/// (a reflow from patching one element must not move the next), then patch each. Returns JS that
/// yields true if any element was found and patched.
fn patch_js_multi(rule: &str, centers: &[(f64, f64)]) -> Option<String> {
    let body = patch_body(rule)?;
    let pts = centers
        .iter()
        .map(|(x, y)| format!("[{x:.0},{y:.0}]", x = x, y = y))
        .collect::<Vec<_>>()
        .join(",");
    Some(format!(
        "(function(){{var els=[{pts}].map(function(p){{return document.elementFromPoint(p[0],p[1]);}});var any=false;els.forEach(function(el){{if(!el)return; {body} any=true;}});return any;}})()"
    ))
}

/// The target point of each mark — the element the fix should touch. Rect → its centre; Dist → its
/// far endpoint (the stray element). Falls back to the finding's rect centre.
fn fix_targets(marks_json: &str, fallback: (f64, f64)) -> Vec<(f64, f64)> {
    let mut out = Vec::new();
    if let Ok(Value::Array(arr)) = serde_json::from_str::<Value>(marks_json) {
        for m in &arr {
            let g =
                |v: &Value, i: usize| v.as_array().and_then(|a| a.get(i)).and_then(Value::as_f64);
            match m["t"].as_str() {
                Some("rect") => {
                    if let (Some(x), Some(y), Some(w), Some(h)) =
                        (g(&m["r"], 0), g(&m["r"], 1), g(&m["r"], 2), g(&m["r"], 3))
                    {
                        out.push((x + w / 2.0, y + h / 2.0));
                    }
                }
                Some("dist") => {
                    if let (Some(x), Some(y)) = (g(&m["p"], 2), g(&m["p"], 3)) {
                        out.push((x, y));
                    }
                }
                _ => {}
            }
        }
    }
    if out.is_empty() {
        out.push(fallback);
    }
    out
}

/// Rules whose whole point is a MEASUREMENT — an element is misaligned, too small, too wide, or
/// a distance is off. Only these get the width/height dimension callouts; for every other finding
/// the dimension lines are noise, so we draw just the outline.
fn wants_dimensions(rule: &str) -> bool {
    matches!(
        rule,
        "tap-target"
            | "line-length"
            | "inconsistent-widths"
            | "aspect-distortion"
            | "layout-width-mismatch"
            | "chrome-eats-viewport"
    )
}

/// JS injected before the "before" screenshot. Renders a list of MARKS baked into the page and
/// RETURNS the clip rect "x,y,w,h" framing them all (evaluate only returns primitives by value,
/// hence a string), clamped to the viewport with a minimum size. A `rect` mark is a dashed outline
/// set off by a margin with corner ticks (and, when `dims`, its width/height as dimension
/// callouts). A `dist` mark is a measured distance — two extension lines and, if there's room, an
/// arrowed dimension line with the label between them; when the span is too small the label sits
/// outside on a short leader. A `guide` is a dashed reference line. Labels are frosted
/// (backdrop-blur) HTML and nudged apart so they don't overlap. All geometry is viewport CSS px at
/// scroll 0, so it bakes in perfectly aligned. `marks_json` is a JSON array of the marks.
/// JS that returns `true` when the finding's target — or any ancestor — is CSS `position: fixed`
/// or `sticky`, i.e. it floats above the normal flow and re-pins when the window is resized. The
/// capture loop uses this to decide whether to shoot at viewport height. Returns `false` when the
/// selector matches nothing (a stale or whole-page finding) so those capture normally, and swallows
/// any selector-parse error the same way.
fn floating_probe_js(sel: &str) -> String {
    // JSON-encode the selector so any quotes/backslashes in it can't break out of the JS string.
    let sel = serde_json::to_string(sel).unwrap_or_else(|_| "\"\"".into());
    format!(
        "(function(){{try{{\
           var el=document.querySelector({sel});\
           for(var n=el;n&&n!==document.documentElement;n=n.parentElement){{\
             var p=getComputedStyle(n).position;\
             if(p==='fixed'||p==='sticky')return true;\
           }}\
           return false;\
         }}catch(e){{return false;}}}})()"
    )
}

fn architect_annotation(marks_json: &str, vw: f64, vh: f64, suggest: bool) -> String {
    format!(
        r####"(function(){{
  var vw={vw:.0},vh={vh:.0},MARKS={marks},SUG={suggest};
  var NS='http://www.w3.org/2000/svg',C=SUG?'#34d399':'#ff453a',SW=1.6,M=12,TICK=9,GAP=17,EXT=6,EXL=8;
  ['__uxrann','__uxrlbl'].forEach(function(i){{var o=document.getElementById(i);if(o)o.remove();}});
  var svg=document.createElementNS(NS,'svg'); svg.id='__uxrann';
  svg.setAttribute('width',vw); svg.setAttribute('height',vh);
  svg.style.cssText='position:fixed;left:0;top:0;width:'+vw+'px;height:'+vh+'px;z-index:2147483647;pointer-events:none;overflow:visible';
  svg.innerHTML='<defs>'
    +'<marker id="uxa" markerWidth="10" markerHeight="10" refX="8.5" refY="4.5" orient="auto-start-reverse"><path d="M1,1 L8.5,4.5 L1,8" fill="none" stroke="'+C+'" stroke-width="'+SW+'" stroke-linecap="round" stroke-linejoin="round"/></marker>'
    +'<filter id="uxs" x="-50%" y="-50%" width="200%" height="200%"><feDropShadow dx="0" dy="0" stdDeviation="1.5" flood-color="#000" flood-opacity="0.6"/></filter></defs>';
  var g=document.createElementNS(NS,'g'); g.setAttribute('filter','url(#uxs)');
  var lbls=document.createElement('div'); lbls.id='__uxrlbl'; lbls.style.cssText='position:fixed;left:0;top:0;pointer-events:none;z-index:2147483647';
  var ext=[], placed=[];
  function E(x,y){{ext.push([x,y]);}}
  function ln(x1,y1,x2,y2,arr,dash){{var l=document.createElementNS(NS,'line');l.setAttribute('x1',x1);l.setAttribute('y1',y1);l.setAttribute('x2',x2);l.setAttribute('y2',y2);l.setAttribute('stroke',C);l.setAttribute('stroke-width',SW);l.setAttribute('stroke-linecap','round');if(dash)l.setAttribute('stroke-dasharray','5 4');if(arr){{l.setAttribute('marker-start','url(#uxa)');l.setAttribute('marker-end','url(#uxa)');}}g.appendChild(l);E(x1,y1);E(x2,y2);}}
  function lw(t){{return t.length*6.9+12;}}
  function label(cx,cy,txt){{var w=lw(txt),h=18,lx=cx-w/2,ly=cy-h/2,k=0;while(k<50&&placed.some(function(p){{return !(lx+w<=p.x||lx>=p.x+p.w||ly+h<=p.y||ly>=p.y+p.h);}})){{ly+=h+3;k++;}}placed.push({{x:lx,y:ly,w:w,h:h}});var d=document.createElement('div');d.textContent=txt;d.style.cssText='position:fixed;left:'+(lx+w/2)+'px;top:'+(ly+h/2)+'px;transform:translate(-50%,-50%);padding:1px 6px;border-radius:5px;font:600 11px ui-monospace,SFMono-Regular,Menlo,monospace;color:#fff;white-space:nowrap;background:rgba(8,10,14,.20);backdrop-filter:blur(5px);-webkit-backdrop-filter:blur(5px);text-shadow:0 1px 2px rgba(0,0,0,.9);pointer-events:none';lbls.appendChild(d);E(lx,ly);E(lx+w,ly+h);}}
  function box(bx,by,bw,bh){{var x2=Math.min(vw-2,bx+bw),y2=Math.min(vh-2,by+bh);bx=Math.max(2,bx);by=Math.max(2,by);bw=Math.max(1,x2-bx);bh=Math.max(1,y2-by);var r=document.createElementNS(NS,'rect');r.setAttribute('x',bx);r.setAttribute('y',by);r.setAttribute('width',bw);r.setAttribute('height',bh);r.setAttribute('rx',3);r.setAttribute('fill','none');r.setAttribute('stroke',C);r.setAttribute('stroke-width',SW);r.setAttribute('stroke-dasharray','5 4');g.appendChild(r);var cn=[[bx,by,1,1],[bx+bw,by,-1,1],[bx,by+bh,1,-1],[bx+bw,by+bh,-1,-1]];for(var i=0;i<4;i++){{var c=cn[i];ln(c[0],c[1],c[0]+c[2]*TICK,c[1],false,false);ln(c[0],c[1],c[0],c[1]+c[3]*TICK,false,false);}}E(bx,by);E(bx+bw,by+bh);}}
  function boxdims(bx,by,bw,bh,ww,hh){{
    var wB=(by+bh+GAP+24)<=vh, dY=wB?(by+bh+GAP):(by-GAP), eY=wB?(by+bh):by;
    ln(bx,eY,bx,dY+(wB?EXT:-EXT),false,false); ln(bx+bw,eY,bx+bw,dY+(wB?EXT:-EXT),false,false); ln(bx,dY,bx+bw,dY,true,false); label((bx+bx+bw)/2,dY,Math.round(ww)+' px');
    var hR=(bx+bw+GAP+54)<=vw, dX=hR?(bx+bw+GAP):(bx-GAP), eX=hR?(bx+bw):bx;
    ln(eX,by,dX+(hR?EXT:-EXT),by,false,false); ln(eX,by+bh,dX+(hR?EXT:-EXT),by+bh,false,false); ln(dX,by,dX,by+bh,true,false); label(dX,(by+by+bh)/2,Math.round(hh)+' px');
  }}
  function dist(x1,y1,x2,y2,txt){{
    var horiz=Math.abs(y2-y1)<=Math.abs(x2-x1), span=Math.hypot(x2-x1,y2-y1), need=lw(txt)+18;
    if(horiz){{
      ln(x1,y1-EXL,x1,y1+EXL,false,false); ln(x2,y2-EXL,x2,y2+EXL,false,false);
      if(span>=need){{ ln(x1,y1,x2,y2,true,false); label((x1+x2)/2,y1-13,txt); }}
      else {{ ln(x1,y1,x2,y2,false,false); var mx=(x1+x2)/2; ln(mx,y1-EXL,mx,y1-EXL-9,false,false); label(mx,y1-EXL-18,txt); }}
    }} else {{
      ln(x1-EXL,y1,x1+EXL,y1,false,false); ln(x2-EXL,y2,x2+EXL,y2,false,false);
      if(span>=need){{ ln(x1,y1,x2,y2,true,false); label(x1+15,(y1+y2)/2,txt); }}
      else {{ ln(x1,y1,x2,y2,false,false); var my=(y1+y2)/2; ln(x1+EXL,my,x1+EXL+9,my,false,false); label(x1+EXL+18+lw(txt)/2,my,txt); }}
    }}
  }}
  // Clip covers ALL marks (issue + suggestion) so the before and after share one frame.
  for(var ci=0;ci<MARKS.length;ci++){{var cm=MARKS[ci],cq=cm.r||cm.p;if(cq){{E(cq[0],cq[1]);E(cm.r?cq[0]+cq[2]:cq[2],cm.r?cq[1]+cq[3]:cq[3]);}}}}
  var pend=[]; // plain (no-dims) rect boxes — merged if they overlap so a stack of them reads as one region
  for(var i=0;i<MARKS.length;i++){{var mk=MARKS[i];
    if(SUG){{ if(mk.t==='suggest'){{var rs=mk.r;box(rs[0]-M,rs[1]-M,rs[2]+2*M,rs[3]+2*M);if(mk.l)label(rs[0]+rs[2]/2,rs[1]-M-13,mk.l);}}
      else if(mk.t==='rewrite'){{var rw2=mk.r;box(rw2[0]-M,rw2[1]-M,rw2[2]+2*M,rw2[3]+2*M);}} }}
    else if(mk.t==='rect'){{var r=mk.r,bx0=r[0]-M,by0=r[1]-M,bw0=r[2]+2*M,bh0=r[3]+2*M;
      if(mk.dims){{box(bx0,by0,bw0,bh0);boxdims(bx0,by0,bw0,bh0,r[2],r[3]);}}
      else pend.push([bx0,by0,bx0+bw0,by0+bh0]);}}
    else if(mk.t==='rewrite'){{var rw1=mk.r;pend.push([rw1[0]-M,rw1[1]-M,rw1[0]+rw1[2]+M,rw1[1]+rw1[3]+M]);}}
    else if(mk.t==='guide'){{var q=mk.p; ln(q[0],q[1],q[2],q[3],false,true);}}
    else if(mk.t==='dist'){{var p=mk.p; dist(p[0],p[1],p[2],p[3],mk.l);}}
  }}
  var ch=true;
  while(ch){{ch=false;
    lp: for(var a1=0;a1<pend.length;a1++)for(var b1=a1+1;b1<pend.length;b1++){{var A=pend[a1],B=pend[b1];
      if(!(A[2]<B[0]||B[2]<A[0]||A[3]<B[1]||B[3]<A[1])){{pend[a1]=[Math.min(A[0],B[0]),Math.min(A[1],B[1]),Math.max(A[2],B[2]),Math.max(A[3],B[3])];pend.splice(b1,1);ch=true;break lp;}}
    }}
  }}
  for(var m1=0;m1<pend.length;m1++){{var q1=pend[m1];box(q1[0],q1[1],q1[2]-q1[0],q1[3]-q1[1]);}}
  svg.appendChild(g); document.body.appendChild(svg); document.body.appendChild(lbls);
  if(!ext.length) return '0,0,'+Math.round(Math.min(vw,320))+','+Math.round(Math.min(vh,220));
  var PAD=40, xs=ext.map(function(e){{return e[0];}}), ys=ext.map(function(e){{return e[1];}});
  // Don't let the frame run past the page's rendered content — a short page (or the space below
  // the last section) is just background and shows as a black band. BUT never clamp away the marks
  // themselves: a footer/copyright can sit below the measured scrollHeight (absolute or overflowing
  // element), and cutting it is worse than a sliver of background — so keep at least their extent.
  var _maxY=Math.max.apply(null,ys);
  var contentBottom=Math.min(vh, Math.max(document.documentElement.scrollHeight||vh, _maxY+8));
  var contentRight=Math.min(vw, document.documentElement.scrollWidth||vw);
  var cx=Math.max(0,Math.min.apply(null,xs)-PAD), cy=Math.max(0,Math.min.apply(null,ys)-PAD);
  var cr=Math.min(contentRight,Math.max.apply(null,xs)+PAD), cb=Math.min(contentBottom,Math.max.apply(null,ys)+PAD);
  var minW=380,minH=280,n;
  if(cr-cx<minW){{n=(minW-(cr-cx))/2;cx=Math.max(0,cx-n);cr=Math.min(contentRight,cr+n);}}
  if(cb-cy<minH){{n=(minH-(cb-cy))/2;cy=Math.max(0,cy-n);cb=Math.min(contentBottom,cb+n);}}
  // Cap the frame: marks scattered down a long page (e.g. small links throughout) must not
  // stretch it the whole viewport — keep it focused on the top cluster. But when there's a
  // suggestion (which may point far from the issue, e.g. foot of a side rail), keep both in view.
  var hasSug=MARKS.some(function(m){{return m.t==='suggest'||m.t==='rewrite';}});
  var CAPH=480; if(cb-cy>CAPH && !hasSug) cb=cy+CAPH;
  // Grow the SHORT axis to make the frame square, centred on the annotation and clamped to the
  // page. The report thumbnail is square, so a square crop shows the whole annotation rather than
  // object-cover slicing it — which is why a wide/short finding here captures a much taller strip
  // of the page (and vice-versa). If a viewport is too narrow/short to reach a full square, we get
  // as close as the page allows and the square thumbnail crops only the small remainder.
  var cw=cr-cx, ch=cb-cy, side=Math.max(cw,ch);
  if(cw<side){{var gx=(side-cw)/2; cx=Math.max(0,cx-gx); cr=Math.min(contentRight,cx+side); cx=Math.max(0,cr-side);}}
  if(ch<side){{var gy=(side-ch)/2; cy=Math.max(0,cy-gy); cb=Math.min(contentBottom,cy+side); cy=Math.max(0,cb-side);}}
  return [Math.round(cx),Math.round(cy),Math.round(cr-cx),Math.round(cb-cy)].join(',');
}})()"####,
        vw = vw,
        vh = vh,
        marks = marks_json,
        suggest = if suggest { "true" } else { "false" }
    )
}

/// Stable fingerprint — MUST match report_html::preview_key on the server.
fn preview_key(rule: &str, route: &str, x: f64, y: f64, w: f64, h: f64) -> String {
    let s = format!(
        "{rule}|{route}|{}|{}|{}|{}",
        x.round() as i64,
        y.round() as i64,
        w.round() as i64,
        h.round() as i64
    );
    let mut hh: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        hh ^= b as u64;
        hh = hh.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hh:016x}")
}

struct Fix {
    route: String,
    vp: String,
    vw: f64,
    vh: f64,
    key: String,
    rule: String,
    fixable: bool,
    x: f64,
    y: f64,
    w: f64,
    h: f64,
    /// JSON array of marks to draw (from the finding, or a synthesised single box).
    marks: String,
    /// The finding's CSS selector, when it names a real element. Lets the capture loop detect a
    /// FLOATING (fixed/sticky) target and shoot it at the true viewport height — where it sits over
    /// what it covers — instead of the tall capture window, where a pinned element re-lays-out and
    /// its box lands on empty page. `None` for whole-page/site sentinels (captured normally).
    sel: Option<String>,
}

/// Build a Fix for one (route, viewport, rule, rect) — with rich marks from the finding when
/// present, else a synthesised outline. Returns None when the viewport is unknown or the rect
/// isn't usably on-screen. Shared by the per-page pass and the cross-resolution variant pass so
/// both produce identical, key-matched previews.
///
/// Extra viewport height captured beyond the layout height so a target low on a tall page still
/// renders into the surface instead of falling outside it. Must match the value used when the
/// capture bounds are set in `run`. Generous because headless swallows ~140px of the requested
/// window height, and a control can sit well past a phone's fold (a "Create account" button near
/// the end of a stacked mobile form is ~1100-1200px down).
const CAPTURE_PAD: f64 = 720.0;

fn make_fix(
    route: &str,
    vp: &str,
    rule: &str,
    rect_val: &Value,
    marks_val: Option<&Value>,
    sel_val: Option<&Value>,
) -> Option<Fix> {
    let (vw, vh) = match vp {
        "desktop" => (1440.0, 900.0),
        "mobile" => (390.0, 844.0),
        _ => return None,
    };
    if route.is_empty() {
        return None;
    }
    let rect = rect_val.as_array().filter(|r| r.len() >= 4)?;
    let (x, y, w, h) = (
        rect[0].as_f64().unwrap_or(-1.0),
        rect[1].as_f64().unwrap_or(-1.0),
        rect[2].as_f64().unwrap_or(0.0),
        rect[3].as_f64().unwrap_or(0.0),
    );
    // The element must fall within the region we actually CAPTURE — which is taller than the layout
    // viewport (CAPTURE_PAD extra), so a control low on a tall page (e.g. a "Create account" button
    // at y≈1120 on a 844-high mobile layout) still gets a preview. Using the plain viewport height
    // here silently dropped every below-the-fold finding. Require a usable slice, not a 2px sliver.
    let vis_w = (vw - x).min(w);
    // Reject only degenerate / absurd rects. The capture surface GROWS to fit the element (see the
    // capture loop), so a target low on a tall page still gets a preview — a fixed viewport+pad
    // previously dropped every finding below ~1620px (footers, late sections) with no image.
    if x < 0.0 || !(0.0..=30000.0).contains(&y) || w < 1.0 || h < 1.0 || vis_w < 8.0 {
        return None;
    }
    // Rich marks from the finding win; otherwise synthesise a single outline (with the box's own
    // width/height as dimensions for measurement rules).
    let marks = match marks_val
        .and_then(|m| m.as_array())
        .filter(|a| !a.is_empty())
    {
        Some(a) => serde_json::to_string(a).unwrap_or_default(),
        None => format!(
            r#"[{{"t":"rect","r":[{x:.1},{y:.1},{w:.1},{h:.1}],"dims":{}}}]"#,
            wants_dimensions(rule)
        ),
    };
    Some(Fix {
        route: route.to_string(),
        vp: vp.to_string(),
        vw,
        vh,
        key: preview_key(rule, route, x, y, w, h),
        fixable: patch_body(rule).is_some(),
        rule: rule.to_string(),
        x,
        y,
        w,
        h,
        marks,
        // A real element selector only — the whole-page / site / head sentinels don't identify a
        // floating element, so they stay None and capture normally.
        sel: sel_val
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty() && !matches!(*s, "page" | "site" | "head"))
            .map(String::from),
    })
}

/// Replace `from` text with `to` for every `rewrite` mark, so the AFTER shot shows the improved
/// copy where it lives. Returns true if at least one rewrite landed.
fn apply_rewrites(tab: &headless_chrome::Tab, marks_json: &str) -> bool {
    let marks: Vec<Value> = serde_json::from_str(marks_json).unwrap_or_default();
    let mut any = false;
    for m in marks.iter().filter(|m| m["t"] == "rewrite") {
        let (from, to) = (
            m["from"].as_str().unwrap_or(""),
            m["to"].as_str().unwrap_or(""),
        );
        if from.trim().is_empty() || to.trim().is_empty() {
            continue;
        }
        let js = REWRITE_JS
            .replace(
                "__FROM__",
                &serde_json::to_string(from).unwrap_or_else(|_| "\"\"".into()),
            )
            .replace(
                "__TO__",
                &serde_json::to_string(to).unwrap_or_else(|_| "\"\"".into()),
            );
        let landed = tab
            .evaluate(&js, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        any = any || landed;
    }
    any
}

/// Find the tightest element whose visible text contains `from` and swap in `to`. Whitespace is
/// normalised so a quote that spans line wraps still matches. Best-effort — returns false if the
/// text can't be located (the judge quote drifted from the on-page copy).
const REWRITE_JS: &str = r#"(() => {
  const from = __FROM__;
  // The judge sometimes wraps the replacement in quotes despite instructions — strip them.
  const to = (__TO__ || '').replace(/^\s*["'“‘]+/, '').replace(/["'”’]+\s*$/, '').trim();
  const norm = s => (s || '').replace(/\s+/g, ' ').trim();
  const nf = norm(from);
  if (!nf) return false;
  let best = null;
  for (const el of document.querySelectorAll('h1,h2,h3,h4,h5,h6,p,li,a,button,span,figcaption,label,dt,dd,blockquote,em,strong,small')) {
    if (el.children.length > 4) continue;
    if (norm(el.textContent).includes(nf)) {
      if (!best || (el.textContent || '').length < (best.textContent || '').length) best = el;
    }
  }
  if (!best) return false;
  best.textContent = norm(best.textContent).replace(nf, to);
  return true;
})()"#;

/// Best-effort: returns how many before/after previews were generated and uploaded.
pub(crate) fn run(cli: &Cli, args: &AuditArgs, report: &Value) -> Result<usize> {
    let Some(id) = report["report_id"].as_str() else {
        return Ok(0);
    };
    // ONE preview per finding: every finding with an on-screen rect gets a single captured crop with
    // the issue outlined IN the screenshot (fixable ones also get an "after"). A finding is already
    // stored on the viewport it matters for (a mobile-only overflow lives on the mobile page), so the
    // one crop is the RIGHT resolution. We deliberately do NOT re-screenshot the same finding at other
    // resolutions — that's the bulk of the cost (screenshots are the audit's bottleneck) for a
    // switcher few open. `viewport_variants` still labels the finding "desktop + mobile"; the web just
    // won't offer a per-resolution crop switcher.
    let mut fixes: Vec<Fix> = Vec::new();
    let mut seen_keys = std::collections::HashSet::new();
    for p in report["pages"]
        .as_array()
        .map(|v| v.as_slice())
        .unwrap_or(&[])
    {
        let vp = p["viewport"].as_str().unwrap_or("");
        let route = p["route"].as_str().unwrap_or("");
        for f in p["findings"]
            .as_array()
            .map(|v| v.as_slice())
            .unwrap_or(&[])
        {
            let rule = f["rule"].as_str().unwrap_or("");
            // A single-rule run (`--rule`, and every `verify_fix` call) previews THAT rule only.
            // Screenshots are the audit's bottleneck, and re-capturing the whole page's findings to
            // answer "did my contrast fix land?" turned a 2s check into 43s — twenty times slower on
            // the loop an agent runs after every edit. The rule you asked about still gets its crop,
            // which is the one anybody looks at.
            if let Some(only) = args.preview_rule.as_deref().or(args.rule.as_deref()) {
                if !only.is_empty() && rule != only {
                    continue;
                }
            }
            if let Some(fx) = make_fix(route, vp, rule, &f["rect"], f.get("marks"), f.get("sel")) {
                if seen_keys.insert(fx.key.clone()) {
                    fixes.push(fx);
                }
            }
        }
    }
    // The cap bounds preview GENERATION time (each is a browser screenshot + crop). With one crop per
    // finding — and element-coverage dedup keeping findings low — this is rarely hit; if it is, say so.
    const PREVIEW_CAP: usize = 120;
    if fixes.len() > PREVIEW_CAP {
        eprintln!(
            "  warning: {} finding(s) exceed the {PREVIEW_CAP}-preview cap and will have NO image — raise the cap or reduce findings",
            fixes.len() - PREVIEW_CAP
        );
        fixes.truncate(PREVIEW_CAP);
    }
    if fixes.is_empty() {
        return Ok(0);
    }

    let browser = Browser::new(
        LaunchOptions::default_builder()
            .headless(true)
            // Hide the scrollbar so it isn't baked into the crop — a real phone/desktop shows an
            // overlay scrollbar (or none), so a classic scrollbar track in the preview looks wrong,
            // especially on the narrow mobile viewport.
            .args({
                let mut f = base_chrome_flags();
                f.push(std::ffi::OsStr::new("--hide-scrollbars"));
                f
            })
            // Taller than any capture viewport so a below-the-fold target (a footer copyright, a
            // late section) actually renders into the surface instead of falling outside it and
            // baking as a black band. The annotation still clips TIGHT around the element.
            .window_size(Some((1440, 1720)))
            .build()?,
    )
    .with_context(missing_browser_message)?;
    let tab = browser.new_tab()?;
    crate::worker::hide_opted_out_chrome(&tab);
    if !args.headers.is_empty() {
        let mut hdrs = HashMap::new();
        for hd in &args.headers {
            if let Some((k, v)) = hd.split_once(':') {
                hdrs.insert(k.trim(), v.trim());
            }
        }
        tab.set_extra_http_headers(hdrs)?;
    }
    if !args.storage.is_empty() {
        let _ = tab
            .navigate_to(&args.base)
            .and_then(|t| t.wait_until_navigated().map(|_| ()));
        for kv in &args.storage {
            if let Some((k, v)) = kv.split_once('=') {
                let _ = tab.evaluate(&format!("localStorage.setItem({:?}, {:?})", k, v), false);
            }
        }
    }
    // Form login, same as the audit browser (worker.rs auth path 3): this pass runs in a FRESH
    // browser, so a site whose only credential is [credentials.login] was signed OUT here — every
    // gated route redirected to the login page and its previews captured the wrong screen.
    if let (Some(url), Some(user), Some(pass)) = (&args.login_url, &args.username, &args.password) {
        let login_url = if url.starts_with("http") {
            url.clone()
        } else {
            format!("{}{}", args.base.trim_end_matches('/'), url)
        };
        if tab
            .navigate_to(&login_url)
            .and_then(|t| t.wait_until_navigated().map(|_| ()))
            .is_ok()
        {
            std::thread::sleep(std::time::Duration::from_millis(700));
            let fill = crate::test_run::FILL_JS
                .replace(
                    "__EMAIL__",
                    &serde_json::to_string(user).unwrap_or_else(|_| "\"\"".into()),
                )
                .replace(
                    "__PW__",
                    &serde_json::to_string(pass).unwrap_or_else(|_| "\"\"".into()),
                );
            let _ = tab.evaluate(&fill, false);
            std::thread::sleep(std::time::Duration::from_millis(450));
            let _ = tab.evaluate(crate::test_run::SUBMIT_JS, false);
            std::thread::sleep(std::time::Duration::from_millis(1600));
        }
    }

    let clip = |x: f64, y: f64, w: f64, h: f64| Viewport {
        x,
        y,
        width: w,
        height: h,
        scale: 1.0,
    };
    let shoot = |c: Viewport| {
        // Redact the WHOLE page immediately before every capture, so nothing leaks into a preview
        // crop. Runs on each shot (not once up front) because the "after" preview fires after a fix
        // patch or copy rewrite has mutated the DOM, which can re-render a field back to its real
        // value; re-masking right before the grab keeps both before and after shots clean.
        let _ = tab.evaluate(crate::redact::mask_secrets_js(), false);
        tab.capture_screenshot(CaptureScreenshotFormatOption::Jpeg, Some(82), Some(c), true)
            .ok()
    };

    // Process desktop findings then mobile ones, resizing the window once per viewport switch;
    // reload the page per finding so a patch doesn't leak into the next capture.
    let mut order: Vec<&Fix> = fixes.iter().collect();
    order.sort_by(|a, b| a.vp.cmp(&b.vp).then(a.route.cmp(&b.route)));
    let mut cur_vp = String::new();
    let mut previews: Vec<Value> = Vec::new();
    // Content-hash of every image we've already buffered → the finding-key that carries its bytes.
    // A page-wide/absence finding falls back to the whole-viewport rect (server rules.rs), so many
    // findings render the SAME full-page crop. Rather than hold and upload that identical image once
    // per finding — the report can have 100+ findings — we hash each capture and, on a repeat, buffer
    // a tiny reference instead of the bytes. Bounds both this process's memory and the upload to the
    // set of DISTINCT images; the server stores one blob and points the duplicates' keys at it.
    let mut seen_content: HashMap<[u8; 32], String> = HashMap::new();
    // Capture at a viewport TALLER than the layout height (fx.vh) so a target low on the page
    // renders into frame; the extra height is just headroom below the fold, and the annotation's
    // clip keeps the crop tight around the element regardless.
    let cap_h = |vh: f64| vh + CAPTURE_PAD;
    // Per viewport, grow the capture surface to reach the LOWEST element on any page (capped so a
    // pathological rect can't blow up memory). One resize per viewport, not per finding.
    let mut max_h: HashMap<String, f64> = HashMap::new();
    for fx in &order {
        let e = max_h.entry(fx.vp.clone()).or_insert(0.0);
        *e = e.max(cap_h(fx.vh).max(fx.y + fx.h + 200.0)).min(10000.0);
    }
    let mut cur_h = 0.0_f64;
    // A floating finding (below) shrinks the window to viewport height for its own shot; this flag
    // makes the NEXT finding restore the tall surface before it navigates, so one floating target
    // can't leave a later below-the-fold target rendering into a too-short window.
    let mut shrunk = false;
    for fx in order {
        if fx.vp != cur_vp {
            cur_h = *max_h.get(&fx.vp).unwrap_or(&cap_h(fx.vh));
            let _ = tab.set_bounds(headless_chrome::types::Bounds::Normal {
                left: None,
                top: None,
                width: Some(fx.vw),
                height: Some(cur_h),
            });
            std::thread::sleep(std::time::Duration::from_millis(200));
            cur_vp = fx.vp.clone();
            shrunk = false;
        } else if shrunk {
            let _ = tab.set_bounds(headless_chrome::types::Bounds::Normal {
                left: None,
                top: None,
                width: Some(fx.vw),
                height: Some(cur_h),
            });
            std::thread::sleep(std::time::Duration::from_millis(200));
            shrunk = false;
        }
        let url = format!("{}{}", args.base.trim_end_matches('/'), fx.route);
        if tab
            .navigate_to(&url)
            .and_then(|t| t.wait_until_navigated().map(|_| ()))
            .is_err()
        {
            continue;
        }
        std::thread::sleep(std::time::Duration::from_millis(600));
        // A FLOATING (fixed/sticky) target re-pins when the capture window is resized: in the tall
        // surface it sits at the bottom of ~1600px, not where the finding's viewport coords put it,
        // so its annotation box would land on empty page. Shrink to the real viewport height so it
        // drops back over the content it actually covers, and annotate/clip at that height. Detected
        // live from the finding's selector; the next iteration restores the tall surface (see above).
        let mut eff_h = cur_h;
        if let Some(sel) = fx.sel.as_deref() {
            let floating = tab
                .evaluate(&floating_probe_js(sel), false)
                .ok()
                .and_then(|r| r.value)
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if floating {
                let _ = tab.set_bounds(headless_chrome::types::Bounds::Normal {
                    left: None,
                    top: None,
                    width: Some(fx.vw),
                    height: Some(fx.vh),
                });
                std::thread::sleep(std::time::Duration::from_millis(250));
                eff_h = fx.vh;
                shrunk = true;
            }
        }
        // Draw the architect-style dimension annotation INTO the page (baked into the pixels, so
        // it's always aligned with the element) and let it return the clip rect that frames the
        // whole annotation. Screenshot exactly that region, then remove the annotation. Reuse the
        // same clip for the "after" so before/after line up.
        // The annotation returns its clip rect as a "x,y,w,h" string — evaluate() only passes
        // PRIMITIVES back by value (an array would come back as an unserialized object ref).
        let clip_rect = tab
            .evaluate(&architect_annotation(&fx.marks, fx.vw, eff_h, false), false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_str().map(String::from))
            .map(|s| {
                s.split(',')
                    .filter_map(|n| n.parse::<f64>().ok())
                    .collect::<Vec<_>>()
            })
            .filter(|a| a.len() == 4);
        let Some(a) = clip_rect else {
            eprintln!(
                "  warning: no annotation clip for {} on {} [{}] — finding will have no preview",
                fx.rule, fx.route, fx.vp
            );
            continue;
        };
        let (cx, cy, cw, ch) = (a[0], a[1], a[2], a[3]);
        std::thread::sleep(std::time::Duration::from_millis(60));
        let Some(before) = shoot(clip(cx, cy, cw, ch)) else {
            eprintln!(
                "  warning: screenshot failed for {} on {} [{}] — finding will have no preview",
                fx.rule, fx.route, fx.vp
            );
            continue;
        };
        let _ = tab.evaluate("(function(){['__uxrann','__uxrlbl'].forEach(function(i){var o=document.getElementById(i);if(o)o.remove();});})()", false);
        // Capture an "after" when the finding has a live fix and/or a green suggestion of where
        // things should go. Apply the patch (if any) to every affected element, then draw the
        // GREEN suggestion annotation and reshoot the same region.
        let has_suggest = fx.marks.contains("\"t\":\"suggest\"");
        let has_rewrite = fx.marks.contains("\"t\":\"rewrite\"");
        let mut after: Vec<u8> = Vec::new();
        if fx.fixable || has_suggest || has_rewrite {
            let mut ok = true;
            if fx.fixable {
                // Apply the fix to EVERY affected element (all marks), not just the one at the centre.
                let targets = fix_targets(&fx.marks, (fx.x + fx.w / 2.0, fx.y + fx.h / 2.0));
                let before_m = measure(&tab, &targets);
                ok = patch_js_multi(&fx.rule, &targets)
                    .and_then(|js| tab.evaluate(&js, false).ok())
                    .and_then(|r| r.value)
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                // Don't ship a fix that made things WORSE: if applying it added horizontal overflow
                // or made the control collide with a neighbour, suppress the "after" — the report
                // shows the outlined issue alone rather than a preview that regressed the layout.
                if ok {
                    if let (Some(b), Some(a)) = (before_m, measure(&tab, &targets)) {
                        if a.0 > b.0 + 2.0 || a.1 > b.1 {
                            eprintln!(
                                "  note: {} fix on {} [{}] regressed the layout (overflow/overlap) — showing the issue only, no after",
                                fx.rule, fx.route, fx.vp
                            );
                            ok = false;
                        }
                    }
                }
            }
            if has_rewrite {
                // Inject each rewrite (replace `from` text with `to`) so the after shows the copy in
                // place. If nothing else made this fixable and no rewrite landed, skip the after.
                let rewrote = apply_rewrites(&tab, &fx.marks);
                if !fx.fixable && !has_suggest {
                    ok = rewrote;
                }
            }
            if ok {
                let _ = tab.evaluate(&architect_annotation(&fx.marks, fx.vw, eff_h, true), false);
                std::thread::sleep(std::time::Duration::from_millis(140));
                after = shoot(clip(cx, cy, cw, ch)).unwrap_or_default();
            }
        }
        use base64::Engine;
        // Fingerprint the exact bytes (before, then after — with a separator so a byte shifting across
        // the boundary can't collide two distinct pairs). SHA-256 makes a false duplicate — which would
        // show the wrong image — astronomically unlikely.
        let digest: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(&before);
            h.update([0u8]);
            h.update(&after);
            h.finalize().into()
        };
        if let Some(src_key) = seen_content.get(&digest) {
            // Identical to an image we've already buffered: reference it, drop these bytes. `has_after`
            // travels so the server's row matches the shared blob (before-only vs before/after).
            previews.push(json!({
                "key": fx.key, "same_as": src_key, "has_after": !after.is_empty(), "w": cw, "h": ch,
            }));
        } else {
            seen_content.insert(digest, fx.key.clone());
            let enc = |b: Vec<u8>| base64::engine::general_purpose::STANDARD.encode(b);
            previews.push(
                json!({ "key": fx.key, "before": enc(before), "after": enc(after), "w": cw, "h": ch }),
            );
        }
    }
    if previews.is_empty() {
        return Ok(0);
    }
    let n = previews.len();
    let http = reqwest::blocking::Client::new();
    let _ = http
        .post(format!("{}/v1/reports/{}/previews", cli.server, id))
        .bearer_auth(cli.api_key.as_deref().unwrap_or(""))
        .json(&previews)
        .send();
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::{floating_probe_js, make_fix, patch_body};
    use serde_json::json;

    #[test]
    fn make_fix_carries_a_real_selector_and_drops_whole_page_sentinels() {
        // A desktop rect low on the page (below the fold) — the exact case the floating fix serves.
        let rect = json!([100.0, 690.0, 300.0, 50.0]);
        let sel_of = |sel: Option<serde_json::Value>| {
            make_fix("/", "desktop", "cta-competition", &rect, None, sel.as_ref())
                .expect("a valid rect must yield a fix")
                .sel
        };
        // A real element selector is carried through so the capture loop can probe it for floating.
        assert_eq!(
            sel_of(Some(json!("div.fixed.bottom-0"))).as_deref(),
            Some("div.fixed.bottom-0")
        );
        // The whole-page / site / head sentinels (and an empty string) don't name an element, so
        // they must NOT arm the floating path — they collapse to None and capture normally.
        for sentinel in ["page", "site", "head", ""] {
            assert_eq!(
                sel_of(Some(json!(sentinel))),
                None,
                "{sentinel:?} must not be treated as a floating selector"
            );
        }
        // A finding with no selector field at all is None too.
        assert_eq!(sel_of(None), None);
    }

    #[test]
    fn floating_probe_js_escapes_the_selector_and_checks_fixed_and_sticky() {
        // Selectors come from the collector, so a quote inside one must be JSON-escaped or it would
        // break out of the JS string literal (and could inject script).
        let js = floating_probe_js(r#"a[title="x"]"#);
        assert!(
            js.contains(r#"a[title=\"x\"]"#),
            "selector must be JSON-escaped into the probe: {js}"
        );
        // It walks ancestors looking for either floating position.
        assert!(
            js.contains("'fixed'") && js.contains("'sticky'"),
            "probe must check both fixed and sticky: {js}"
        );
        // Even the degenerate empty selector yields a self-contained, catch-guarded expression that
        // can't throw out of evaluate().
        let empty = floating_probe_js("");
        assert!(
            empty.contains("querySelector") && empty.contains("catch"),
            "probe must stay guarded: {empty}"
        );
    }

    #[test]
    fn fixable_rules_have_a_patch_body() {
        // Every rule we advertise an after-preview for must yield a non-empty patch.
        for rule in [
            "link-color-only",
            "tiny-text",
            "tap-target",
            "aspect-distortion",
            "misaligned-text",
            "breadcrumbs-missing",
            "line-length",
            "contrast",
            "section-nav-not-sticky",
            "settings-in-primary-nav",
            "placeholder-as-label",
            "content-truncated",
            "text-clipping",
            "clipped-content",
            "unwanted-wrap",
            "ios-input-zoom",
        ] {
            let body = patch_body(rule);
            assert!(
                body.as_deref().map(str::len).unwrap_or(0) > 0,
                "{rule} has no patch body"
            );
        }
    }

    #[test]
    fn non_visual_rules_have_no_patch() {
        // Rules whose fix isn't a visible DOM change must NOT claim an after-preview.
        for rule in [
            "image-overweight",
            "junk-alt-text",
            "meta-description-missing",
            "html-lang-missing",
        ] {
            assert!(patch_body(rule).is_none(), "{rule} should not be fixable");
        }
    }
}
