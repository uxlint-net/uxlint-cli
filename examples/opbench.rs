//! Micro-bench CDP primitives on a real page — where does interaction-pass time go?
use anyhow::Result;
use headless_chrome::{Browser, LaunchOptions};

fn main() -> Result<()> {
    let url = std::env::args().nth(1).expect("url");
    let browser = Browser::new(LaunchOptions::default_builder().headless(true).build()?)?;
    let tab = browser.new_tab()?;
    tab.set_default_timeout(std::time::Duration::from_secs(10));
    tab.navigate_to(&url)?;
    tab.wait_until_navigated()?;
    std::thread::sleep(std::time::Duration::from_millis(500));

    let time = |label: &str, n: u32, f: &dyn Fn()| {
        let t0 = std::time::Instant::now();
        for _ in 0..n {
            f();
        }
        eprintln!(
            "{label}: {n} ops in {:.2}s = {:.0}ms/op",
            t0.elapsed().as_secs_f64(),
            t0.elapsed().as_millis() as f64 / f64::from(n)
        );
    };

    time("evaluate('1')", 30, &|| {
        let _ = tab.evaluate("1", false);
    });
    time("press_key(Tab)", 30, &|| {
        let _ = tab.press_key("Tab");
    });
    time("move_mouse", 20, &|| {
        let _ = tab.move_mouse_to_point(headless_chrome::browser::tab::point::Point {
            x: 400.0,
            y: 300.0,
        });
    });
    const TRAP_SIG: &str = r#"(() => { const e = document.activeElement; if (!e || e === document.body) return '';
  if (!e.__uxrTab) e.__uxrTab = 'n' + (window.__uxrTabSeq = (window.__uxrTabSeq || 0) + 1);
  return (e.__uxrTab + '|' + e.tagName + '#' + (e.id || '') + ':' + (e.textContent || '').trim().slice(0, 20)); })()"#;
    time("trap-sig evaluate", 20, &|| {
        let _ = tab.evaluate(TRAP_SIG, false);
    });
    const FOCUS_OBS: &str = r#"(() => {
  const el = document.activeElement;
  if (!el || el === document.body) return null;
  const pick = n => { const cs = getComputedStyle(n); return [cs.boxShadow, cs.outlineStyle, cs.outlineWidth, cs.borderColor, cs.backgroundColor, cs.color].join('|'); };
  const focused = pick(el);
  const key = (el.tagName + '|' + (el.getAttribute('class') || '')).slice(0, 80);
  const label = (el.getAttribute('aria-label') || el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 40);
  el.blur();
  const blurred = pick(el);
  el.focus();
  return JSON.stringify({ key, label, changed: focused !== blurred });
})()"#;
    time("focus-obs evaluate", 20, &|| {
        let _ = tab.evaluate(FOCUS_OBS, false);
    });
    Ok(())
}
