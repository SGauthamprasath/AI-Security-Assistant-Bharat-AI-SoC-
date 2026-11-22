"""Drive study_app.html with a headless browser as a BOT participant to prove the UI works end to end (consent -> trials -> SUS -> CSV).
The CSV it produces is a functional test artefact: every row is stamped synthetic=1 and the analysis refuses to report it."""
import json, os, sys, random
from playwright.sync_api import sync_playwright
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
out = os.path.join(ROOT, "study", "_selftest")
pid = int(sys.argv[1]) if len(sys.argv) > 1 else 1
rnd = random.Random(pid)
with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/usr/bin/google-chrome", args=["--no-sandbox"])
    pg = b.new_page(viewport={"width": 420, "height": 900})
    errs = []
    pg.on("pageerror", lambda e: errs.append(str(e)))
    pg.goto("file://" + os.path.join(ROOT, "study", "study_app.html"))
    pg.check("#ok"); pg.fill("#pid", str(pid)); pg.click("#go")
    for key, n in (("upi", 5), ("susp", 5), ("loss", 3)):
        pg.check(f"input[name={key}][value='{rnd.randrange(n)}']")
    pg.click("#next"); pg.click("#go")
    shots = 0
    for i in range(10):
        if i in (0, 1) and pid == 1:
            pg.screenshot(path=os.path.join(out, f"trial_{i+1}.png"), full_page=True)
        pg.check(f"input[name=a][value='{rnd.randrange(5)}']"); pg.check(f"input[name=r][value='{rnd.randrange(4)}']")
        pg.check(f"input[name=c][value='{rnd.randint(1,5)}']"); pg.check(f"input[name=t][value='{rnd.randint(1,5)}']")
        pg.click("#next")
    for i in range(10):
        pg.check(f"input[name=s{i}][value='{rnd.randint(1,5)}']")
    pg.fill("#cm", "bot"); pg.click("#fin")
    csv = pg.evaluate("csv()")
    b.close()
assert not errs, errs
lines = csv.strip().splitlines()
assert len(lines) == 1 + 10 + 1, len(lines)
# stamp every row synthetic=1 (the app exports 0 for real participants); analyze_study.py refuses such files in --report mode
hdr, *body = lines
assert hdr.endswith("synthetic")
assert all(l.endswith('"0"') for l in body)
csv = "\n".join([hdr] + [l[:-3] + '"1"' for l in body]) + "\n"
open(os.path.join(out, f"ui_bot_{pid:02d}.csv"), "w").write(csv)
print("UI smoke test OK:", len(lines) - 1, "rows, no JS errors")
