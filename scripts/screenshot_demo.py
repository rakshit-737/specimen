"""Re-shoot the README hero image (docs/figures/demo.png) from the built docs site.

    python -m mkdocs build --strict      # after scripts/build_demo.py
    python scripts/screenshot_demo.py    # needs: pip install playwright && playwright install chromium

Serves ``site/`` on localhost, opens the njRAT demo report in headless
Chromium, waits for the Mermaid provenance graph to render and saves a PNG
of the top of the page (verdict, family evidence and graph). Only the local
site is loaded, plus the Mermaid script the Material theme fetches.
"""
from __future__ import annotations

import functools
import http.server
import socketserver
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
OUT = ROOT / "docs" / "figures" / "demo.png"


def main() -> int:
    from playwright.sync_api import sync_playwright
    if not (SITE / "demo" / "avast_njrat_1" / "index.html").exists():
        sys.exit("site/ not built: run python -m mkdocs build --strict first")
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(SITE))
    with socketserver.TCPServer(("127.0.0.1", 0), handler) as httpd:
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport={"width": 1180, "height": 1500}, device_scale_factor=1)
            page.goto(f"http://127.0.0.1:{port}/demo/avast_njrat_1/", wait_until="networkidle")
            page.wait_for_selector(".mermaid svg", timeout=30_000)
            page.add_style_tag(content=".md-header, .md-tabs { position: static !important; }")
            graph = page.locator(".mermaid").first.bounding_box()
            height = int(min(1500, (graph["y"] + graph["height"] + 24) if graph else 1100))
            page.screenshot(path=str(OUT), clip={"x": 0, "y": 0, "width": 1180, "height": height})
            browser.close()
        httpd.shutdown()
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KiB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
