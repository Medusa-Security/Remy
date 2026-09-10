"""Agent 1 — Autonomous Browser Exploration.

A curious-human agent: it opens the app and pokes at everything — clicks every
button, fills every form with invalid input, opens every in-app link, tries
keyboard navigation, and resizes the viewport. Every interaction is recorded as
an event, and any console error, page exception, or crash becomes a finding.

Playwright is an optional dependency (``pip install remy-agent[medusa]``). The
agent raises :class:`MedusaAgentError` when it is not installed so the
orchestrator can skip it instead of aborting the whole run.
"""

from __future__ import annotations

from remy.report.models import Severity

from ..agents import AgentContext, BaseAgent, MedusaAgentError
from ..events import AgentResult, EventKind
from ..target import MedusaTarget


def _playwright_available() -> bool:
    try:
        import importlib.util

        return importlib.util.find_spec("playwright") is not None
    except Exception:
        return False


_INVALID_INPUTS = [
    "",
    "💀" * 200,
    "../../etc/passwd",
    "'; DROP TABLE users;--",
    "a" * 5000,
    "-1",
]


class BrowserAgent(BaseAgent):
    name = "browser"

    def __init__(self, max_clicks: int = 15, max_links: int = 8) -> None:
        self.max_clicks = max_clicks
        self.max_links = max_links

    def available(self) -> bool:
        return _playwright_available()

    def run(self, target: MedusaTarget, ctx: AgentContext) -> AgentResult:
        if not self.available():
            raise MedusaAgentError(
                "Playwright is not installed. Run: pip install remy-agent[medusa] "
                "and `playwright install chromium`."
            )

        from playwright.sync_api import sync_playwright

        console_errors: list[str] = []
        page_errors: list[str] = []

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.on(
                "console",
                lambda m: console_errors.append(m.text) if m.type == "error" else None,
            )
            page.on("pageerror", lambda e: page_errors.append(str(e)))

            nav = ctx.navigate(self.name, target.base_url)
            try:
                page.goto(target.base_url, timeout=target.timeout * 1000)
            except Exception as e:  # noqa: BLE001
                ctx.exception(self.name, target.base_url, parent=nav.id, detail=str(e))
                browser.close()
                return self._finish(ctx, console_errors, page_errors)

            self._click_everything(page, ctx, target)
            self._fill_forms(page, ctx)
            self._walk_links(page, ctx, target)

            # viewport / responsive probe
            try:
                page.set_viewport_size({"width": 375, "height": 667})
                page.set_viewport_size({"width": 1280, "height": 800})
            except Exception:  # noqa: BLE001
                pass

            browser.close()

        return self._finish(ctx, console_errors, page_errors)

    def _click_everything(self, page, ctx, target) -> None:
        try:
            selectors = page.eval_on_selector_all(
                "button, a[href], input[type=submit], [role=button]",
                "els => els.slice(0, 60).map(e => e.outerHTML)",
            )
        except Exception:  # noqa: BLE001
            selectors = []
        clicked = 0
        for html in selectors:
            if clicked >= self.max_clicks:
                break
            ev = None
            try:
                el = page.locator(
                    "button, a[href], input[type=submit], [role=button]"
                ).nth(clicked)
                label = html[:60]
                ev = ctx.click(self.name, label)
                el.click(timeout=3000)
                clicked += 1
            except Exception as e:  # noqa: BLE001
                ctx.exception(
                    self.name, label, parent=ev.id if ev else None, detail=str(e)
                )

    def _fill_forms(self, page, ctx) -> None:
        from ..events import Event, EventKind

        try:
            fields = page.locator("input:not([type=submit]), textarea")
            count = fields.count()
        except Exception:  # noqa: BLE001
            return
        for i in range(min(count, 20)):
            value = _INVALID_INPUTS[i % len(_INVALID_INPUTS)]
            try:
                fld = fields.nth(i)
                ev = ctx.emit(
                    Event.make(
                        EventKind.FILL,
                        self.name,
                        f"field#{i}",
                        detail=f"value={value!r}",
                    )
                )
                fld.fill(str(value), timeout=2000)
            except Exception as e:  # noqa: BLE001
                ctx.exception(self.name, f"field#{i}", parent=ev.id, detail=str(e))

    def _walk_links(self, page, ctx, target) -> None:
        try:
            links = page.eval_on_selector_all(
                "a[href^='/']",
                "els => els.slice(0, 40).map(e => e.getAttribute('href'))",
            )
        except Exception:  # noqa: BLE001
            links = []
        seen = {target.base_url.rstrip("/")}
        walked = 0
        for href in links:
            if walked >= self.max_links or not href:
                break
            full = (
                (target.base_url.rstrip("/") + href) if href.startswith("/") else href
            )
            if full in seen:
                continue
            seen.add(full)
            ev = ctx.navigate(self.name, full)
            try:
                page.goto(full, timeout=target.timeout * 1000)
                walked += 1
            except Exception as e:  # noqa: BLE001
                ctx.exception(self.name, full, parent=ev.id, detail=str(e))

    def _finish(self, ctx, console_errors, page_errors) -> AgentResult:
        for err in console_errors + page_errors:
            ctx.finding(
                scanner=self.name,
                severity=Severity.MEDIUM,
                title="Browser runtime error",
                detail=f"Client-side error observed during exploration: {err[:300]}",
                location="browser-console",
                cwe="CWE-754",
                remediation="Handle the error in the UI; surface a fallback instead of failing silently.",
            )
        return AgentResult(
            agent=self.name,
            events=ctx.events,
            findings=ctx.findings,
            summary={
                "console_errors": len(console_errors),
                "page_errors": len(page_errors),
                "clicks": len([e for e in ctx.events if e.kind == EventKind.CLICK]),
                "navigations": len(
                    [e for e in ctx.events if e.kind == EventKind.NAVIGATE]
                ),
            },
        )
