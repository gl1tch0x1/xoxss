import asyncio

from xoxss.scanner import PlaywrightEngine


class Console:
    def ok(self, msg, important=True):
        print("OK:", msg)

    def warn(self, msg, important=True):
        print("WARN:", msg)

    def error(self, msg, important=True):
        print("ERR:", msg)

    def debug(self, msg):
        print("DBG:", msg)


async def main():
    engine = PlaywrightEngine(Console(), headless=True, page_timeout=10)
    started = await engine.start()
    print("started:", started)
    if not started:
        return
    try:
        url = (
            "data:text/html,<html><body>"
            "<div id=x></div>"
            "<script>window.__xoxss_hits.push('PWTOKEN');"
            "document.getElementById('x').innerHTML='PWTOKEN';</script>"
            "</body></html>"
        )
        error = await engine.navigate(url)
        print("navigate error:", error)
        data = await engine.collect()
        print("hits:", data.get("hits"))
        print("sinks:", data.get("sinks"))
        print("html has token:", "PWTOKEN" in data.get("html", ""))
        hit = await engine.check_token("PWTOKEN", timeout=3)
        print("matched:", hit)
        form_url = (
            "data:text/html,<html><body><form>"
            "<input name=q value=old><button type=submit>go</button>"
            "</form></body></html>"
        )
        await engine.navigate(form_url)
        result = await engine.submit_form(0, "q", "newvalue")
        print("submit:", result)
    finally:
        await engine.stop()
        print("stopped")


asyncio.run(main())
