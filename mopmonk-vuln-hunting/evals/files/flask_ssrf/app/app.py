"""Flask app with mixed SSRF risks. Used as an eval fixture for
mopmonk-vuln-hunting.

Contains:
- /preview: weak scheme prefix check -> requests.get (真漏洞)
- /import: hostname allowlist + urllib parse-vs-use mismatch (真漏洞)
- /healthcheck: 内部固定 URL 无用户输入 (无漏洞)
- /webhook: 使用 urlparse 校验且用 parsed url 请求 (无漏洞)
"""
from flask import Flask, request, abort
from urllib.parse import urlparse
import requests
import urllib.request

app = Flask(__name__)

ALLOWED_HOSTS = {"images.example.com", "cdn.example.com"}


@app.route("/preview")
def preview():
    u = request.args["u"]
    if not u.startswith("http"):
        abort(400)
    return proxy_get(u)


def proxy_get(url):
    return requests.get(url, timeout=5).text


@app.route("/import", methods=["POST"])
def import_from_url():
    data = request.get_json(force=True)
    parsed = urlparse(data["url"])
    if parsed.hostname not in ALLOWED_HOSTS:
        abort(403)
    resp = urllib.request.urlopen(data["url"])  # BUG: 用原始 url 而非 parsed
    return resp.read()


@app.route("/healthcheck")
def healthcheck():
    return requests.get("http://localhost:9999/status", timeout=2).text


@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.get_json(force=True)
    parsed = urlparse(data["url"])
    if parsed.scheme not in ("http", "https"):
        abort(400)
    if parsed.hostname not in ALLOWED_HOSTS:
        abort(403)
    safe_url = f"{parsed.scheme}://{parsed.hostname}{parsed.path or ''}"
    return requests.get(safe_url, timeout=5).text


if __name__ == "__main__":
    app.run()
