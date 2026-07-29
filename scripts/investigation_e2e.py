#!/usr/bin/env python3
"""Playwright E2E flow for Investigation UI (SPL autonomy scaffold)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.cookiejar import CookieJar
from pathlib import Path

from runtime_config import UI_ENV_PATH, parse_env_file, write_env_file

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT_ROOT = PROJECT_ROOT / "artifacts" / "spl_autonomy"

FAILED_LOGON_QUESTION = "Show failed login activity in the last 24 hours in windows."
REQUIRED_SPL_TERMS = ("4625",)
REQUIRED_SPL_ANY_TERMS = ("stats", "eval", "table")
FORBIDDEN_SPL_PATTERNS = (r"linux_secure.*4625", r"4625.*linux_secure")
DEFAULT_E2E_USER = "e2e_admin"
DEFAULT_E2E_PASSWORD = "AgtsmithE2eTest1!"
PLACEHOLDER_PASSWORDS = {
    "",
    "Replace-With-A-Strong-Password",
    "changeme",
    "password",
    "admin",
}


def _looks_like_password_hash(value: str) -> bool:
    token = str(value or "").strip()
    return token.startswith("pbkdf2:") or token.startswith("scrypt:") or token.startswith("$2")


def _resolve_e2e_credentials() -> tuple[str, str]:
    _, file_values = parse_env_file(UI_ENV_PATH)
    user = (
        os.environ.get("AGTSMITH_UI_USER", "").strip()
        or os.environ.get("SOC_UI_AUTH_USERNAME", "").strip()
        or file_values.get("SOC_UI_AUTH_USERNAME", "").strip()
        or DEFAULT_E2E_USER
    )
    password = (
        os.environ.get("AGTSMITH_UI_PASS", "").strip()
        or os.environ.get("SOC_UI_AUTH_PASSWORD", "").strip()
        or file_values.get("SOC_UI_AUTH_PASSWORD", "").strip()
    )
    if _looks_like_password_hash(password):
        password = os.environ.get("AGTSMITH_E2E_PASS", DEFAULT_E2E_PASSWORD)
    elif password in PLACEHOLDER_PASSWORDS or len(password) < 12:
        password = os.environ.get("AGTSMITH_E2E_PASS", DEFAULT_E2E_PASSWORD)
    return user, password


def _build_opener(jar: CookieJar | None = None) -> urllib.request.OpenerDirector:
    handlers: list[urllib.request.BaseHandler] = [urllib.request.HTTPRedirectHandler()]
    if jar is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(jar))
    return urllib.request.build_opener(*handlers)


def _page_is_first_run(html: str) -> bool:
    return "Create first login" in html or 'action="/setup/first-run"' in html


def _page_is_login(html: str) -> bool:
    return 'action="/login"' in html or "A.G.E.N.T. Smith Login" in html


def _fetch(url: str, *, jar: CookieJar | None = None, timeout: int = 10) -> tuple[int, str, str]:
    opener = _build_opener(jar)
    req = urllib.request.Request(url, method="GET")
    with opener.open(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        return int(resp.status), resp.geturl(), body


def _post_form(url: str, fields: dict[str, str], *, jar: CookieJar | None = None, timeout: int = 15) -> tuple[int, str]:
    opener = _build_opener(jar)
    body = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with opener.open(req, timeout=timeout) as resp:
        resp.read()
        return int(resp.status), resp.geturl()


def _try_urllib_login(base_url: str, user: str, password: str) -> bool:
    jar = CookieJar()
    login_url = f"{base_url.rstrip('/')}/login"
    try:
        _post_form(login_url, {"username": user, "password": password}, jar=jar)
    except urllib.error.HTTPError as exc:
        if exc.code != 401:
            raise
        return False
    try:
        status, final_url, _body = _fetch(f"{base_url.rstrip('/')}/investigation", jar=jar)
    except urllib.error.HTTPError as exc:
        return exc.code not in {401, 403}
    return status < 400 and "/login" not in final_url and "/setup/first-run" not in final_url


def _restart_ui_server(base_url: str) -> None:
    port = urllib.parse.urlparse(base_url).port or 8787
    restart_cmd = f"""
pids=$(ss -ltnp 2>/dev/null | awk '/:{port} / {{print $NF}}' | sed -n 's/.*pid=\\([0-9]\\+\\).*/\\1/p' | sort -u)
if [ -n "$pids" ]; then
  kill $pids 2>/dev/null || true
  sleep 1
fi
cd {PROJECT_ROOT}
if [ -f config/ui.env ]; then
  set -a
  . ./config/ui.env
  set +a
fi
nohup env PYTHONPATH=.{os.pathsep}scripts .venv/bin/python scripts/web_ui_server.py --host 0.0.0.0 --port {port} > /tmp/agtsmith-ui-e2e.log 2>&1 &
"""
    subprocess.run(["bash", "-c", restart_cmd], check=False, cwd=PROJECT_ROOT)
    deadline = time.time() + 20
    while time.time() < deadline:
        if _lab_up(base_url):
            return
        time.sleep(0.5)
    raise RuntimeError(f"UI server did not come back on {base_url}")


def _maybe_bootstrap_first_run(base_url: str, user: str, password: str) -> bool:
    setup_url = f"{base_url.rstrip('/')}/setup/first-run"
    try:
        status, final_url, body = _fetch(setup_url)
    except urllib.error.HTTPError as exc:
        if exc.code in {302, 303, 307, 308}:
            return False
        raise
    if status != 200 or not _page_is_first_run(body):
        return False
    jar = CookieJar()
    _post_form(
        setup_url,
        {
            "username": user,
            "role": "admin",
            "password": password,
            "confirm_password": password,
        },
        jar=jar,
    )
    return True


def _question_locator(page):
    return page.locator('[data-testid="investigation-question"], #question').first


def _run_locator(page):
    return page.locator('[data-testid="investigation-run"], #run').first


def _spl_panel_locator(page):
    return page.locator('[data-testid="spl-query-panel"], #spl-query, #drawer-spl-query').first


def _exec_state_locator(page):
    return page.locator('[data-testid="exec-monitor-state"], #exec-monitor-state').first


def _docker_ui_running() -> bool:
    try:
        proc = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", "agtsmith-ui-deploy"],
            capture_output=True,
            text=True,
            check=False,
        )
        return proc.returncode == 0 and proc.stdout.strip() == "true"
    except (OSError, subprocess.SubprocessError):
        return False


def _refresh_mcp_token_if_possible() -> None:
    _, values = parse_env_file(UI_ENV_PATH)
    if not values.get("SPLUNK_USER") or not values.get("SPLUNK_PASS"):
        return
    token_script = PROJECT_ROOT / ".cursor/skills/agtsmith-local-lab/scripts/mcp-token.sh"
    if not token_script.exists():
        return
    import re

    env = os.environ.copy()
    env.update(values)
    proc = subprocess.run([str(token_script)], capture_output=True, text=True, cwd=PROJECT_ROOT, env=env, check=False)
    out = proc.stdout + proc.stderr
    match = re.search(r"^SPLUNK_LAB_BEARER_TOKEN=(.+)$", out, re.M)
    if not match:
        return
    token = match.group(1).strip()
    write_env_file({"SPLUNK_LAB_BEARER_TOKEN": token}, UI_ENV_PATH)
    if not _docker_ui_running():
        return
    sync_py = f"""
import sys
sys.path[:0] = [".", "scripts"]
from runtime_config import write_env_file
write_env_file({{"SPLUNK_LAB_BEARER_TOKEN": {token!r}}})
"""
    subprocess.run(
        ["docker", "exec", "agtsmith-ui-deploy", "env", "PYTHONPATH=/app:/app/scripts", "python", "-c", sync_py],
        check=False,
    )


def _bootstrap_docker_ui_auth(user: str, password: str) -> None:
    bootstrap_py = f"""
import json
import sys

sys.path[:0] = [".", "scripts"]
from runtime_config import write_env_file
from web_ui_server import _hash_password

hashed = _hash_password({password!r})
write_env_file(
    {{
        "SOC_UI_AUTH_ENABLED": "1",
        "SOC_UI_AUTH_USERNAME": {user!r},
        "SOC_UI_AUTH_PASSWORD": hashed,
        "SOC_UI_AUTH_ROLE": "admin",
        "SOC_UI_AUTH_USERS_JSON": json.dumps(
            [{"username": {user!r}, "password": hashed, "role": "admin"}],
            separators=(",", ":"),
        ),
        "SOC_UI_AUTH_INITIALIZED": "1",
        "AGTSMITH_TEMPLATE_OVERRIDE": "always",
    }}
)
print("bootstrap_ok")
"""
    proc = subprocess.run(
        ["docker", "exec", "agtsmith-ui-deploy", "python", "-c", bootstrap_py],
        capture_output=True,
        text=True,
        check=False,
        cwd=PROJECT_ROOT,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(f"docker auth bootstrap failed: {detail}")
    subprocess.run(["docker", "restart", "agtsmith-ui-deploy"], check=True)
    deadline = time.time() + 45
    while time.time() < deadline:
        if _lab_up("http://127.0.0.1:8787"):
            return
        time.sleep(1)
    raise RuntimeError("agtsmith-ui-deploy did not become reachable after restart")


def _ensure_ui_auth(base_url: str, user: str, password: str) -> tuple[str, str]:
    boot_user = os.environ.get("AGTSMITH_E2E_USER", DEFAULT_E2E_USER)
    boot_pass = os.environ.get("AGTSMITH_E2E_PASS", DEFAULT_E2E_PASSWORD)

    for candidate_user, candidate_pass in (
        (boot_user, boot_pass),
        (user, password),
    ):
        if _try_urllib_login(base_url, candidate_user, candidate_pass):
            return candidate_user, candidate_pass

    if _docker_ui_running():
        _bootstrap_docker_ui_auth(boot_user, boot_pass)
        if _try_urllib_login(base_url, boot_user, boot_pass):
            return boot_user, boot_pass

    if _maybe_bootstrap_first_run(base_url, boot_user, boot_pass):
        if _try_urllib_login(base_url, boot_user, boot_pass):
            return boot_user, boot_pass

    _restart_ui_server(base_url)
    if _maybe_bootstrap_first_run(base_url, boot_user, boot_pass) and _try_urllib_login(base_url, boot_user, boot_pass):
        return boot_user, boot_pass

    if _try_urllib_login(base_url, user, password):
        return user, password

    raise RuntimeError("Unable to authenticate for investigation-e2e after bootstrap/restart")


def _lab_up(base_url: str) -> bool:
    try:
        with urllib.request.urlopen(f"{base_url.rstrip('/')}/login", timeout=3) as resp:
            return resp.status < 500
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def _login(page, base_url: str, user: str, password: str) -> None:
    page.goto(f"{base_url.rstrip('/')}/login", wait_until="domcontentloaded")
    if "/setup/first-run" in page.url:
        page.locator('input[name="username"]').fill(user)
        page.locator('select[name="role"]').select_option("admin")
        page.locator('input[name="password"]').first.fill(password)
        page.locator('input[name="confirm_password"]').fill(password)
        page.locator('button.setup-btn, button[type="submit"]').first.click()
        page.wait_for_url(lambda url: "/setup/first-run" not in url, timeout=15000)
        page.wait_for_load_state("networkidle")
        return

    user_input = page.locator('input[name="username"], input[name="user"], #username')
    pass_input = page.locator('input[name="password"], #password')
    user_input.first.fill(user)
    pass_input.first.fill(password)
    submit = page.locator('button[type="submit"], input[type="submit"]')
    if submit.count():
        submit.first.click()
    else:
        page.keyboard.press("Enter")
    try:
        page.wait_for_url(lambda url: "/login" not in url, timeout=15000)
    except Exception as exc:
        if page.locator(".login-error").count():
            msg = page.locator(".login-error").first.inner_text(timeout=2000)
            raise RuntimeError(f"Login failed: {msg.strip()}") from exc
        raise
    page.wait_for_load_state("networkidle")


def _extract_spl_from_output(page) -> str:
    try:
        spl_text = page.evaluate(
            """() => {
              try {
                const raw = document.getElementById('output')?.textContent || '';
                if (!raw.trim()) return '';
                const data = JSON.parse(raw);
                const result = data?.result || {};
                const direct = String(result.generated_spl || '').trim();
                if (direct) return direct;
                const details = Array.isArray(result.selected_spl_details) ? result.selected_spl_details : [];
                for (let i = details.length - 1; i >= 0; i -= 1) {
                  const query = String(details[i]?.query || '').trim();
                  if (query) return query;
                }
                return String(result.query_args?.query || '').trim();
              } catch (_) {
                return '';
              }
            }"""
        )
    except Exception:
        spl_text = ""
    return str(spl_text or "").strip()


def _assert_spl_panel(page, report: dict[str, object]) -> None:
    import re

    spl_panel = _spl_panel_locator(page)
    spl_panel.wait_for(state="attached", timeout=300000)
    spl_text = spl_panel.inner_text(timeout=5000).strip()
    if not spl_text or spl_text.startswith("(No Splunk query"):
        spl_text = _extract_spl_from_output(page)
    report["spl_query"] = spl_text
    if not spl_text or spl_text.startswith("(No Splunk query"):
        raise AssertionError("SPL panel empty after investigation run")
    lower = spl_text.lower()
    missing = [term for term in REQUIRED_SPL_TERMS if term.lower() not in lower]
    if missing:
        raise AssertionError(f"SPL missing required terms: {', '.join(missing)}")
    if REQUIRED_SPL_ANY_TERMS and not any(term.lower() in lower for term in REQUIRED_SPL_ANY_TERMS):
        raise AssertionError(f"SPL missing one of: {', '.join(REQUIRED_SPL_ANY_TERMS)}")
    forbidden_hits = [pattern for pattern in FORBIDDEN_SPL_PATTERNS if re.search(pattern, spl_text, flags=re.IGNORECASE | re.DOTALL)]
    if forbidden_hits:
        raise AssertionError(f"SPL matched forbidden patterns: {', '.join(forbidden_hits)}")


def main() -> int:
    base_url = os.environ.get("AGTSMITH_UI_URL", "http://127.0.0.1:8787")
    user, password = _resolve_e2e_credentials()
    out_root = Path(os.environ.get("SPL_AUTONOMY_OUT", str(DEFAULT_OUT_ROOT)))

    if not _lab_up(base_url):
        print(f"SKIP investigation-e2e: sidecar unreachable at {base_url}")
        return 0

    if not user or not password:
        print("SKIP investigation-e2e: AGTSMITH_UI_USER and AGTSMITH_UI_PASS required")
        return 0

    os.environ.setdefault("AGTSMITH_TEMPLATE_OVERRIDE", "always")

    try:
        _refresh_mcp_token_if_possible()
        user, password = _ensure_ui_auth(base_url, user, password)
    except Exception as exc:
        print(f"FAIL investigation-e2e auth bootstrap: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(
            "Install playwright: pip install -r .cursor/skills/agtsmith-screenshots/scripts/requirements.txt",
            file=sys.stderr,
        )
        return 1

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = out_root / "runs" / stamp
    run_dir.mkdir(parents=True, exist_ok=True)
    report_path = run_dir / "investigation_e2e_report.json"
    screenshot_path = run_dir / "investigation_e2e_failure.png"

    report: dict[str, object] = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "base_url": base_url,
        "question": FAILED_LOGON_QUESTION,
        "auth_user": user,
        "ok": False,
        "steps": [],
    }

    page = None
    browser = None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1920, "height": 1080})
            _login(page, base_url, user, password)
            report["steps"].append({"step": "login", "url": page.url})

            page.goto(f"{base_url.rstrip('/')}/investigation", wait_until="domcontentloaded")
            _question_locator(page).wait_for(timeout=10000)
            report["steps"].append({"step": "navigate_investigation", "url": page.url})

            question = _question_locator(page)
            question.fill(FAILED_LOGON_QUESTION)
            _run_locator(page).click()
            report["steps"].append({"step": "submit_question"})

            page.wait_for_function(
                """() => {
                  const status = (document.getElementById('status') || {}).textContent || '';
                  const readSplFromOutput = () => {
                    try {
                      const raw = document.getElementById('output')?.textContent || '';
                      if (!raw.trim()) return '';
                      const data = JSON.parse(raw);
                      const result = data?.result || {};
                      const direct = String(result.generated_spl || '').trim();
                      if (direct) return direct;
                      const details = Array.isArray(result.selected_spl_details) ? result.selected_spl_details : [];
                      for (let i = details.length - 1; i >= 0; i -= 1) {
                        const query = String(details[i]?.query || '').trim();
                        if (query) return query;
                      }
                      return String(result.query_args?.query || '').trim();
                    } catch (_) {
                      return '';
                    }
                  };
                  const outputSpl = readSplFromOutput();
                  if (outputSpl) return true;
                  const el = document.querySelector('[data-testid="spl-query-panel"]')
                    || document.querySelector('#spl-query')
                    || document.querySelector('#drawer-spl-query');
                  const text = el ? (el.textContent || '').trim() : '';
                  const hasSpl = text.length > 0 && !text.startsWith('(No Splunk query');
                  return hasSpl || status.includes('Complete');
                }""",
                timeout=600000,
            )
            state_text = _exec_state_locator(page).inner_text(timeout=5000)
            report["steps"].append({"step": "wait_complete", "run_state": state_text.strip()})

            toggle = page.locator("#spl-visibility-toggle")
            if toggle.count() and toggle.is_visible():
                toggle.click()
            _assert_spl_panel(page, report)
            report["ok"] = True
            browser.close()
            browser = None
    except Exception as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
        try:
            if page is not None:
                page.screenshot(path=str(screenshot_path), full_page=True)
                report["screenshot"] = str(screenshot_path.relative_to(PROJECT_ROOT))
        except Exception as shot_exc:
            report["screenshot_error"] = f"{type(shot_exc).__name__}:{shot_exc}"
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"FAIL investigation-e2e -> {report_path.relative_to(PROJECT_ROOT)}", file=sys.stderr)
        print(report["error"], file=sys.stderr)
        return 1
    finally:
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass

    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"OK  investigation-e2e report -> {report_path.relative_to(PROJECT_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
