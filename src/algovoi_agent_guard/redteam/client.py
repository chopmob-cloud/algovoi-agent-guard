"""Provider-agnostic OpenAI-compatible chat client for the red-team adversary.

The adversary's creativity can come from any OpenAI-compatible endpoint — Qwen
(the funded default), Mistral, NVIDIA NIM, OpenAI, or a local server. The transport
is a plain ``/chat/completions`` call; provider differences are isolated in PRESETS
and a couple of quirks (Qwen reasoning models need ``enable_thinking=false``;
some providers return ``content`` as a list of blocks). Stdlib only; keys are read
from the environment or ``$HERMES_HOME/.env`` and are never logged.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: a 30x must not forward the Authorization header."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}

# name -> base URL, candidate key env vars (first non-empty wins), default model,
# and any provider quirk. "local" tolerates a missing key (dummy bearer).
PRESETS = {
    "qwen": {
        "base": "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
        "key_envs": ["ALIBABA_TOKEN_PLAN_API_KEY", "DASHSCOPE_API_KEY"],
        "model": "qwen4-max-preview",
        "enable_thinking": False,
    },
    "mistral": {
        "base": "https://api.mistral.ai/v1",
        "key_envs": ["MISTRAL_API_KEY"],
        "model": "mistral-large-latest",
        "enable_thinking": None,
    },
    "nim": {
        "base": "https://integrate.api.nvidia.com/v1",
        "key_envs": ["NVIDIA_API_KEY", "NIM_API_KEY"],
        "model": "moonshotai/kimi-k3.1-pro",
        "enable_thinking": None,
    },
    "openai": {
        "base": "https://api.openai.com/v1",
        "key_envs": ["OPENAI_API_KEY"],
        "model": "gpt-4o-mini",
        "enable_thinking": None,
    },
    "local": {
        "base": "http://localhost:8000/v1",
        "key_envs": ["LOCAL_API_KEY"],
        "model": "local-model",
        "enable_thinking": None,
    },
}


def _hermes_env_key(name: str) -> str:
    home = os.environ.get("HERMES_HOME") or os.path.join(
        os.path.expanduser("~"), "AppData", "Local", "hermes")
    path = os.path.join(home, ".env")
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if line.startswith(name + "="):
                    return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return ""


def resolve_key(key_envs, env=None) -> str:
    # Only fall back to the ambient $HERMES_HOME/.env when no explicit env was
    # injected; an injected (e.g. empty/test) env must not leak ambient secrets.
    use_ambient = env is None
    env = os.environ if env is None else env
    for name in key_envs:
        val = (env.get(name) or "").strip()
        if not val and use_ambient:
            val = _hermes_env_key(name)
        if val:
            return val
    return ""


def extract_json(text: str) -> dict:
    """Tolerantly pull the first balanced JSON object out of a model reply."""
    text = text.strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1] if text.count("```") >= 2 else text
        if text.startswith("json"):
            text = text[4:]
    start = text.find("{")
    if start < 0:
        raise ValueError("no JSON object in reply")
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start:i + 1])
    raise ValueError("unbalanced JSON object in reply")


def _content_text(content) -> str:
    # Some providers return content as a list of blocks (thinking beside text).
    if isinstance(content, list):
        return "".join(b.get("text", "") for b in content
                       if isinstance(b, dict) and b.get("type") == "text")
    return content or ""


class OpenAICompatClient:
    """Minimal OpenAI-compatible chat client. ``chat`` returns (content, model)."""

    def __init__(self, base_url: str, api_key: str, model: str,
                 enable_thinking=None, provider: str = "custom", timeout: int = 120):
        self.base = base_url.rstrip("/")
        self.key = api_key
        self.model = model
        self.enable_thinking = enable_thinking
        self.provider = provider
        self.timeout = timeout
        self.calls = 0

    def chat(self, messages, max_tokens: int = 2000, temperature: float = 0.9,
             enable_thinking=None, retries: int = 2):
        body = {"model": self.model, "messages": messages,
                "max_tokens": max_tokens, "temperature": temperature}
        et = self.enable_thinking if enable_thinking is None else enable_thinking
        if et is not None:
            body["enable_thinking"] = et
        data = json.dumps(body).encode()
        parsed = urlparse(self.base)
        if parsed.scheme != "https" and parsed.hostname not in _LOCAL_HOSTS:
            safe = f"{parsed.scheme}://{parsed.hostname or '?'}"
            raise RuntimeError(
                "refusing to send an API key over a non-https endpoint "
                f"({safe}); use https or a localhost server")
        opener = urllib.request.build_opener(_NoRedirect)
        last = None
        for attempt in range(retries + 1):
            req = urllib.request.Request(
                self.base + "/chat/completions", data=data,
                headers={"Authorization": f"Bearer {self.key}",
                         "Content-Type": "application/json"})
            try:
                with opener.open(req, timeout=self.timeout) as r:
                    j = json.loads(r.read())
                self.calls += 1
                return _content_text(j["choices"][0]["message"]["content"]), j.get("model", self.model)
            except urllib.error.HTTPError as ex:
                # Do not echo the response body: it can contain keys or PII that
                # would otherwise land unescaped in report.json / report.md.
                last = RuntimeError(f"HTTP {ex.code}")
                if ex.code in (429, 500, 502, 503) and attempt < retries:
                    time.sleep(2 * (attempt + 1))
                    continue
                raise last
            except (urllib.error.URLError, TimeoutError, KeyError) as ex:
                last = ex
                if attempt < retries:
                    time.sleep(2 * (attempt + 1))
                    continue
                raise
        raise RuntimeError("chat failed")  # pragma: no cover


def client_for(provider: str | None = None, model: str | None = None,
               base_url: str | None = None, api_key_env: str | None = None,
               env=None) -> OpenAICompatClient:
    """Resolve a client from a provider preset plus optional overrides.

    ``provider`` defaults to the funded Qwen lane. ``base_url``/``api_key_env``/
    ``model`` override the preset, so any OpenAI-compatible endpoint can be used
    even without a named preset.
    """
    name = (provider or "qwen").lower()
    if name not in PRESETS and not base_url:
        raise RuntimeError(
            f"unknown provider '{name}' (choose from {sorted(PRESETS)} or pass --base-url)")
    preset = PRESETS.get(name, {"base": base_url, "key_envs": [],
                                "model": "custom-model", "enable_thinking": None})
    base = base_url or preset["base"]
    if api_key_env:
        key_envs = [api_key_env]
    elif base_url and base.rstrip("/") != preset["base"].rstrip("/"):
        # A custom host must never implicitly receive a preset provider's key.
        key_envs = []
    else:
        key_envs = preset["key_envs"]
    key = resolve_key(key_envs, env)
    if not key:
        if name == "local":
            key = "not-needed"
        elif not key_envs:
            raise RuntimeError(
                "no API key for custom endpoint (pass --api-key-env to name one)")
        else:
            raise RuntimeError(
                f"no API key for provider '{name}' (set one of: {', '.join(key_envs)})")
    return OpenAICompatClient(
        base, key, model or preset["model"],
        enable_thinking=preset.get("enable_thinking"), provider=name)
