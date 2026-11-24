"""Backward-compatible Qwen preset for the red-team adversary.

The adversary is now provider-agnostic (see ``client.py`` and ``adversary.py``);
``QwenClient`` remains as the funded default so existing callers and the ``qwen``
lane keep working, including the ``ALIBABA_TOKEN_PLAN_BASE_URL`` override and the
``env=`` injection used by tests. ``extract_json`` is re-exported. The key is never
logged or returned. Standalone: stdlib only.
"""
from __future__ import annotations

import os

from .client import PRESETS, OpenAICompatClient, extract_json

DEFAULT_MODEL = PRESETS["qwen"]["model"]
DEFAULT_BASE = PRESETS["qwen"]["base"]

__all__ = ["QwenClient", "extract_json", "DEFAULT_MODEL", "DEFAULT_BASE"]


def _load_env() -> dict:
    env = dict(os.environ)
    homes = []
    if os.environ.get("HERMES_HOME"):
        homes.append(os.environ["HERMES_HOME"])
    homes.append(os.path.join(os.path.expanduser("~"), "AppData", "Local", "hermes"))
    homes.append(os.path.join(os.path.expanduser("~"), ".hermes"))
    for home in homes:
        cand = os.path.join(home, ".env")
        if os.path.isfile(cand):
            with open(cand, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        env.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    return env


class QwenClient(OpenAICompatClient):
    def __init__(self, model: str = DEFAULT_MODEL, env: dict | None = None):
        e = env or _load_env()
        key = e.get("ALIBABA_TOKEN_PLAN_API_KEY") or e.get("DASHSCOPE_API_KEY")
        base = (e.get("ALIBABA_TOKEN_PLAN_BASE_URL") or DEFAULT_BASE).rstrip("/")
        if not key:
            raise RuntimeError("no Alibaba token-plan key (ALIBABA_TOKEN_PLAN_API_KEY)")
        super().__init__(base, key, model or DEFAULT_MODEL,
                         enable_thinking=False, provider="qwen")