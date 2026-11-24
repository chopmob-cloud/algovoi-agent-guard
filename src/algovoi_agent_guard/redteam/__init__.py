"""Autonomous red-team for the spend-authority guard (AI or human adversary)."""
from .adversary import (FileAdversary, FuzzAdversary, HumanAdversary,
                        ModelAdversary, make_adversary)
from .client import OpenAICompatClient, PRESETS
from .engine import AI_DISCLAIMER, run_redteam
from .qwen import QwenClient

__all__ = ["run_redteam", "AI_DISCLAIMER", "make_adversary", "ModelAdversary",
           "HumanAdversary", "FileAdversary", "FuzzAdversary",
           "OpenAICompatClient", "PRESETS", "QwenClient"]