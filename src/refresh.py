from __future__ import annotations

import json
import os
from typing import Any, Dict

import requests

CHROMIUM_DASH = "https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Windows&num=5"


def fetch_stable_versions() -> Dict[str, Any]:
    r = requests.get(CHROMIUM_DASH, timeout=15)
    r.raise_for_status()
    data = r.json()
    # Expect newest first; map to N, N-1, N-2
    versions = [d.get("version") for d in data if d.get("version")]
    return {
        "N": versions[0] if len(versions) > 0 else None,
        "N-1": versions[1] if len(versions) > 1 else None,
        "N-2": versions[2] if len(versions) > 2 else None,
    }


def write_versions_cache(target_dir: str, versions: Dict[str, Any]) -> str:
    os.makedirs(target_dir, exist_ok=True)
    path = os.path.join(target_dir, "stable_versions.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(versions, f, indent=2)
    return path
