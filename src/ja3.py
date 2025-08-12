from __future__ import annotations

import hashlib
from typing import Iterable


def is_grease(value: int) -> bool:
    return (value & 0x0F0F) == 0x0A0A


def ja3_from_fields(
    tls_version: int,
    ciphers: Iterable[int],
    extensions: Iterable[int],
    groups: Iterable[int],
    ec_point_formats: Iterable[int],
) -> str:
    c = "-".join(str(x) for x in ciphers if not is_grease(x))
    e = "-".join(str(x) for x in extensions if not is_grease(x))
    g = "-".join(str(x) for x in groups if not is_grease(x))
    p = "-".join(str(x) for x in ec_point_formats)
    return f"{tls_version},{c},{e},{g},{p}"


def ja3_md5(ja3_string: str) -> str:
    return hashlib.md5(ja3_string.encode()).hexdigest()
