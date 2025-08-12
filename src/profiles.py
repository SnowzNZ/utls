from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# GREASE values set per RFC 8701: any value of form 0x?a?a
def is_grease(value: int) -> bool:
    return (value & 0x0F0F) == 0x0A0A


@dataclass
class ChromeTLSProfile:
    name: str
    version: str  # e.g. "stable-126"
    tls_version_min: int
    tls_version_max: int
    cipher_suites: List[int]
    extensions: List[int]
    supported_groups: List[int]
    ec_point_formats: List[int]
    signature_algorithms: List[int]
    alpn: List[str]
    ja3_expect: Optional[str] = None  # MD5 hex string
    metadata: Dict[str, Any] = field(default_factory=dict)

    def ja3_string(self) -> str:
        # JA3: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
        ciphers = "-".join(str(x) for x in self.cipher_suites if not is_grease(x))
        exts = "-".join(str(x) for x in self.extensions if not is_grease(x))
        groups = "-".join(str(x) for x in self.supported_groups if not is_grease(x))
        ec_pf = "-".join(str(x) for x in self.ec_point_formats)
        return f"{self.tls_version_max},{ciphers},{exts},{groups},{ec_pf}"

    def ja3_md5(self) -> str:
        s = self.ja3_string().encode()
        return hashlib.md5(s).hexdigest()

    def to_json(self) -> str:
        return json.dumps(self.__dict__, separators=(",", ":"))

    @staticmethod
    def from_json(data: str) -> "ChromeTLSProfile":
        obj = json.loads(data)
        return ChromeTLSProfile(**obj)


def default_profile() -> ChromeTLSProfile:
    # Conservative Chrome-like TLS 1.3-first profile. Extension and cipher order
    # mirrors modern Chrome family (subject to updates via refresh).
    # Numeric values are IANA IDs.
    return ChromeTLSProfile(
        name="chrome-stable-sample",
        version="stable-default",
        tls_version_min=769,  # TLS 1.0 (unused but present in JA3 field)
        tls_version_max=771,  # TLS 1.2 in JA3; TLS1.3 not part of JA3 version
        # Cipher order aligned to latest Chrome sample
        cipher_suites=[
            4865,
            4866,
            4867,
            49195,
            49199,
            49196,
            49200,
            52393,
            52392,
            49171,
            49172,
            156,
            157,
            47,
            53,
        ],
        # Extension order aligned to latest Chrome sample
        extensions=[
            43,
            65281,
            17613,
            5,
            10,
            0,
            11,
            16,
            45,
            13,
            35,
            18,
            65037,
            23,
            27,
            51,
        ],
        # Supported groups aligned to latest Chrome sample
        supported_groups=[
            4588,
            29,
            23,
            24,
        ],
        ec_point_formats=[0],  # uncompressed
        signature_algorithms=[
            0x0403,
            0x0804,
            0x0401,
            0x0503,
            0x0805,
            0x0501,
            0x0806,
            0x0601,
        ],
        alpn=["h2", "http/1.1"],
        ja3_expect="0542cc80f2db7ed592d0060fe85d03fe",
        metadata={
            "source": "embedded-default",
            "note": "Aligned to latest Chrome peet.ws JA3 sample",
        },
    )


def select_profile(version_hint: Optional[str]) -> ChromeTLSProfile:
    # For now, route everything to default. The refresh step can persist
    # remote profiles to disk and set version hints.
    return default_profile()
