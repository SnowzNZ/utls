from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from .profiles import ChromeTLSProfile


@dataclass
class ClientHelloBytes:
    bytes_hex: str
    seed: int
    sni: str
    profile_name: str
    ja3: str
    ja3_md5: str


def _hkdf_like(seed: int, label: bytes, out_len: int) -> bytes:
    # Deterministic derivation used to construct ClientRandom, SessionID, GREASE slots, etc.
    key = seed.to_bytes(8, "big")
    result = b""
    counter = 1
    while len(result) < out_len:
        result += hmac.new(
            key, label + counter.to_bytes(4, "big"), hashlib.sha256
        ).digest()
        counter += 1
    return result[:out_len]


def _tls_u16(x: int) -> bytes:
    return x.to_bytes(2, "big")


def _var_bytes(b: bytes) -> bytes:
    assert len(b) < 2**16
    return _tls_u16(len(b)) + b


def _grease(value_from_seed: int) -> int:
    # RFC 8701 GREASE: pick any 0x?a?a form
    v = ((value_from_seed & 0xF) << 12) | 0x0A0A
    return v


def build_client_hello(
    profile: ChromeTLSProfile, sni: str, seed: int = 1337
) -> ClientHelloBytes:
    # Deterministically fill GREASE slots and randomness
    grease_seed = _hkdf_like(seed, b"grease", 2)
    grease_val = _grease(int.from_bytes(grease_seed, "big"))

    client_random = _hkdf_like(seed, b"client-random", 32)
    session_id = _hkdf_like(seed, b"session-id", 32)

    # Cipher suites: replace GREASE placeholder 0x0a0a with derived grease_val
    ciphers = [grease_val if x == 0x0A0A else x for x in profile.cipher_suites]
    cipher_bytes = b"".join(_tls_u16(x) for x in ciphers)

    # Compression methods: null only
    comp = b"\x01\x00"

    # Extensions: build only those present in the profile, with plausible bodies
    built: dict[int, bytes] = {}

    def put(ext_type: int, body: bytes) -> None:
        built[ext_type] = _tls_u16(ext_type) + _var_bytes(body)

    for et in profile.extensions:
        if et == 0:  # server_name (SNI)
            sni_bytes = sni.encode()
            sni_list = b"\x00" + _tls_u16(len(sni_bytes)) + sni_bytes
            put(0, _var_bytes(sni_list))
        elif et == 23:  # extended_master_secret
            put(23, b"")
        elif et == 65281:  # renegotiation_info
            put(65281, b"\x00")
        elif et == 10:  # supported_groups
            groups = [x for x in profile.supported_groups]
            group_bytes = b"".join(_tls_u16(x) for x in groups)
            put(10, _var_bytes(group_bytes))
        elif et == 11:  # ec_point_formats
            epf = bytes([len(profile.ec_point_formats)]) + bytes(
                profile.ec_point_formats
            )
            put(11, epf)
        elif et == 16:  # ALPN
            alpn_list = b"".join([bytes([len(a)]) + a.encode() for a in profile.alpn])
            put(16, _var_bytes(alpn_list))
        elif et == 5:  # status_request
            put(5, b"\x01" + b"\x00\x00\x00\x00\x00")
        elif et == 35:  # session_ticket
            put(35, b"")
        elif et == 18:  # SCT
            put(18, b"")
        elif et == 51:  # key_share (x25519)
            keyshare_key = _hkdf_like(seed, b"keyshare-x25519", 32)
            keyshare_entry = _tls_u16(29) + _var_bytes(keyshare_key)
            put(51, _var_bytes(keyshare_entry))
        elif et == 43:  # supported_versions
            put(43, bytes([2 + 2]) + _tls_u16(0x0304) + _tls_u16(0x0303))
        elif et == 13:  # signature_algorithms
            sig_bytes = b"".join(_tls_u16(x) for x in profile.signature_algorithms)
            put(13, _var_bytes(sig_bytes))
        elif et == 45:  # psk_key_exchange_modes
            put(45, b"\x01\x01")
        elif et in (28, 27, 65037, 41):  # placeholders
            put(et, b"")
        else:
            # default empty for unknowns
            put(et, b"")

    # Assemble in the exact order provided by the profile
    ext_bytes = b"".join(built[t] for t in profile.extensions if t in built)
    ext_block = _var_bytes(ext_bytes)

    # Assemble ClientHello
    # Handshake record (TLSPlaintext): type=0x16 (handshake), version=0x0301 (legacy), len=...
    # ClientHello structure with legacy_version 0x0303
    legacy_version = b"\x03\x03"
    sid = bytes([len(session_id)]) + session_id
    cs_bytes = _var_bytes(cipher_bytes)
    ch_body = legacy_version + client_random + sid + cs_bytes + comp + ext_block
    # Handshake header: msg_type=1 (client_hello), length=3 bytes
    ch_header = b"\x01" + len(ch_body).to_bytes(3, "big")
    handshake = ch_header + ch_body
    # TLSPlaintext header
    record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake

    from .ja3 import ja3_from_fields, ja3_md5

    ja3_s = ja3_from_fields(
        tls_version=771,
        ciphers=ciphers,
        extensions=profile.extensions,
        groups=profile.supported_groups,
        ec_point_formats=profile.ec_point_formats,
    )
    return ClientHelloBytes(
        bytes_hex=record.hex(),
        seed=seed,
        sni=sni,
        profile_name=profile.name,
        ja3=ja3_s,
        ja3_md5=ja3_md5(ja3_s),
    )
