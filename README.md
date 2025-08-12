## Chrome-Stable (N-2) uTLS template generator

Generates deterministic, Chrome-like TLS ClientHello templates and related fingerprints. Aimed at producing reproducible uTLS-style ClientHello byte blobs that mimic Chrome Stable (current, N-1, N-2), along with the corresponding JA3/JA3 MD5, and self validation.

Commands:

- `generate` — build a deterministic ClientHello byte blob for a given SNI and Chrome Stable version (N, N-1, N-2).
  - `--sni` — Server Name Indication (hostname)
  - `--seed` — Deterministic seed for randomness/GREASE
  - `--profile` — Profile hint (e.g., stable-139)
  - `--out-hex` — Print hex of TLS record
- `test` — generate the ClientHello, compute JA3, and compare to the embedded profile JA3.
  - `--impersonate` — Impersonation profile (e.g., chrome_139)
- `versions` — discover Stable N, N-1, N-2 via Chromium Dash and update local profile pointers; attempts to fetch matching upstream profiles.

Usage:

```
pip install -r requirements.txt
python -m src.cli <command>
```
