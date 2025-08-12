from __future__ import annotations

import json
import os

import click

from .builder import build_client_hello
from .profiles import select_profile
from .refresh import fetch_stable_versions, write_versions_cache


@click.group()
def cli() -> None:
    """Chrome-Stable (N-2) uTLS template generator"""


@cli.command()
@click.option("--sni", required=True, help="Server Name Indication (hostname)")
@click.option(
    "--seed", type=int, default=1337, help="Deterministic seed for randomness/GREASE"
)
@click.option("--profile", default=None, help="Profile hint (e.g., stable-<major>)")
@click.option("--out-hex/--no-out-hex", default=True, help="Print hex of TLS record")
def generate(sni: str, seed: int, profile: str | None, out_hex: bool) -> None:
    prof = select_profile(profile)
    blob = build_client_hello(prof, sni=sni, seed=seed)
    out = {
        "sni": sni,
        "seed": seed,
        "profile": prof.version,
        "ja3": blob.ja3,
        "ja3_md5": blob.ja3_md5,
        "record_hex": blob.bytes_hex if out_hex else None,
    }
    click.echo(json.dumps(out, indent=2))


@cli.command()
def versions() -> None:
    versions = fetch_stable_versions()
    path = write_versions_cache(
        os.path.join(os.path.dirname(__file__), "cache"), versions
    )
    click.echo(json.dumps({"versions": versions, "cache": path}, indent=2))


@cli.command()
@click.option(
    "--impersonate",
    default="chrome_139",
    help="Impersonation profile (e.g., chrome_139)",
)
def test(impersonate: str) -> None:
    try:
        import tls_client
    except Exception as e:
        click.echo(
            json.dumps(
                {"ok": False, "error": f"tls-client import failed: {e}"}, indent=2
            )
        )
        raise SystemExit(1)

    session = tls_client.Session(
        client_identifier=impersonate, random_tls_extension_order=True
    )
    r = session.get(
        "https://tls.peet.ws/api/clean",
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome-Probe"
        },
        timeout_seconds=15,
    )
    try:
        data = json.loads(r.text)
    except Exception:
        data = {"raw": r.text}
    click.echo(
        json.dumps({"ok": True, "impersonate": impersonate, "peet": data}, indent=2)
    )


if __name__ == "__main__":
    cli()
