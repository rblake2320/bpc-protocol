"""
bpc CLI — manage BPC pairs, rotate keys, query audit logs.

Commands:
    bpc pair register   Register a new pair with a BPC-protected server
    bpc pair list       List all saved pairs
    bpc pair info       Show details for a saved pair
    bpc pair rotate     Rotate the secret for a saved pair
    bpc pair revoke     Revoke a pair on the server
    bpc status          Check server health and threat score
    bpc audit           Query the server audit log
    bpc request         Make a one-off signed HTTP request
"""

import json
import sys
from typing import Optional

import click

from bpc_client.client import BPCClient, BPCError, BPCAuthError, BPCPairLockedError
from bpc_client.cli.config import get_config, set_config


@click.group()
@click.version_option(package_name="bpc-client")
def cli():
    """BPC (Bound Pair Credentials) — cryptographic device-binding for APIs."""
    pass


# ── bpc pair ──────────────────────────────────────────────────────────────────

@cli.group()
def pair():
    """Manage BPC pairs (register, rotate, revoke, list)."""
    pass


@pair.command("register")
@click.option("--url", required=True, help="Base URL of the BPC-protected server")
@click.option("--name", required=True, help="Human-readable name for this pair (e.g. 'my-laptop')")
@click.option("--secret", required=True, help="Pair secret (8-64 chars, must include upper, lower, digit, symbol)")
@click.option("--scope", default="read-write", type=click.Choice(["read", "read-write", "admin"]), help="Pair scope")
@click.option("--mode", default="development", type=click.Choice(["development", "production"]), help="Pair mode")
@click.option("--register-path", default="/bpc/register", help="Registration endpoint path")
def pair_register(url, name, secret, scope, mode, register_path):
    """Register a new BPC pair with a server."""
    click.echo(f"Registering pair '{name}' with {url} ...")
    try:
        client = BPCClient.register(
            base_url=url,
            name=name,
            secret=secret,
            scope=scope,
            mode=mode,
            register_path=register_path,
        )
        click.secho(f"✓ Pair registered successfully", fg="green")
        click.echo(f"  Pair ID : {client.pair_id}")
        click.echo(f"  Name    : {name}")
        click.echo(f"  Scope   : {scope}")
        click.echo(f"  Mode    : {mode}")
        click.echo(f"  Saved to: {BPCClient.PAIRS_FILE}")
    except BPCError as e:
        click.secho(f"✗ {e}", fg="red")
        sys.exit(1)


@pair.command("list")
def pair_list():
    """List all saved BPC pairs."""
    pairs = BPCClient._load_pairs_file()
    if not pairs:
        click.echo("No saved pairs. Run 'bpc pair register' to create one.")
        return
    click.echo(f"{'NAME':<20} {'PAIR ID':<30} {'SCOPE':<12} {'SERVER'}")
    click.echo("-" * 80)
    for name, data in pairs.items():
        click.echo(
            f"{name:<20} {data.get('pair_id','?'):<30} {data.get('scope','?'):<12} {data.get('base_url','?')}"
        )


@pair.command("info")
@click.argument("name")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def pair_info(name, as_json):
    """Show details for a saved pair."""
    pairs = BPCClient._load_pairs_file()
    if name not in pairs:
        click.secho(f"✗ No pair named '{name}'", fg="red")
        sys.exit(1)
    data = {k: v for k, v in pairs[name].items() if k != "private_key_pem"}
    if as_json:
        click.echo(json.dumps(data, indent=2))
    else:
        for k, v in data.items():
            click.echo(f"  {k:<20}: {v}")


@pair.command("rotate")
@click.argument("name")
@click.option("--new-secret", required=True, help="New secret for the pair")
@click.option("--url", help="Override base URL")
def pair_rotate(name, new_secret, url):
    """Rotate the secret for a saved pair."""
    try:
        client = BPCClient.load(name=name, base_url=url)
        new_client = client.rotate(new_secret=new_secret)
        click.secho(f"✓ Pair '{name}' rotated successfully", fg="green")
        click.echo(f"  Pair ID: {new_client.pair_id}")
    except BPCError as e:
        click.secho(f"✗ {e}", fg="red")
        sys.exit(1)


@pair.command("revoke")
@click.argument("name")
@click.option("--url", help="Override base URL")
@click.confirmation_option(prompt="Are you sure you want to revoke this pair?")
def pair_revoke(name, url):
    """Revoke a pair on the server and remove it locally."""
    try:
        client = BPCClient.load(name=name, base_url=url)
        client.revoke()
        click.secho(f"✓ Pair '{name}' revoked", fg="green")
    except BPCError as e:
        click.secho(f"✗ {e}", fg="red")
        sys.exit(1)


# ── bpc status ────────────────────────────────────────────────────────────────

@cli.command("status")
@click.option("--url", help="Server base URL (or set BPC_BASE_URL env var)")
@click.option("--name", help="Use saved pair's base URL")
@click.option("--json", "as_json", is_flag=True)
def status(url, name, as_json):
    """Check server health and anomaly threat score."""
    base_url = url
    if not base_url and name:
        pairs = BPCClient._load_pairs_file()
        base_url = pairs.get(name, {}).get("base_url")
    if not base_url:
        import os
        base_url = os.environ.get("BPC_BASE_URL")
    if not base_url:
        click.secho("✗ Provide --url, --name, or set BPC_BASE_URL", fg="red")
        sys.exit(1)

    import httpx
    try:
        r = httpx.get(f"{base_url.rstrip('/')}/bpc/health", timeout=10)
        data = r.json()
        if as_json:
            click.echo(json.dumps(data, indent=2))
        else:
            ok = data.get("ok", False)
            color = "green" if ok else "red"
            click.secho(f"{'✓' if ok else '✗'} Server: {'healthy' if ok else 'unhealthy'}", fg=color)
            if "threatScore" in data:
                score = data["threatScore"]
                score_color = "green" if score < 30 else ("yellow" if score < 70 else "red")
                click.secho(f"  Threat score: {score}/100", fg=score_color)
            if "activePairs" in data:
                click.echo(f"  Active pairs: {data['activePairs']}")
    except Exception as e:
        click.secho(f"✗ Could not reach server: {e}", fg="red")
        sys.exit(1)


# ── bpc audit ─────────────────────────────────────────────────────────────────

@cli.command("audit")
@click.option("--name", required=True, help="Saved pair name to authenticate with")
@click.option("--url", help="Override base URL")
@click.option("--limit", default=20, help="Number of audit entries to return")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON")
@click.option("--audit-path", default="/bpc/audit", help="Audit endpoint path")
def audit(name, url, limit, as_json, audit_path):
    """Query the server audit log (requires admin scope)."""
    try:
        client = BPCClient.load(name=name, base_url=url)
        resp = client.get(f"{audit_path}?limit={limit}")
        if resp.status_code != 200:
            click.secho(f"✗ Server returned {resp.status_code}: {resp.text}", fg="red")
            sys.exit(1)
        data = resp.json()
        if as_json:
            click.echo(json.dumps(data, indent=2))
        else:
            entries = data if isinstance(data, list) else data.get("entries", [])
            click.echo(f"{'TIMESTAMP':<26} {'EVENT':<20} {'PAIR ID':<30} {'RESULT'}")
            click.echo("-" * 90)
            for e in entries:
                ts = e.get("timestamp", e.get("createdAt", "?"))
                event = e.get("event", e.get("type", "?"))
                pid = e.get("pairId", e.get("pair_id", "?"))
                result = e.get("result", e.get("outcome", "?"))
                color = "green" if result in ("ok", "success", "pass") else "red"
                click.secho(f"{str(ts):<26} {event:<20} {pid:<30} {result}", fg=color)
    except BPCAuthError as e:
        click.secho(f"✗ Auth error: {e}", fg="red")
        sys.exit(1)
    except BPCError as e:
        click.secho(f"✗ {e}", fg="red")
        sys.exit(1)


# ── bpc request ───────────────────────────────────────────────────────────────

@cli.command("request")
@click.argument("method", type=click.Choice(["GET", "POST", "PUT", "PATCH", "DELETE"]))
@click.argument("path")
@click.option("--name", required=True, help="Saved pair name")
@click.option("--url", help="Override base URL")
@click.option("--body", help="Request body (JSON string)")
@click.option("--json", "as_json", is_flag=True, help="Pretty-print JSON response")
def request_cmd(method, path, name, url, body, as_json):
    """Make a one-off BPC-signed HTTP request."""
    try:
        client = BPCClient.load(name=name, base_url=url)
        kwargs = {}
        if body:
            kwargs["json"] = json.loads(body)
        resp = client.request(method, path, **kwargs)
        if as_json:
            try:
                click.echo(json.dumps(resp.json(), indent=2))
            except Exception:
                click.echo(resp.text)
        else:
            click.echo(f"HTTP {resp.status_code}")
            click.echo(resp.text)
    except BPCError as e:
        click.secho(f"✗ {e}", fg="red")
        sys.exit(1)


def main():
    cli()


if __name__ == "__main__":
    main()
