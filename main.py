#!/usr/bin/env python3
"""
CanaryNet — CLI entry point.

Usage:
  python main.py serve
  python main.py generate env
  python main.py canary list
  python main.py events list
  python main.py db init
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()


# ─── Root group ──────────────────────────────────────────────────────────────
@click.group()
def cli():
    """🍯 CanaryNet — Defensive threat detection system."""


# ─── serve ───────────────────────────────────────────────────────────────────
@cli.command()
@click.option("--host", default="0.0.0.0", show_default=True, help="Bind host")
@click.option("--port", default=8000, show_default=True, help="Bind port")
@click.option("--reload", is_flag=True, default=False, help="Enable auto-reload (dev)")
@click.option("--workers", default=1, show_default=True, help="Number of uvicorn workers")
def serve(host: str, port: int, reload: bool, workers: int):
    """Start the dashboard and webhook server."""
    import uvicorn

    console.print(
        Panel(
            f"[bold indigo]🍯 CanaryNet[/]\n"
            f"Listening on [cyan]http://{host}:{port}[/]\n"
            f"Docs: [cyan]http://{host}:{port}/api/docs[/]",
            title="Starting Server",
        )
    )
    uvicorn.run(
        "dashboard.app:app",
        host=host,
        port=port,
        reload=reload,
        workers=1 if reload else workers,
        log_level="info",
    )


# ─── generate group ──────────────────────────────────────────────────────────
@cli.group()
def generate():
    """Generate honeypot bait content."""


@generate.command("env")
@click.option("--token", default="SAMPLETOKEN", help="Canary token to embed")
@click.option("--output", default="bait.env", show_default=True, help="Output file path")
def generate_env(token: str, output: str):
    """Generate a .env bait file."""
    from collectors.bait_generator import BaitGenerator

    bg = BaitGenerator()
    content = bg.generate_env_file(token)
    Path(output).write_text(content, encoding="utf-8")
    console.print(f"[green]✓[/] Bait .env written to [cyan]{output}[/]")
    console.print("[yellow]⚠ Deploy only on infrastructure you own/control.[/]")


@generate.command("workflow")
@click.option("--token", default="SAMPLETOKEN", help="Canary token to embed")
@click.option("--output", default="deploy.yml", show_default=True)
def generate_workflow(token: str, output: str):
    """Generate a fake GitHub Actions workflow bait file."""
    from collectors.bait_generator import BaitGenerator

    bg = BaitGenerator()
    content = bg.generate_github_actions_file(token)
    Path(output).write_text(content, encoding="utf-8")
    console.print(f"[green]✓[/] Bait workflow written to [cyan]{output}[/]")


@generate.command("bundle")
@click.option("--output-dir", default="bait_bundle", show_default=True)
def generate_bundle(output_dir: str):
    """Generate a full bait file bundle."""
    from collectors.bait_generator import BaitGenerator

    tokens = {
        "env": "ENV_CANARY_TOKEN_001",
        "workflow": "WF_CANARY_TOKEN_002",
        "config": "CFG_CANARY_TOKEN_003",
        "pat": "PAT_CANARY_TOKEN_004",
        "api_doc": "API_CANARY_TOKEN_005",
    }
    bg = BaitGenerator()
    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console
    ) as prog:
        task = prog.add_task("Generating bait bundle…", total=None)
        files = bg.generate_bait_package(output_dir, tokens)
        prog.update(task, completed=True)

    console.print(f"\n[green]✓[/] Generated {len(files)} bait files in [cyan]{output_dir}/[/]")
    for f in files:
        console.print(f"  • {f}")
    console.print("\n[yellow]⚠ DEFENSIVE RESEARCH ONLY — Deploy on authorized infrastructure.[/]")


# ─── canary group ────────────────────────────────────────────────────────────
@cli.group()
def canary():
    """Manage canary tokens."""


@canary.command("list")
def canary_list():
    """List all canary tokens."""
    async def _run():
        from storage.database import get_session
        from collectors.canary import CanaryManager

        async with get_session() as db:
            mgr = CanaryManager(db)
            tokens = await mgr.list_tokens()

        table = Table(title="Canary Tokens", show_lines=True)
        table.add_column("Label", style="bold")
        table.add_column("Type", style="cyan")
        table.add_column("Hits", justify="right")
        table.add_column("Active")
        table.add_column("URL", style="dim")

        for t in tokens:
            table.add_row(
                t.label,
                t.bait_type,
                str(t.hit_count),
                "✅" if t.is_active else "❌",
                (t.url or "")[:60],
            )
        console.print(table)

    asyncio.run(_run())


@canary.command("create")
@click.argument("label")
@click.option("--bait-type", default="custom", show_default=True)
@click.option("--description", default=None)
def canary_create(label: str, bait_type: str, description: str | None):
    """Create a new canary token."""
    async def _run():
        from storage.database import get_session, init_db
        from collectors.canary import CanaryManager

        await init_db()
        async with get_session() as db:
            mgr = CanaryManager(db)
            token = await mgr.generate_token(label, bait_type, description)

        console.print(Panel(
            f"[bold]Label:[/] {token.label}\n"
            f"[bold]Token:[/] [cyan]{token.token}[/]\n"
            f"[bold]URL:[/] [underline]{token.url}[/]\n"
            f"[bold]Type:[/] {token.bait_type}",
            title="[green]✓ Canary Token Created[/]",
        ))

    asyncio.run(_run())


@canary.command("deactivate")
@click.argument("token_id")
def canary_deactivate(token_id: str):
    """Deactivate a canary token by ID."""
    async def _run():
        from storage.database import get_session
        from collectors.canary import CanaryManager

        async with get_session() as db:
            mgr = CanaryManager(db)
            ok = await mgr.deactivate_token(token_id)

        if ok:
            console.print(f"[green]✓[/] Token {token_id} deactivated.")
        else:
            console.print(f"[red]✗[/] Token not found: {token_id}")

    asyncio.run(_run())


# ─── events group ────────────────────────────────────────────────────────────
@cli.group()
def events():
    """View and export honeypot events."""


@events.command("list")
@click.option("--limit", default=20, show_default=True)
@click.option("--risk", default=None, help="Filter by risk level (low/medium/high/critical)")
def events_list(limit: int, risk: str | None):
    """List recent honeypot events."""
    async def _run():
        from storage.database import get_session
        from storage.models import HoneypotEvent
        from sqlalchemy import select

        async with get_session() as db:
            stmt = select(HoneypotEvent).order_by(HoneypotEvent.timestamp.desc()).limit(limit)
            if risk:
                stmt = stmt.where(HoneypotEvent.risk_level == risk)
            result = await db.execute(stmt)
            evs = result.scalars().all()

        _RISK_COLORS = {
            "low": "green", "medium": "yellow", "high": "dark_orange", "critical": "red"
        }
        table = Table(title=f"Recent Events (limit={limit})", show_lines=True)
        table.add_column("Timestamp", style="dim")
        table.add_column("Source IP", style="cyan")
        table.add_column("Risk")
        table.add_column("Type")
        table.add_column("Country")
        table.add_column("Score", justify="right")

        for e in evs:
            color = _RISK_COLORS.get(e.risk_level, "white")
            table.add_row(
                e.timestamp.strftime("%Y-%m-%d %H:%M:%S") if e.timestamp else "—",
                e.source_ip,
                f"[{color}]{e.risk_level}[/]",
                e.event_type,
                e.geo_country or "—",
                str(e.risk_score),
            )
        console.print(table)

    asyncio.run(_run())


@events.command("export")
@click.option("--format", "fmt", type=click.Choice(["json", "csv"]), default="json", show_default=True)
@click.option("--output", default=None, help="Output file path")
@click.option("--limit", default=10000, show_default=True)
def events_export(fmt: str, output: str | None, limit: int):
    """Export events to JSON or CSV."""
    async def _run():
        from storage.database import get_session
        from storage.models import HoneypotEvent
        from storage.exporter import export_events_json, export_events_csv, save_report
        from sqlalchemy import select

        async with get_session() as db:
            stmt = select(HoneypotEvent).order_by(HoneypotEvent.timestamp.desc()).limit(limit)
            result = await db.execute(stmt)
            evs = list(result.scalars().all())

        if fmt == "json":
            data = export_events_json(evs)
            ext = "json"
        else:
            data = export_events_csv(evs)
            ext = "csv"

        filename = output or f"events_export.{ext}"
        path = Path(filename)
        path.write_text(data, encoding="utf-8")
        console.print(f"[green]✓[/] Exported {len(evs)} events to [cyan]{path}[/]")

    asyncio.run(_run())


# ─── actors group ────────────────────────────────────────────────────────────
@cli.group()
def actors():
    """View actor profiles."""


@actors.command("list")
@click.option("--limit", default=20, show_default=True)
def actors_list(limit: int):
    """List actor profiles."""
    async def _run():
        from storage.database import get_session
        from storage.models import Actor
        from sqlalchemy import select

        async with get_session() as db:
            result = await db.execute(
                select(Actor).order_by(Actor.last_seen.desc()).limit(limit)
            )
            all_actors = result.scalars().all()

        table = Table(title="Actor Profiles", show_lines=True)
        table.add_column("IP Address", style="cyan")
        table.add_column("First Seen", style="dim")
        table.add_column("Hits", justify="right")
        table.add_column("Risk Level")
        table.add_column("Blocklisted")

        for a in all_actors:
            table.add_row(
                a.ip_address,
                a.first_seen.strftime("%Y-%m-%d") if a.first_seen else "—",
                str(a.total_hits),
                a.risk_level,
                "🚫 YES" if a.is_blocklisted else "—",
            )
        console.print(table)

    asyncio.run(_run())


@actors.command("blocklist")
@click.argument("ip")
def actors_blocklist(ip: str):
    """Toggle blocklist status for an IP address."""
    async def _run():
        from storage.database import get_session
        from storage.models import Actor
        from sqlalchemy import select

        async with get_session() as db:
            result = await db.execute(select(Actor).where(Actor.ip_address == ip))
            actor = result.scalar_one_or_none()
            if not actor:
                console.print(f"[yellow]No actor found for IP {ip}.[/]")
                return
            actor.is_blocklisted = not actor.is_blocklisted
            status = "blocklisted" if actor.is_blocklisted else "unblocked"
            console.print(f"[green]✓[/] {ip} is now [bold]{status}[/].")

    asyncio.run(_run())


# ─── db group ────────────────────────────────────────────────────────────────
@cli.group()
def db():
    """Database management commands."""


@db.command("init")
def db_init():
    """Initialize the database (create tables)."""
    async def _run():
        from storage.database import init_db

        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console
        ) as prog:
            t = prog.add_task("Initialising database…", total=None)
            await init_db()
            prog.update(t, completed=True)
        console.print("[green]✓[/] Database initialised.")

    asyncio.run(_run())


@db.command("stats")
def db_stats():
    """Show database statistics."""
    async def _run():
        from storage.database import get_session
        from storage.models import HoneypotEvent, Actor, CanaryToken, AlertLog
        from sqlalchemy import select, func

        async with get_session() as db_session:
            events_count = (await db_session.execute(select(func.count()).select_from(HoneypotEvent))).scalar()
            actors_count = (await db_session.execute(select(func.count()).select_from(Actor))).scalar()
            canaries_count = (await db_session.execute(select(func.count()).select_from(CanaryToken))).scalar()
            alerts_count = (await db_session.execute(select(func.count()).select_from(AlertLog))).scalar()

        console.print(Panel(
            f"[bold]Events:[/]   {events_count}\n"
            f"[bold]Actors:[/]   {actors_count}\n"
            f"[bold]Canaries:[/] {canaries_count}\n"
            f"[bold]Alerts:[/]   {alerts_count}",
            title="Database Stats",
        ))

    asyncio.run(_run())


if __name__ == "__main__":
    cli()
