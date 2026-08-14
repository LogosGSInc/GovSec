from __future__ import annotations
from pathlib import Path
import click
from dep_keystone.parsers.requirements_txt import parse_requirements_txt
from dep_keystone.report import write_trust_bundle_artifacts

@click.group()
def main() -> None:
    """DEP.KEYSTONE — deterministic dependency verification and SBOM attestation."""
    pass

@main.command()
@click.argument("lockfile", type=click.Path(exists=True, path_type=Path))
@click.option("--project-name", default=None, help="Project name (defaults to parent dir).")
@click.option("--output-dir", default="out", show_default=True, help="Output directory.")
def verify(lockfile: Path, project_name: str | None, output_dir: str) -> None:
    """Verify a lockfile and emit trust bundle artifacts."""
    resolved_project = project_name or lockfile.parent.name or "unknown-project"
    if lockfile.name.endswith("requirements.txt"):
        dependencies = parse_requirements_txt(lockfile)
    else:
        raise click.ClickException(f"Unsupported: {lockfile.name}. Supported: requirements.txt")
    report = write_trust_bundle_artifacts(
        output_dir=output_dir, project_name=resolved_project,
        source_file=str(lockfile), dependencies=dependencies)
    color = {"verified": "green", "warning": "yellow", "failed": "red"}.get(report.status, "white")
    click.echo("")
    click.echo("  DEP.KEYSTONE  Trust Bundle")
    click.echo(f"  Project      {report.project_name}")
    click.echo(f"  Dependencies {report.dependency_count}")
    click.echo(f"  Trust Score  {report.trust_score}/100")
    click.secho(f"  Status       {report.status.upper()}", fg=color, bold=True)
    click.echo(f"  Manifest     {report.manifest_hash_sha256[:16]}...")
    if report.findings:
        click.echo(f"  Findings     {len(report.findings)}")
        for f in report.findings:
            fc = {"critical":"red","high":"red","medium":"yellow","low":"cyan","info":"white"}.get(f.severity,"white")
            click.secho(f"    [{f.severity.upper():8}] {f.code} — {f.message}", fg=fc)
    click.echo(f"  Output       {Path(output_dir).resolve()}/")
    click.echo("")
