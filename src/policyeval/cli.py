import json
import typer
import sys
from pathlib import Path

app = typer.Typer(help="Policy Evaluator CLI - AccuKnox Style")

def load_json(path: str):
    file_path = Path(path)
    if not file_path.exists():
        typer.echo(f"File not found: {path}")
        sys.exit(2)
    return json.loads(file_path.read_text())

@app.command()
def evaluate(
    policy: str = typer.Option(..., "--policy", "-p", help="Policy JSON file"),
    scan: str = typer.Option(..., "--scan", "-s", help="Scan result JSON file"),
    output: str = typer.Option(None, "--output", "-o", help="Save result to file")
):
    policy_data = load_json(policy)
    scan_data = load_json(scan)

    conditions = policy_data.get("conditions", {})
    sev_rules = conditions.get("severities", {})

    failed = []

    for f in scan_data.get("findings", []):
        sev = f.get("severity", "").upper()
        if sev in sev_rules and sev_rules[sev] == "block":
            failed.append(f)

    result = {
        "policy": policy_data.get("policy_name", "N/A"),
        "status": "FAILED" if failed else "PASSED",
        "failed_count": len(failed),
        "failed_items": failed,
    }

    typer.echo(json.dumps(result, indent=2))

    if output:
        Path(output).write_text(json.dumps(result, indent=2))
        typer.echo(f"📄 Saved to {output}")

    sys.exit(1 if failed else 0)

if __name__ == "__main__":
    app()
