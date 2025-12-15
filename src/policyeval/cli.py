import json
import sys
import typer

from policyeval.scan.sast.sast import evaluate
from policyeval.policy import load_policy


app = typer.Typer(
    name="policyeval",
    help="Evaluate security scan results against policy rules",
    no_args_is_help=True,
)


@app.command()
def run(
    scan_type: str = typer.Argument(
        ...,
        help="Scan type (currently supported: sast)",
    ),
    policies: list[str] = typer.Argument(
        ...,
        help="One or more policy YAML files",
    ),
    results_file: str = typer.Argument(
        ...,
        help="Scan results JSON file",
    ),
):
    """
    Example:
      policyeval sast policy1.yaml policy2.yaml results.json
    """

    scan_type = scan_type.lower()

    if scan_type != "sast":
        typer.echo(
            json.dumps(
                {
                    "passed": False,
                    "error": f"Unsupported scan type: {scan_type}",
                }
            )
        )
        raise typer.Exit(code=1)

    # Load policies
    try:
        loaded_policies = [load_policy(p) for p in policies]
    except Exception as e:
        ...

    # Load results
    try:
        with open(results_file, "r") as f:
            results = json.load(f)
    except Exception as e:
        ...

    # Evaluate
    try:
        output = evaluate(results, loaded_policies)
        typer.echo(json.dumps(output, indent=2))
    except Exception as e:
        typer.echo(json.dumps({"passed": False, "error": str(e)}, indent=2))
        raise typer.Exit(code=1)

    # Exit code for CI
    sys.exit(1 if not output.get("passed") else 0)


if __name__ == "__main__":
    app()
