import argparse
import sys
from rich.console import Console
from rich.table import Table
from utils.docker_ops import get_docker_client, get_image

from scanners.config_scan import ConfigScanner
from scanners.sast_scan import SastScanner
from scanners.dast_scan import DastScanner

console = Console()

def run_scan(target_image, json_output=None):
    client = get_docker_client()
    if not client:
        sys.exit(1)

    image = get_image(client, target_image)
    if not image:
        console.print(f"[bold red]Could not find or pull image {target_image}[/bold red]")
        sys.exit(1)

    console.print(f"[bold green]Starting scan for {target_image} (ID: {image.short_id})[/bold green]")

    findings = []
    
    # Register scanners
    active_scanners = [
        ConfigScanner(), 
        SastScanner(), 
        DastScanner()
    ]
    # active_scanners = [ConfigScanner(), SastScanner(), DastScanner()]

    context = {"client": client, "image_name": target_image}

    if not active_scanners:
        console.print("[yellow]No scanners registered yet.[/yellow]")

    for scanner in active_scanners:
        try:
            console.print(f"Running {scanner.name}...")
            results = scanner.scan(image, context)
            findings.extend(results)
        except Exception as e:
            console.print(f"[bold red]Error running {scanner.name}:[/bold red] {e}")

    print_report(findings, json_output)

import json

def print_report(findings, json_output=None):
    if json_output:
        with open(json_output, 'w') as f:
            json.dump(findings, f, indent=2)
        console.print(f"[bold green]Report saved to {json_output}[/bold green]")
        return

    if not findings:
        console.print("\n[bold green]No issues found![/bold green]")
        return

    table = Table(title="Scan Results")
    table.add_column("Scanner", style="cyan")
    table.add_column("Severity", style="magenta")
    table.add_column("Issue", style="white")
    table.add_column("Details", style="dim")

    for f in findings:
        severity_style = "red" if f.get('severity') == 'HIGH' else "yellow" if f.get('severity') == 'MEDIUM' else "blue"
        table.add_row(
            f.get('scanner', 'Unknown'),
            f"[{severity_style}]{f.get('severity', 'UNKNOWN')}[/{severity_style}]",
            f.get('description', ''),
            f.get('details', '')
        )

    console.print("\n")
    console.print(table)

def main():
    parser = argparse.ArgumentParser(description="Modular Container Scanner")
    parser.add_argument("image", help="Target Docker image (e.g., nginx:latest)")
    parser.add_argument("--json", help="Output report to JSON file", default=None)
    args = parser.parse_args()

    run_scan(args.image, args.json)

if __name__ == "__main__":
    main()
