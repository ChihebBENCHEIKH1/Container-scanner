import requests
import time
from typing import Dict, Any, List
from scanners.base import BaseScanner
from rich.console import Console

console = Console()

class DastScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "DastScanner"

    def scan(self, image_obj: Any, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        client = context.get('client')
        
        if not client:
            return findings

        # Spin up container (ephemeral)
        # We publish all ports to random host ports
        
        container = None
        try:
            console.print("[blue]Starting ephemeral container for DAST...[/blue]")
            # Detached, auto-remove potentially? Better to remove manually to capture logs if needed.
            # Use publish_all_ports=True (-P)
            container = client.containers.run(
                image_obj.id, 
                detach=True, 
                publish_all_ports=True,
                remove=True # For now let docker handle cleanup
            )
            
            # Wait a tick for container to startup
            time.sleep(2) 
            container.reload()
            
            ports = container.attrs['NetworkSettings']['Ports']
            # Port mapping format: {'80/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '32768'}], ...}
            
            if not ports:
                console.print("[yellow]No ports exposed by container, skipping HTTP probe.[/yellow]")
                return findings

            for port_def, mappings in ports.items():
                if not mappings:
                    continue
                
                # Assume TCP
                if '/tcp' in port_def:
                    host_port = mappings[0]['HostPort']
                    self._probe_http(f"http://localhost:{host_port}", findings)

        except Exception as e:
            console.print(f"[red]Error during DAST scan: {e}[/red]")
        finally:
            if container:
                try:
                    container.stop()
                    # auto-removed if remove=True, but stopping is good practice
                except Exception:
                    pass

        return findings

    def _probe_http(self, url: str, findings: List[Dict[str, Any]]):
        try:
            # Short timeout to avoid hanging
            response = requests.get(url, timeout=3)
            headers = response.headers
            
            # Check Security Headers
            missing_headers = []
            if 'X-Content-Type-Options' not in headers:
                missing_headers.append('X-Content-Type-Options')
            if 'X-Frame-Options' not in headers:
                missing_headers.append('X-Frame-Options')
            if 'Content-Security-Policy' not in headers:
                missing_headers.append('Content-Security-Policy')
                
            if missing_headers:
                 findings.append({
                    "scanner": self.name,
                    "severity": "LOW",
                    "description": "Missing Security Headers",
                    "details": f"URL {url} is missing headers: {', '.join(missing_headers)}"
                })
            
            # Check Server Banner (Information Leakage)
            if 'Server' in headers:
                 findings.append({
                    "scanner": self.name,
                    "severity": "LOW",
                    "description": "Server Header Leaked",
                    "details": f"Server header returned: {headers['Server']}"
                })

        except requests.exceptions.RequestException:
            # Not an HTTP service or not reachable
            pass
