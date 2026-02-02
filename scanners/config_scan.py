from typing import Dict, Any, List
from scanners.base import BaseScanner

class ConfigScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "ConfigScanner"

    def scan(self, image_obj: Any, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        config = image_obj.attrs.get('Config', {})
        
        # Check User
        user = config.get('User', '')
        if not user or user == '0' or user == 'root':
            findings.append({
                "scanner": self.name,
                "severity": "MEDIUM",
                "description": "Running as root",
                "details": f"User is set to '{user}'. It is best practice to run as a non-root user."
            })

        # Check Healthcheck
        # Healthcheck is usually in Config or ContainerConfig
        if 'Healthcheck' not in config:
            findings.append({
                "scanner": self.name,
                "severity": "LOW",
                "description": "No Healthcheck defined",
                "details": "Image does not define a HEALTHCHECK instruction."
            })

        # Check Exposed Ports
        exposed_ports = config.get('ExposedPorts', {})
        # Sensitive ports list (e.g., 22 SSH, 23 Telnet, 3306 MySQL, 5432 Postgres open to world)
        # Note: This is just checking what is EXPOSED in metadata, not what is mapped.
        SENSITIVE_PORTS = {'22/tcp', '23/tcp', '3389/tcp'}
        
        for port in exposed_ports:
            if port in SENSITIVE_PORTS:
                findings.append({
                    "scanner": self.name,
                    "severity": "HIGH",
                    "description": "Sensitive Port Exposed",
                    "details": f"Port {port} is exposed in the image config."
                })

        # Check Labels
        labels = config.get('Labels', {})
        if not labels or ('maintainer' not in labels and 'org.opencontainers.image.authors' not in labels):
            findings.append({
                "scanner": self.name,
                "severity": "LOW",
                "description": "Missing Maintainer Label",
                "details": "Image does not have a 'maintainer' or 'org.opencontainers.image.authors' label."
            })

        # Check Environment Variables for secrets
        env_vars = config.get('Env', [])
        SECRET_KEYWORDS = ['PASS', 'KEY', 'SECRET', 'TOKEN', 'AUTH']
        for env in env_vars:
            if any(keyword in env.upper() for keyword in SECRET_KEYWORDS):
                # Verify it's not just a path or something innocuous
                # usually env is in form KEY=VALUE
                findings.append({
                    "scanner": self.name,
                    "severity": "HIGH",
                    "description": "Potential Secret in Environment Variable",
                    "details": f"Found environment variable that may contain a secret: {env.split('=')[0]}"
                })

        return findings
