import re
import tarfile
import tempfile
import os
import io
from typing import Dict, Any, List
from scanners.base import BaseScanner
from rich.console import Console

console = Console()

class SastScanner(BaseScanner):
    def __init__(self):
        self.secret_patterns = {
            "AWS Access Key": re.compile(r'AKIA[0-9A-Z]{16}'),
            "Private Key": re.compile(r'-----BEGIN PRIVATE KEY-----'),
            "Generic Password": re.compile(r'password\s*=\s*[\'"][^\'"]+[\'"]', re.IGNORECASE)
        }
        # Max file size to scan (1MB) to avoid memory issues
        self.MAX_FILE_SIZE = 1024 * 1024 

    @property
    def name(self) -> str:
        return "SastScanner"

    def scan(self, image_obj: Any, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        client = context.get('client')
        
        if not client:
            return findings

        # Create a container (don't start it) to export FS
        # Note: This is expensive. For MVP we scan a subset or use `export`.
        # Better: `docker create` -> `docker export` -> tar stream.
        
        try:
            container = client.containers.create(image_obj.id)
            try:
                # Export filesystem as tar stream
                # chunks = container.export()
                # Use a simpler approach: get_archive of /app or /usr/src/app if we knew where code is.
                # But generic scanner needs to check sensitive paths.
                # For safety/speed in this MVP, we will try to iterate stream in memory if possible 
                # or write to temp file. Writing to temp file is safer for tar.
                
                with tempfile.TemporaryFile() as tmp:
                    for chunk in container.export():
                        tmp.write(chunk)
                    tmp.seek(0)
                    
                    with tarfile.open(fileobj=tmp, mode='r|') as tar:
                        for member in tar:
                            if not member.isfile():
                                continue
                            
                            # Skip huge files or binaries roughly by extension/location
                            if self._should_skip(member.name):
                                continue

                            try:
                                f = tar.extractfile(member)
                                if f:
                                    # Read first N bytes
                                    content = f.read(self.MAX_FILE_SIZE)
                                    findings.extend(self._analyze_content(member.name, content))
                            except Exception as e:
                                # Start debug logging if needed
                                pass
            finally:
                container.remove()

        except Exception as e:
            console.print(f"[red]Error during SAST scan fs extraction: {e}[/red]")
            # Fallback or just logs

        return findings

    def _should_skip(self, filename: str) -> bool:
        # naive exclusion
        if filename.startswith('proc/') or filename.startswith('sys/') or filename.startswith('dev/'):
            return True
        if filename.endswith(('.so', '.pyc', '.o', '.bin', '.exe', '.dll')):
            return True
        return False

    def _analyze_content(self, filename: str, content: bytes) -> List[Dict[str, Any]]:
        findings = []
        try:
            text = content.decode('utf-8', errors='ignore')
        except:
            return []

        for name, pattern in self.secret_patterns.items():
            if pattern.search(text):
                findings.append({
                    "scanner": self.name,
                    "severity": "HIGH",
                    "description": f"Potential Secret Found: {name}",
                    "details": f"Found in file: {filename}"
                })
        
        # Package inventory check (simple presence)
        if filename.endswith("requirements.txt"):
             findings.append({
                "scanner": self.name,
                "severity": "INFO",
                "description": "Python Dependencies",
                "details": f"Found requirements.txt at {filename}"
            })
             
        return findings
