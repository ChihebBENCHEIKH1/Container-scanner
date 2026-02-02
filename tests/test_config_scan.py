import unittest
from unittest.mock import MagicMock
from scanners.config_scan import ConfigScanner

class TestConfigScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = ConfigScanner()
        self.context = {}

    def test_running_as_root(self):
        # Mock an image object with User='0'
        image = MagicMock()
        image.attrs = {
            'Config': {
                'User': '0',
                'ExposedPorts': {},
                # No Healthcheck
            }
        }
        
        findings = self.scanner.scan(image, self.context)
        
        # Expecting: Root user (Medium), No Healthcheck (Low), Missing Maintainer (Low)
        self.assertEqual(len(findings), 3)
        
        root_finding = next((f for f in findings if f['description'] == "Running as root"), None)
        self.assertIsNotNone(root_finding)
        self.assertEqual(root_finding['severity'], "MEDIUM")

    def test_running_as_user(self):
        image = MagicMock()
        image.attrs = {
            'Config': {
                'User': '1000',
                'ExposedPorts': {},
                'Healthcheck': {'Test': ['CMD', 'ls']},
                'Labels': {'maintainer': 'The Dev'}
            }
        }
        findings = self.scanner.scan(image, self.context)
        # Should be empty assuming no exposed sensitive ports
        self.assertEqual(len(findings), 0)

    def test_sensitive_ports(self):
        image = MagicMock()
        image.attrs = {
            'Config': {
                'User': '1000',
                'ExposedPorts': {'22/tcp': {}},
                'Healthcheck': {'Test': ['CMD']},
                'Labels': {'maintainer': 'The Dev'}
            }
        }
        findings = self.scanner.scan(image, self.context)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['description'], 'Sensitive Port Exposed')
        self.assertEqual(findings[0]['severity'], 'HIGH')

    def test_env_secrets(self):
        image = MagicMock()
        image.attrs = {
            'Config': {
                'User': '1000',
                'Env': ['DB_PASSWORD=secret123', 'PATH=/usr/bin'],
                'Healthcheck': {'Test': ['CMD']},
                'Labels': {'maintainer': 'The Dev'}
            }
        }
        findings = self.scanner.scan(image, self.context)
        secret_finding = next((f for f in findings if "Potential Secret in Environment Variable" in f['description']), None)
        self.assertIsNotNone(secret_finding)
        self.assertEqual(secret_finding['severity'], "HIGH")

if __name__ == '__main__':
    unittest.main()
