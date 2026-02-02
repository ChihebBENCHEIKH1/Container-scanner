import unittest
from unittest.mock import MagicMock, patch
from scanners.dast_scan import DastScanner

class TestDastScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = DastScanner()
        self.mock_client = MagicMock()
        self.context = {'client': self.mock_client}
        self.mock_image = MagicMock()
        self.mock_image.id = "sha256:test"

    @patch('scanners.dast_scan.requests.get')
    def test_http_probe(self, mock_get):
        # Mock Container
        mock_container = MagicMock()
        self.mock_client.containers.run.return_value = mock_container
        
        # Mock Container Ports
        mock_container.attrs = {
            'NetworkSettings': {
                'Ports': {
                    '80/tcp': [{'HostPort': '8080'}]
                }
            }
        }
        
        # Mock HTTP Response (Insecure)
        mock_response = MagicMock()
        mock_response.headers = {'Server': 'nginx/1.0'} # Missing security headers
        mock_get.return_value = mock_response

        findings = self.scanner.scan(self.mock_image, self.context)
        
        self.assertEqual(len(findings), 2) # Missing Headers + Leaked Server
        
        missing_header_finding = next((f for f in findings if f['description'] == "Missing Security Headers"), None)
        self.assertIsNotNone(missing_header_finding)
        self.assertIn("Content-Security-Policy", missing_header_finding['details'])

        server_finding = next((f for f in findings if f['description'] == "Server Header Leaked"), None)
        self.assertIsNotNone(server_finding)

        # Ensure container was stopped
        mock_container.stop.assert_called_once()

    @patch('scanners.dast_scan.requests.get')
    def test_no_ports(self, mock_get):
        mock_container = MagicMock()
        self.mock_client.containers.run.return_value = mock_container
        mock_container.attrs = {'NetworkSettings': {'Ports': {}}} # No exposed ports
        
        findings = self.scanner.scan(self.mock_image, self.context)
        self.assertEqual(len(findings), 0)
        mock_get.assert_not_called()

if __name__ == '__main__':
    unittest.main()
