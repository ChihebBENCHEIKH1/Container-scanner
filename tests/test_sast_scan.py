import unittest
from unittest.mock import MagicMock, patch
import tarfile
import io
from scanners.sast_scan import SastScanner

class TestSastScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = SastScanner()
        self.mock_client = MagicMock()
        self.context = {'client': self.mock_client}
        self.mock_image = MagicMock()
        self.mock_image.id = "sha256:test"

    @patch('scanners.sast_scan.tarfile')
    @patch('scanners.sast_scan.tempfile')
    def test_secret_detection(self, mock_tempfile, mock_tarfile):
        # Setup Mock Container
        mock_container = MagicMock()
        self.mock_client.containers.create.return_value = mock_container
        mock_container.export.return_value = [b'chunk']
        
        # Setup Mock Tar
        # We need to mock tarfile.open -> yield mock_tar
        # mock_tar iterates yielding members
        
        mock_tar_obj = MagicMock()
        mock_member_secret = MagicMock()
        mock_member_secret.isfile.return_value = True
        mock_member_secret.name = "app/config.py"
        
        mock_file_content = io.BytesIO(b"api_key = 'AKIA1234567890123456'")
        mock_tar_obj.extractfile.return_value = mock_file_content
        
        # Iteration
        mock_tar_obj.__iter__.return_value = [mock_member_secret]
        
        mock_tarfile.open.return_value.__enter__.return_value = mock_tar_obj

        findings = self.scanner.scan(self.mock_image, self.context)
        
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['description'], "Potential Secret Found: AWS Access Key")
        self.assertIn("app/config.py", findings[0]['details'])

    def test_analysis_logic(self):
        # Direct test of _analyze_content
        findings = self.scanner._analyze_content("foo.py", b"password = 'supersecret'")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['description'], "Potential Secret Found: Generic Password")

if __name__ == '__main__':
    unittest.main()
