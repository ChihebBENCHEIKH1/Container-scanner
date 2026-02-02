from abc import ABC, abstractmethod
from typing import Dict, Any, List

class BaseScanner(ABC):
    """
    Abstract base class for all scanner modules.
    """
    
    @abstractmethod
    def scan(self, image_obj: Any, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Perform the scan on the given image object.
        
        Args:
            image_obj: The docker image object (from docker SDK).
            context: Additional context data (e.g. temp dir, args).
            
        Returns:
            A list of dictionary results/findings.
            Example finding:
            {
                "scanner": "ConfigScanner",
                "severity": "HIGH",
                "description": "Running as root",
                "details": "User is set to 0"
            }
        """
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Returns the name of the scanner."""
        pass
