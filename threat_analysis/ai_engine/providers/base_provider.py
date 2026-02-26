from abc import ABC, abstractmethod
from typing import List, Dict

class BaseLLMProvider(ABC):
    @abstractmethod
    async def check_connection(self) -> bool:
        """Checks if the LLM provider is reachable and responsive."""
        pass

    @abstractmethod
    async def generate_threats(
        self,
        component: Dict,
        context: Dict
    ) -> List[Dict]:
        """Generates STRIDE threats for a component."""
        pass

    @abstractmethod
    async def generate_attack_flow(
        self,
        threat: Dict,
        component: Dict,
        context: Dict
    ) -> Dict:
        """Generates an Attack Flow STIX 2.1 for a threat."""
        pass
