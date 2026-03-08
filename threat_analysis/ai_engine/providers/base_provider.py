# Copyright 2025 ellipse2v
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from abc import ABC, abstractmethod
from typing import AsyncGenerator, Dict, List, Optional


class BaseLLMProvider(ABC):
    @abstractmethod
    async def check_connection(self) -> bool:
        """Checks if the LLM provider is reachable and responsive."""
        pass

    @abstractmethod
    async def generate_threats(
        self,
        component: Dict,
        context: Dict,
    ) -> List[Dict]:
        """Generates STRIDE threats for a component."""
        pass

    @abstractmethod
    async def generate_attack_flow(
        self,
        threat: Dict,
        component: Dict,
        context: Dict,
    ) -> Dict:
        """Generates an Attack Flow STIX 2.1 for a threat."""
        pass

    @abstractmethod
    async def generate_markdown(
        self,
        prompt: str,
        markdown: Optional[str] = None,
    ) -> AsyncGenerator[str, None]:
        """Streams DSL Markdown from a natural language prompt.

        This is an async generator — callers must use ``async for chunk in ...``.
        Each yielded value is a string token from the LLM stream.
        """
        raise NotImplementedError
        yield  # pragma: no cover — makes this an abstract async generator
