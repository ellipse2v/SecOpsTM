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

import asyncio
import json
import pytest
from unittest.mock import MagicMock, AsyncMock, patch, mock_open

from threat_analysis.server.ai_service import AIService

AI_CONFIG_WITH_RAG = """
ai_providers: {}
rag:
  enabled: true
"""

@pytest.fixture
def ai_service():
    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=AI_CONFIG_WITH_RAG)):
            return AIService(config_path="dummy_config.yaml")

def test_init_ai(ai_service):
    async def _run():
        with patch("threat_analysis.server.ai_service.LiteLLMProvider") as mock_provider_class, \
             patch("threat_analysis.server.ai_service.RAGThreatGenerator") as mock_rag:

            mock_provider = MagicMock()
            mock_provider.check_connection = AsyncMock(return_value=True)
            mock_provider_class.return_value = mock_provider

            await ai_service.init_ai()

            assert ai_service.ai_online is True
            mock_provider.check_connection.assert_awaited_once()
            mock_rag.assert_called_once()
    asyncio.run(_run())

def test_generate_markdown_from_prompt(ai_service):
    async def _run():
        ai_service.ai_online = True
        ai_service.provider = MagicMock()

        async def mock_gen(**kwargs):
            yield "chunk 1 "
            yield "chunk 2"

        ai_service.provider.generate_markdown.return_value = mock_gen()

        chunks = []
        async for chunk in ai_service.generate_markdown_from_prompt("test prompt", "existing markdown"):
            chunks.append(chunk)

        assert chunks == ["chunk 1 ", "chunk 2"]
        ai_service.provider.generate_markdown.assert_called_once()
    asyncio.run(_run())

def test_generate_markdown_from_prompt_sync(ai_service):
    ai_service.ai_online = True
    ai_service.provider = MagicMock()

    async def mock_gen(**kwargs):
        yield "chunk 1 "
        yield "chunk 2"

    ai_service.provider.generate_markdown.return_value = mock_gen()

    chunks = list(ai_service.generate_markdown_from_prompt_sync("test prompt"))
    assert chunks == ["chunk 1 ", "chunk 2"]

def test_enrich_with_ai_threats(ai_service):
    async def _run():
        ai_service.ai_online = True
        ai_service.provider = MagicMock()
        ai_service.provider.check_connection = AsyncMock(return_value=True)

        class MockElement:
            def __init__(self, name, description, stereotype):
                self.name = name
                self.description = description
                self.stereotype = stereotype
                self.threats = []

        actor = MockElement("Actor 1", "Actor desc", "Actor")

        # Mock threat model
        threat_model = MagicMock()
        threat_model.actors = [{'object': actor}]
        threat_model.servers = []
        threat_model.dataflows = []
        threat_model.tm.description = "System desc"

        threat_payload = {
            "title": "SQLi",
            "description": "SQL injection",
            "category": "Information Disclosure",
            "likelihood": "high",
            "business_impact": {"severity": "critical", "details": "bad"},
        }
        # Batch path (default): generate_threats_batch returns name→threats dict
        ai_service.provider.generate_threats_batch = AsyncMock(
            return_value={"Actor 1": [threat_payload]}
        )
        # Individual fallback path kept for completeness
        ai_service.provider.generate_threats = AsyncMock(return_value=[threat_payload])

        await ai_service._enrich_with_ai_threats(threat_model)

        assert len(actor.threats) == 1
        assert "SQLi" in actor.threats[0].description
    asyncio.run(_run())

def test_load_ai_config_not_found(ai_service):
    with patch("os.path.exists", return_value=False):
        config = ai_service._load_ai_config("nonexistent.yaml")
        assert config == {}

def test_load_ai_config_parse_error(ai_service):
    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data="{invalid: yaml")):
            config = ai_service._load_ai_config("bad.yaml")
            assert config == {}

def test_generate_rag_threats(ai_service):
    async def _run():
        ai_service.rag_generator = MagicMock()
        ai_service.rag_generator.generate_threats.return_value = [
            {"name": "RAG Threat", "description": "rag desc", "category": "Tampering", "likelihood": "high", "impact": "high"}
        ]

        threat_model = MagicMock()
        threat_model.tm.name = "Test TM"
        threat_model.tm.description = "Test desc"
        threat_model.actors = []
        threat_model.servers = []
        threat_model.dataflows = []

        threats = await ai_service._generate_rag_threats(threat_model)

        assert len(threats) == 1
        assert "RAG Threat" in threats[0].description
        assert threats[0].source == "LLM"
    asyncio.run(_run())

def test_enrich_with_ai_threats_rag_enabled(ai_service):
    async def _run():
        ai_service.ai_online = True
        ai_service.provider = MagicMock()
        ai_service.provider.check_connection = AsyncMock(return_value=True)
        ai_service.rag_generator = MagicMock()
        ai_service.rag_generator.generate_threats.return_value = []

        # Mock threat model
        threat_model = MagicMock()
        threat_model.actors = []
        threat_model.servers = []
        threat_model.dataflows = []
        threat_model.tm.description = "System desc"
        threat_model.tm.global_threats_llm = []

        await ai_service._enrich_with_ai_threats(threat_model)

        ai_service.rag_generator.generate_threats.assert_called_once()
    asyncio.run(_run())

def test_enrich_with_ai_threats_json_fallback(ai_service):
    async def _run():
        ai_service.ai_online = True
        ai_service.provider = MagicMock()
        ai_service.provider.check_connection = AsyncMock(return_value=True)

        class MockElement:
            def __init__(self, name, description, stereotype):
                self.name = name
                self.description = description
                self.stereotype = stereotype
                self.threats = []

        actor = MockElement("Actor 1", "Actor desc", "Actor")
        threat_model = MagicMock()
        threat_model.actors = [{'object': actor}]
        threat_model.servers = []
        threat_model.dataflows = []
        threat_model.tm.description = "System desc"

        threat_payload = {"title": "Fenced", "description": "desc"}
        ai_service.provider.generate_threats_batch = AsyncMock(
            return_value={"Actor 1": [threat_payload]}
        )
        ai_service.provider.generate_threats = AsyncMock(return_value=[threat_payload])

        await ai_service._enrich_with_ai_threats(threat_model)
        assert len(actor.threats) == 1
        assert "Fenced" in actor.threats[0].description
    asyncio.run(_run())


# ---------------------------------------------------------------------------
# SOC analyst persona tests
# ---------------------------------------------------------------------------

def _make_ai_threat(title="SQL Injection", category="Information Disclosure", target_name="DB"):
    """Minimal ExtendedThreat-like object with source='AI'."""
    t = MagicMock()
    t.source = "AI"
    t.SID = title
    t.description = f"(AI) {title}: some description"
    t.category = category
    t.ai_details = {
        "title": title,
        "description": "Root cause detail",
        "attack_scenario": "1. Attacker sends payload\n2. DB executes query",
    }
    target = MagicMock()
    target.name = target_name
    t.target = target
    return t


def _make_soc_threat_model(actors=None, servers=None, dataflows=None):
    """Minimal threat_model mock for SOC tests."""
    tm = MagicMock()
    tm.actors = actors if actors is not None else [{"name": "User", "object": MagicMock()}]
    tm.servers = servers if servers is not None else [{"name": "WebApp", "object": MagicMock()}]
    # boundaries as dict
    b_info = MagicMock()
    b_info.get = lambda k, d=None: {"isTrusted": False}.get(k, d)
    tm.boundaries = {"Internet": {"isTrusted": False}}
    df = MagicMock()
    df.source.name = "User"
    df.sink.name = "WebApp"
    df.protocol = "HTTPS"
    df.is_encrypted = True
    df.is_authenticated = True
    tm.dataflows = dataflows if dataflows is not None else [df]
    return tm


class TestCompressModelForSoc:
    def test_boundaries_and_flows(self):
        tm = _make_soc_threat_model()
        digest_str = AIService._compress_model_for_soc(tm)
        digest = json.loads(digest_str)
        assert any(b["name"] == "Internet" for b in digest["boundaries"])
        assert any("WebApp" in f for f in digest["flows"])

    def test_empty_model(self):
        tm = _make_soc_threat_model(actors=[], servers=[], dataflows=[])
        digest_str = AIService._compress_model_for_soc(tm)
        digest = json.loads(digest_str)
        assert digest["boundaries"] is not None
        assert digest["flows"] == []
        assert digest["components"] == []

    def test_actor_name_from_dict_with_name_key(self):
        tm = _make_soc_threat_model(actors=[{"name": "UserX", "object": MagicMock()}])
        digest_str = AIService._compress_model_for_soc(tm)
        digest = json.loads(digest_str)
        assert any(c["name"] == "UserX" for c in digest["components"])

    def test_actor_name_from_dict_with_object_key_only(self):
        obj = MagicMock()
        obj.name = "DerivedName"
        tm = _make_soc_threat_model(actors=[{"object": obj}])
        digest_str = AIService._compress_model_for_soc(tm)
        digest = json.loads(digest_str)
        assert any(c["name"] == "DerivedName" for c in digest["components"])

    def test_flow_caps_at_20(self):
        dfs = []
        for i in range(25):
            df = MagicMock()
            df.source.name = f"Src{i}"
            df.sink.name = f"Dst{i}"
            df.protocol = "HTTP"
            df.is_encrypted = False
            df.is_authenticated = False
            dfs.append(df)
        tm = _make_soc_threat_model(dataflows=dfs)
        digest = json.loads(AIService._compress_model_for_soc(tm))
        assert len(digest["flows"]) == 20

    def test_encrypted_flag_in_flow(self):
        df = MagicMock()
        df.source.name = "A"
        df.sink.name = "B"
        df.protocol = "SQL"
        df.is_encrypted = True
        df.is_authenticated = False
        tm = _make_soc_threat_model(dataflows=[df])
        digest = json.loads(AIService._compress_model_for_soc(tm))
        assert "+enc" in digest["flows"][0]

    def test_auth_flag_in_flow(self):
        df = MagicMock()
        df.source.name = "A"
        df.sink.name = "B"
        df.protocol = "SQL"
        df.is_encrypted = False
        df.is_authenticated = True
        tm = _make_soc_threat_model(dataflows=[df])
        digest = json.loads(AIService._compress_model_for_soc(tm))
        assert "+auth" in digest["flows"][0]


@pytest.fixture
def soc_ai_service():
    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data="ai_providers: {}\n")):
            svc = AIService(config_path="dummy.yaml")
    svc.ai_online = True
    svc._ai_semaphore = asyncio.Semaphore(1)
    return svc


class TestEnrichWithSocAnalysis:
    def test_skips_when_offline(self, soc_ai_service):
        soc_ai_service.ai_online = False
        soc_ai_service.provider = MagicMock()
        tm = _make_soc_threat_model()
        asyncio.run(soc_ai_service._enrich_with_soc_analysis(tm))
        soc_ai_service.provider.generate_soc_analysis.assert_not_called()

    def test_skips_when_no_ai_threats(self, soc_ai_service):
        soc_ai_service.provider = MagicMock()
        soc_ai_service.provider.generate_soc_analysis = AsyncMock(return_value=[])
        tm = _make_soc_threat_model()
        # actors/servers have no threats
        obj = MagicMock()
        obj.threats = []
        tm.actors = [{"name": "U", "object": obj}]
        tm.servers = []
        tm.dataflows = []
        # boundaries with no boundary object
        tm.boundaries = {"B": {"isTrusted": True}}
        asyncio.run(soc_ai_service._enrich_with_soc_analysis(tm))
        soc_ai_service.provider.generate_soc_analysis.assert_not_called()

    def test_soc_analysis_stored_on_threat(self, soc_ai_service):
        async def _run():
            threat = _make_ai_threat("SQLi")
            obj = MagicMock()
            obj.threats = [threat]
            tm = _make_soc_threat_model(actors=[{"name": "U", "object": obj}])
            tm.servers = []
            tm.dataflows = []
            tm.boundaries = {"B": {"isTrusted": True, "boundary": None}}

            soc_result = [{
                "threat_id": "t-0",
                "detectability": "medium",
                "missing_logs": ["Sysmon Event 1"],
                "siem_rules": [{"title": "Rule", "logic": "EventID=1"}],
                "iocs": ["evil.exe"],
            }]
            soc_ai_service.provider = MagicMock()
            soc_ai_service.provider.generate_soc_analysis = AsyncMock(return_value=soc_result)

            await soc_ai_service._enrich_with_soc_analysis(tm)

            assert threat.ai_details["soc_analysis"]["detectability"] == "medium"
            assert threat.ai_details["soc_analysis"]["missing_logs"] == ["Sysmon Event 1"]
            assert threat.ai_details["soc_analysis"]["iocs"] == ["evil.exe"]
        asyncio.run(_run())

    def test_non_ai_threats_are_ignored(self, soc_ai_service):
        async def _run():
            pytm_threat = MagicMock()
            pytm_threat.source = "pytm"
            obj = MagicMock()
            obj.threats = [pytm_threat]
            tm = _make_soc_threat_model(actors=[{"name": "U", "object": obj}])
            tm.servers = []
            tm.dataflows = []
            tm.boundaries = {}

            soc_ai_service.provider = MagicMock()
            soc_ai_service.provider.generate_soc_analysis = AsyncMock(return_value=[])

            await soc_ai_service._enrich_with_soc_analysis(tm)
            # No SOC call because no AI threats
            soc_ai_service.provider.generate_soc_analysis.assert_not_called()
        asyncio.run(_run())

    def test_provider_error_is_silenced(self, soc_ai_service):
        async def _run():
            threat = _make_ai_threat("T1")
            obj = MagicMock()
            obj.threats = [threat]
            tm = _make_soc_threat_model(actors=[{"name": "U", "object": obj}])
            tm.servers = []
            tm.dataflows = []
            tm.boundaries = {}

            soc_ai_service.provider = MagicMock()
            soc_ai_service.provider.generate_soc_analysis = AsyncMock(
                side_effect=RuntimeError("LLM timeout")
            )

            # Must not raise
            await soc_ai_service._enrich_with_soc_analysis(tm)
            # Threat should not have soc_analysis
            assert "soc_analysis" not in (threat.ai_details or {})
        asyncio.run(_run())

    def test_bad_provider_response_type_is_silenced(self, soc_ai_service):
        async def _run():
            threat = _make_ai_threat("T1")
            obj = MagicMock()
            obj.threats = [threat]
            tm = _make_soc_threat_model(actors=[{"name": "U", "object": obj}])
            tm.servers = []
            tm.dataflows = []
            tm.boundaries = {}

            soc_ai_service.provider = MagicMock()
            soc_ai_service.provider.generate_soc_analysis = AsyncMock(
                return_value={"unexpected": "dict"}  # not a list
            )

            await soc_ai_service._enrich_with_soc_analysis(tm)
            assert "soc_analysis" not in (threat.ai_details or {})
        asyncio.run(_run())

    def test_batching_splits_threats(self, soc_ai_service):
        async def _run():
            threats = [_make_ai_threat(f"T{i}") for i in range(10)]
            obj = MagicMock()
            obj.threats = threats
            tm = _make_soc_threat_model(actors=[{"name": "U", "object": obj}])
            tm.servers = []
            tm.dataflows = []
            tm.boundaries = {}

            calls = []
            async def _mock_soc(batch_prompt, system_prompt):
                parsed = json.loads(batch_prompt.split("## Threats to Analyze\n")[1].split("\n---")[0])
                calls.append(len(parsed))
                return [{"threat_id": t["id"], "detectability": "low", "missing_logs": [], "siem_rules": [], "iocs": []} for t in parsed]

            soc_ai_service.provider = MagicMock()
            soc_ai_service.provider.generate_soc_analysis = _mock_soc
            await soc_ai_service._enrich_with_soc_analysis(tm, batch_size=4)
            assert len(calls) == 3  # 10 threats / 4 per batch → 3 batches
            assert sum(calls) == 10
        asyncio.run(_run())
