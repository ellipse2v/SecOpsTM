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

# ── Stage: base ─────────────────────────────────────────────────────────────
FROM python:3.10-slim AS base

RUN apt-get update \
    && apt-get install -y --no-install-recommends graphviz \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash appuser
WORKDIR /app

# Copy source code and offline knowledge base
COPY --chown=appuser:appuser threat_analysis/ ./threat_analysis/
COPY --chown=appuser:appuser config/ ./config/
COPY --chown=appuser:appuser threatModel_Template/ ./threatModel_Template/
COPY --chown=appuser:appuser pyproject.toml README.md LICENSE ./

USER appuser

# ── Stage: core (default) ───────────────────────────────────────────────────
FROM base AS core

# Install runtime dependencies (no AI extras)
RUN pip install --no-cache-dir --user .

ENV PATH="/home/appuser/.local/bin:${PATH}"

EXPOSE 5000

VOLUME ["/app/output"]

ENTRYPOINT ["secopstm"]
CMD ["--server", "--port", "5000"]

# ── Stage: ai ───────────────────────────────────────────────────────────────
FROM core AS ai

# Install AI extras: litellm, chromadb, sentence-transformers
RUN pip install --no-cache-dir --user ".[ai]"

# ChromaDB vector store is large (~1.8 GB) — mount it at runtime
VOLUME ["/app/threat_analysis/vector_store", "/app/output"]

# Optional: override AI config at runtime
VOLUME ["/app/config/ai_config.yaml"]
