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

# ── Stage: core (default) ───────────────────────────────────────────────────
FROM base AS core

# Install as root (system-wide), then drop to non-root for runtime
RUN pip install --no-cache-dir .

USER appuser

# Bind to all interfaces so the port is reachable from the Docker host
ENV FLASK_HOST=0.0.0.0

EXPOSE 5000

VOLUME ["/app/output"]

ENTRYPOINT ["secopstm"]
CMD ["--server"]

# ── Stage: ai ───────────────────────────────────────────────────────────────
# All AI deps (litellm, chromadb, sentence-transformers) are required deps —
# already installed in the core stage. This stage adds:
#   - pre-downloaded embedding model (no HuggingFace download at runtime)
#   - fixed vector store path mountable via Docker named volume
FROM core AS ai

USER root

# Pre-download the embedding model into the image so it's available offline.
# HF_HUB_DISABLE_SYMLINKS_WARNING avoids a noisy warning on Windows hosts.
RUN HF_HUB_DISABLE_SYMLINKS_WARNING=1 \
    python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"

# Fixed vector store path — mountable via Docker named volume.
# secopstm --init-rag and the RAG service both respect this env var.
ENV SECOPSTM_VECTOR_STORE_DIR=/app/rag/vector_store

RUN mkdir -p /app/rag && chown appuser:appuser /app/rag

USER appuser

VOLUME ["/app/rag", "/app/output"]
