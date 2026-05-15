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

FROM python:3.10-slim

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

# Install as root (system-wide), make config.js writable by appuser,
# then pre-download the embedding model so it's available offline.
RUN pip install --no-cache-dir . && \
    chown appuser:appuser /usr/local/lib/python3.10/site-packages/threat_analysis/server/static/js/config.js && \
    HF_HUB_DISABLE_SYMLINKS_WARNING=1 \
    python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"

# Fixed vector store path — mountable via Docker named volume.
# secopstm --init-rag and the RAG service both respect this env var.
ENV SECOPSTM_VECTOR_STORE_DIR=/app/rag/vector_store

# Bind to all interfaces so the port is reachable from the Docker host
ENV FLASK_HOST=0.0.0.0

RUN mkdir -p /app/rag && chown appuser:appuser /app/rag

USER appuser

EXPOSE 5000

VOLUME ["/app/rag", "/app/output"]

ENTRYPOINT ["secopstm"]
CMD ["--server"]
