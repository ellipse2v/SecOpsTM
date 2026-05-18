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

# ── Layer 1 : dépendances Python (reconstruite seulement si requirements.txt change) ──
# Séparer deps / code source permet de bénéficier du cache Docker sur les rebuilds
# de code source (cas le plus fréquent).
COPY requirements.txt ./
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -r requirements.txt

# ── Layer 2 : modèle d'embedding (reconstruite seulement si sentence-transformers change) ──
RUN HF_HUB_DISABLE_SYMLINKS_WARNING=1 \
    python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"

# ── Layer 3 : code source (change souvent — pip install --no-deps est quasi-instantané) ──
COPY --chown=appuser:appuser threat_analysis/ ./threat_analysis/
COPY --chown=appuser:appuser config/ ./config/
COPY --chown=appuser:appuser threatModel_Template/ ./threatModel_Template/
COPY --chown=appuser:appuser pyproject.toml README.md LICENSE ./

RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-deps . && \
    chown appuser:appuser /usr/local/lib/python3.10/site-packages/threat_analysis/server/static/js/config.js

# Fixed vector store path — mountable via Docker named volume.
# secopstm --init-rag and the RAG service both respect this env var.
ENV SECOPSTM_VECTOR_STORE_DIR=/app/rag/vector_store

# Bind to all interfaces so the port is reachable from the Docker host
ENV FLASK_HOST=0.0.0.0

# Suppress LiteLLM warnings about AWS Bedrock/SageMaker (botocore not installed)
ENV LITELLM_LOG=ERROR

RUN mkdir -p /app/rag && chown appuser:appuser /app/rag

USER appuser

EXPOSE 5000

VOLUME ["/app/rag", "/app/output"]

ENTRYPOINT ["secopstm"]
CMD ["--server"]
