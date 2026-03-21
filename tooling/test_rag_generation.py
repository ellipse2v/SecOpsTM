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

import logging
import sys
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(project_root))

from threat_analysis.ai_engine.rag_service import RAGThreatGenerator

if __name__ == "__main__":
    # Example Usage
    # Ensure you have a vector store built and user_context.example.json present.
    # python tooling/build_vector_store.py
    # Then run this example.
    
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    example_threat_model = """
    # Threat Model for E-commerce Backend API

    ## System Overview
    The system is a Python Flask backend API serving an e-commerce platform. It handles user authentication, product catalog management, order processing, and payment integration (via a third-party service). Data is stored in a PostgreSQL database. Communication with the frontend is via RESTful API calls over HTTPS.

    ## Components
    - **Flask API**: Handles business logic, API endpoints.
    - **PostgreSQL Database**: Stores user data, product info, order history.
    - **Payment Gateway Integration**: External API for processing payments.
    - **Load Balancer/API Gateway**: Distributes traffic, provides initial security.
    """

    try:
        # Before running this, ensure:
        # 1. tooling/build_vector_store.py has been run successfully.
        # 2. config/user_context.example.json exists.
        # 3. An LLM provider (e.g., Ollama) is enabled in config/ai_config.yaml and accessible.
        rag_generator = RAGThreatGenerator(
            user_context_path="config/user_context.example.json",
            ai_config_path="config/ai_config.yaml"
        )
        threats = rag_generator.generate_threats(example_threat_model)
        print("\n--- Generated Threats ---")
        if threats:
            for i, threat in enumerate(threats):
                print(f"Threat {i+1}: {threat.get('name', 'N/A')}")
                print(f"  Description: {threat.get('description', 'N/A')}")
                print(f"  Source: {threat.get('source', 'N/A')}")
        else:
            print("No threats generated.")
    except Exception as e:
        logging.error(f"Failed to initialize or run RAGThreatGenerator: {e}")
