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

import os
import logging
# from langchain_community.document_loaders import ( # Removed for lazy loading
#     CSVLoader,
#     JSONLoader,
#     UnstructuredExcelLoader,
#     UnstructuredXMLLoader,
#     DirectoryLoader,
#     TextLoader,
# )
# from langchain_text_splitters import RecursiveCharacterTextSplitter # Removed for lazy loading
# from langchain_huggingface import HuggingFaceEmbeddings # Removed for lazy loading
# from langchain_community.vectorstores import Chroma # Removed for lazy loading
# from langchain_core.documents import Document # Removed for lazy loading

# Désactiver la télémétrie Chroma
os.environ["ANONYMIZED_TELEMETRY"] = "False"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define paths
DATA_SOURCE_DIR = "threat_analysis/external_data"
VECTOR_STORE_DIR = "threat_analysis/vector_store"

# Ensure the vector store directory exists
os.makedirs(VECTOR_STORE_DIR, exist_ok=True)

def load_documents():
    """Load documents from the data source directory using various loaders."""
    # Lazy imports for document loaders
    from langchain_community.document_loaders import (
        CSVLoader,
        JSONLoader,
        UnstructuredExcelLoader,
        UnstructuredXMLLoader,
        DirectoryLoader,
        TextLoader,
    )
    from langchain_core.documents import Document # Need Document here for type hinting if doc is used
    
    documents = []
    
    # Loader for JSONL files in cve2capec
    jsonl_loader = DirectoryLoader(
        os.path.join(DATA_SOURCE_DIR, "cve2capec"),
        glob="**/*.jsonl",
        loader_cls=TextLoader, # Reads JSONL as plain text lines
        show_progress=True,
        use_multithreading=True
    )
    documents.extend(jsonl_loader.load())

    # Load other file types from the root data directory
    file_loaders = {
        ".csv": CSVLoader,
        ".json": JSONLoader,
        ".xlsx": UnstructuredExcelLoader,
        ".xml": UnstructuredXMLLoader,
    }

    files_in_dir = os.listdir(DATA_SOURCE_DIR)
    for file_name in files_in_dir:
        file_path = os.path.join(DATA_SOURCE_DIR, file_name)
        if os.path.isfile(file_path):
            ext = os.path.splitext(file_name)[1]
            loader_class = file_loaders.get(ext)
            if loader_class:
                try:
                    logging.info(f"Loading {file_name} with {loader_class.__name__}")
                    if file_name == 'enterprise-attack.json':
                        # This file is large and complex. We extract specific fields to create meaningful documents.
                        loader = JSONLoader(file_path, jq_schema='.objects[] | select(.type != "relationship") | .name + ": " + .description', text_content=True)
                    elif ext == '.json':
                        # For other JSONs, convert the entire structure to string representation
                        loader = JSONLoader(file_path, jq_schema='.', text_content=False)
                    else:
                        loader = loader_class(file_path)

                    loaded_docs = loader.load()
                    documents.extend(loaded_docs)
                except Exception as e:
                    logging.error(f"Failed to load {file_name}: {e}")
    
    # Filter out empty or whitespace-only documents
    initial_count = len(documents)
    filtered_documents = [doc for doc in documents if isinstance(doc, Document) and doc.page_content and doc.page_content.strip()]
    logging.info(f"Filtered out {initial_count - len(filtered_documents)} empty or whitespace-only documents.")

    return filtered_documents

def main():
    """Main function to build the vector store."""
    logging.info("Starting vector store build process...")

    # Lazy imports for main function
    from langchain_text_splitters import RecursiveCharacterTextSplitter
    from langchain_chroma import Chroma # Use langchain_chroma for Chroma
    from threat_analysis.ai_engine.embedding_factory import get_embeddings
    import yaml

    # Load ai_config
    ai_config_path = "config/ai_config.yaml"
    with open(ai_config_path, 'r', encoding='utf-8') as f:
        ai_config = yaml.safe_load(f)

    # 1. Load and filter documents
    logging.info(f"Loading and filtering documents from {DATA_SOURCE_DIR}...")
    documents = load_documents()
    if not documents:
        logging.warning("No documents loaded after filtering. Exiting.")
        return
    logging.info(f"Loaded {len(documents)} valid documents.")

    # 2. Split documents into chunks
    logging.info("Splitting documents into chunks...")
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
    texts = text_splitter.split_documents(documents)
    logging.info(f"Split documents into {len(texts)} chunks.")

    # 3. Create embeddings
    logging.info("Creating embeddings...")
    embeddings = get_embeddings(ai_config)

    # 4. Create and persist the vector store
    logging.info(f"Creating and persisting Chroma vector store at '{VECTOR_STORE_DIR}'...")

    vector_store = Chroma.from_documents(
        documents=texts,
        embedding=embeddings,
        persist_directory=VECTOR_STORE_DIR
    )
    
    logging.info("Vector store build process completed successfully.")
    logging.info(f"Total vectors in store: {vector_store._collection.count()}")

if __name__ == "__main__":
    main()