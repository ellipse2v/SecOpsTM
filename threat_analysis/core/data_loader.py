#!/usr/bin/env python
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

"""
This module is responsible for loading and parsing external threat data files.
"""

import pandas as pd
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import defaultdict


def load_attack_techniques() -> Dict[str, Dict[str, Any]]:
    """Loads all ATT&CK techniques from the enterprise-attack.json file."""
    techniques = {}
    stix_path = Path(__file__).parent.parent / 'external_data' / 'enterprise-attack.json'
    try:
        with open(stix_path, 'r', encoding='utf-8') as f:
            stix_data = json.load(f)
        
        for obj in stix_data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                external_id = next((ref['external_id'] for ref in obj.get('external_references', []) if ref.get('source_name') == 'mitre-attack'), None)
                if external_id:
                    techniques[external_id] = {
                        "id": external_id,
                        "name": obj.get("name"),
                        "description": obj.get("description"),
                        "url": next((ref['url'] for ref in obj.get('external_references', []) if ref.get('source_name') == 'mitre-attack'), None),
                        "tactics": [phase['phase_name'].replace('-', ' ').title() for phase in obj.get('kill_chain_phases', []) if phase.get('kill_chain_name') == 'mitre-attack']
                    }
    except FileNotFoundError:
        logging.error(f"Error: STIX data file not found at {stix_path}.")
    except Exception as e:
        logging.error(f"Error processing STIX data file: {e}")
    logging.info(f"Successfully loaded {len(techniques)} ATT&CK techniques into the dictionary.")
    return techniques


def load_capec_to_mitre_mapping() -> Dict[str, List[Dict[str, Any]]]:
    """Initializes CAPEC to MITRE ATT&CK mapping from the structured JSON file."""
    capec_to_mitre = {}
    json_path = Path(__file__).parent.parent / 'external_data' / 'capec_to_mitre_structured_mapping.json'
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            structured_data = json.load(f)
        
        all_techniques = set()
        for capec_entry in structured_data:
            capec_id = capec_entry.get('capec_id')
            techniques = capec_entry.get('techniques', [])
            
            if not capec_id:
                continue

            technique_objects = [
                tech for tech in techniques 
                if tech.get('taxonomy') == 'ATT&CK' and tech.get('id')
            ]
            
            if technique_objects:
                capec_to_mitre[capec_id] = technique_objects
                all_techniques.update([tech['id'] for tech in technique_objects])

        logging.info(f"Successfully loaded CAPEC->MITRE mapping. "
                      f"Found {len(capec_to_mitre)} CAPEC entries "
                      f"mapped to a total of {len(all_techniques)} unique ATT&CK techniques.")

    except FileNotFoundError:
        logging.error(f"Error: CAPEC to MITRE JSON mapping file not found at {json_path}. "
                      f"Please run 'tooling/capec_to_mitre_builder.py' to generate it.")
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON from {json_path}. The file might be corrupt.")
    except Exception as e:
        logging.error(f"Error processing CAPEC to MITRE JSON mapping file: {e}")
        
    return capec_to_mitre



def load_stride_to_capec_map() -> Dict[str, List[Dict[str, str]]]:
    """Loads the STRIDE to CAPEC mapping from the JSON file."""
    capec_mapping_path = Path(__file__).parent.parent / 'external_data' / 'stride_to_capec.json'
    try:
        with open(capec_mapping_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        logging.error(f"Error: stride_to_capec.json not found at {capec_mapping_path}.")
        return {}
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON from {capec_mapping_path}.")
        return {}

def load_d3fend_mapping() -> Dict[str, Dict[str, str]]:
    """
    Initializes D3FEND mitigations by loading from d3fend.csv.
    
    Returns:
        Dict[str, Dict[str, str]]: Dictionary mapping D3FEND IDs to their details.
            Format: {
                "D3F-ID": {
                    "name": "D3FEND Technique Name",
                    "description": "Technique description",
                    "url_name": "D3FENDTechniqueForURL"
                }
            }
    
    Raises:
        None: Errors are logged but not raised to ensure graceful degradation.
    """
    d3fend_details = {}
    csv_file_path = Path(__file__).parent.parent / 'external_data' / 'd3fend.csv'
    
    try:
        # File validation
        if not csv_file_path.exists():
            logging.warning(f"D3FEND CSV file not found at {csv_file_path}")
            return d3fend_details
        
        if csv_file_path.stat().st_size == 0:
            logging.warning(f"D3FEND CSV file is empty: {csv_file_path}")
            return d3fend_details
        
        # Loading with more specific error handling
        try:
            df = pd.read_csv(csv_file_path, encoding='utf-8')
        except UnicodeDecodeError:
            # Fallback for files with different encoding
            df = pd.read_csv(csv_file_path, encoding='latin-1')
            logging.info("Used latin-1 encoding for d3fend.csv")
        
        # Required columns validation
        required_columns = ['ID', 'Definition']
        technique_cols = ["D3FEND Technique", "D3FEND Technique Level 0", "D3FEND Technique Level 1"]
        
        # Check for at least one technique column
        if not any(col in df.columns for col in technique_cols):
            logging.error(f"Missing any of the D3FEND technique name columns in d3fend.csv: {technique_cols}")
            return d3fend_details

        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            logging.error(f"Missing required columns in d3fend.csv: {missing_columns}")
            return d3fend_details
        
        if df.empty:
            logging.warning("D3FEND CSV file contains no data rows")
            return d3fend_details
        
        # Data processing with validation
        for index, row in df.iterrows():
            try:
                d3fend_id = _clean_string(row['ID'])
                if not d3fend_id:
                    logging.warning(f"Empty or invalid ID at row {index + 1}, skipping")
                    continue
                
                # Determine the name for display from the main technique column if it exists
                d3fend_name = d3fend_id
                if 'D3FEND Technique' in df.columns and pd.notna(row['D3FEND Technique']):
                    d3fend_name = _clean_string(row['D3FEND Technique'])

                # Determine the name for the URL by finding the first available technique column
                url_name_part = ''
                for col in technique_cols:
                    if col in df.columns and pd.notna(row[col]) and _clean_string(row[col]):
                        url_name_part = _clean_string(row[col])
                        break # Found the first non-empty value
                
                d3fend_description = (_clean_string(row['Definition']) 
                                    if 'Definition' in df.columns and pd.notna(row['Definition']) 
                                    else "")
                
                d3fend_details[d3fend_id] = {
                    "name": d3fend_name,
                    "description": d3fend_description,
                    "url_name": url_name_part
                }
                
            except Exception as row_error:
                logging.warning(f"Error processing row {index + 1}: {row_error}")
                continue
        
        logging.info(f"Successfully loaded {len(d3fend_details)} D3FEND techniques from {csv_file_path}")
        
    except pd.errors.EmptyDataError:
        logging.error(f"D3FEND CSV file is empty or corrupted: {csv_file_path}")
    except pd.errors.ParserError as e:
        logging.error(f"Error parsing D3FEND CSV file: {e}")
    except PermissionError:
        logging.error(f"Permission denied accessing D3FEND CSV file: {csv_file_path}")
    except Exception as e:
        logging.error(f"Unexpected error loading d3fend.csv: {e}")
    
    return d3fend_details


def _clean_string(value: Optional[str]) -> str:
    """
    Cleans and validates a string value.
    
    Args:
        value: Value to clean
        
    Returns:
        str: Cleaned string or empty string if invalid
    """
    if pd.isna(value) or value is None:
        return ""
    
    cleaned = str(value).strip()
    return cleaned if cleaned and cleaned.lower() not in ['nan', 'null', 'none'] else ""


def load_nist_mappings() -> Dict[str, List[Dict[str, str]]]:
    """
    Loads NIST 800-53 R5 mappings from the local Excel file.
    Maps ATT&CK Technique IDs to NIST control details.
    """
    nist_mappings = defaultdict(list)
    excel_path = Path(__file__).parent.parent / 'external_data' / "nist800-53-r5-mappings.xlsx"

    if not excel_path.exists() or excel_path.stat().st_size == 0:
        logging.error(f"NIST mapping file not found at {excel_path}. Please run 'tooling/download_nist_data.py' to download it.")
        return defaultdict(list)

    try:
        # Load the Excel file
        df = pd.read_excel(excel_path, sheet_name='Mappings')

        # Clean column names
        df.columns = df.columns.str.strip()

        # Expected columns
        attack_id_col = 'Technique ID'
        nist_id_col = 'Control ID'
        nist_name_col = 'Control Name'
        
        if not all(col in df.columns for col in [attack_id_col, nist_id_col, nist_name_col]):
            logging.error(f"Missing expected columns in NIST Excel file. Found: {df.columns.tolist()}")
            return defaultdict(list)

        for index, row in df.iterrows():
            attack_id = str(row[attack_id_col]).strip()
            nist_id = str(row[nist_id_col]).strip()
            nist_name = str(row[nist_name_col]).strip()

            if attack_id and nist_id:
                nist_url = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
                nist_mappings[attack_id].append({
                    "id": nist_id,
                    "name": nist_name,
                    "url": nist_url,
                    "framework": "NIST"
                })
        
        logging.info(f"Successfully loaded {len(nist_mappings)} ATT&CK techniques mapped to NIST controls.")

    except FileNotFoundError:
        logging.error(f"Error: NIST Excel file not found at {excel_path}. Please run 'tooling/download_nist_data.py'.")
    except pd.errors.EmptyDataError:
        logging.error(f"NIST Excel file is empty or corrupted: {excel_path}")
    except Exception as e:
        logging.error(f"Error processing NIST Excel file: {e}")
        
    return nist_mappings

def load_cis_to_mitre_mapping() -> Dict[str, Dict[str, List[str]]]:
    """
    Loads the CIS Controls to MITRE ATT&CK mapping from the generated JSON file.
    The JSON maps CIS IDs to a list of MITRE techniques.
    """
    json_path = Path(__file__).parent.parent / 'external_data' / 'cis_to_mitre_mapping.json'
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            logging.info(f"Successfully loaded CIS to MITRE mapping from {json_path}.")
            return data
    except FileNotFoundError:
        logging.error(f"Error: CIS to MITRE mapping file not found at {json_path}. "
                      f"Please run 'tooling/cis_controls_parser.py' to generate it.")
        return {}
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON from {json_path}. The file might be corrupt.")
        return {}



