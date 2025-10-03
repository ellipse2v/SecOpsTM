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
This script downloads the latest CAPEC CSV data, processes it, and creates a
structured JSON file mapping CAPEC entries to MITRE ATT&CK techniques.
It includes a web scraping fallback to enrich data for entries missing
techniques in the CSV.
"""

import csv
import json
import re
import requests
import zipfile
import io
from pathlib import Path
from bs4 import BeautifulSoup

# Define paths relative to the script location
TOOLING_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = TOOLING_DIR.parent
EXTERNAL_DATA_DIR = PROJECT_ROOT / "threat_analysis" / "external_data"

# Configuration
CAPEC_CSV_URL = "https://capec.mitre.org/data/csv/658.csv.zip"
CSV_FILENAME = "CAPEC_VIEW_ATT&CK_Related_Patterns.csv"
JSON_FILENAME = "capec_to_mitre_structured_mapping.json"

CSV_OUTPUT_PATH = EXTERNAL_DATA_DIR / CSV_FILENAME
JSON_OUTPUT_PATH = EXTERNAL_DATA_DIR / JSON_FILENAME

def download_and_unzip_capec_data():
    """Downloads and unzips the CAPEC CSV data."""
    print(f"Downloading CAPEC data from {CAPEC_CSV_URL}...")
    try:
        response = requests.get(CAPEC_CSV_URL, timeout=30)
        response.raise_for_status()
        print("Download successful. Unzipping in memory...")
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            csv_file_in_zip = next((name for name in z.namelist() if name.endswith('.csv')), None)
            if not csv_file_in_zip:
                print("❌ ERROR: No CSV file found in the downloaded zip archive.")
                return False
            with z.open(csv_file_in_zip) as source, open(CSV_OUTPUT_PATH, 'wb') as target:
                target.write(source.read())
            print(f"✅ Successfully extracted and saved to {CSV_OUTPUT_PATH}")
            return True
    except requests.exceptions.RequestException as e:
        print(f"❌ ERROR: Failed to download the file: {e}")
    except zipfile.BadZipFile:
        print("❌ ERROR: The downloaded file is not a valid zip archive.")
    except Exception as e:
        print(f"❌ An unexpected error occurred during download/unzip: {e}")
    return False

def parse_taxonomy_mappings(mappings_string: str):
    """Parses the 'Taxonomy Mappings' string from the CSV into a list of techniques."""
    if not mappings_string:
        return []
    techniques = []
    pattern = re.compile(r"TAXONOMY NAME:ATTACK:ENTRY ID:([^:]+):ENTRY NAME:([^:]+?)(?=(?:::)|$)")
    matches = pattern.findall(mappings_string)
    for match in matches:
        technique_id = match[0].strip()
        technique_name = match[1].strip()
        techniques.append({
            "taxonomy": "ATT&CK",
            "id": f"T{technique_id}",
            "name": technique_name,
            "fromMitre": "yes",
            "tactics": []
        })
    return techniques

def scrape_techniques_from_html(url: str) -> list:
    """
    If a CAPEC has no techniques in the CSV, this function scrapes them
    from the CAPEC's specific HTML definition page.
    """
    print(f"  -> No techniques in CSV, scraping fallback: {url}")
    techniques = []
    try:
        response = requests.get(url, timeout=20)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'lxml')

        # Find the div with id="Taxonomy_Mappings" based on the user's finding.
        taxonomy_div = soup.find('div', id='Taxonomy_Mappings')
        
        if not taxonomy_div:
            print("  -> Could not find the 'Taxonomy_Mappings' div on the page.")
            return []

        # Find all links that point to an ATT&CK technique page
        attack_links = taxonomy_div.find_all('a', href=re.compile(r"attack.mitre.org/(?:techniques|wiki/Technique)/T\d+"))
        
        for link in attack_links:
            href = link.get('href', '')
            # Extract the 'TXXXX' or 'TXXXX.XXX' part from the URL
            match = re.search(r"(T\d+(?:\.\d+)?)", href)
            if match:
                technique_id = match.group(1)
                technique_name = ""
                # The name is usually the text of the parent td's next sibling
                parent_td = link.find_parent('td')
                if parent_td and parent_td.find_next_sibling('td'):
                    technique_name = parent_td.find_next_sibling('td').get_text(strip=True)
                
                # Extract tactics
                tactics = []
                tactic_section = soup.find(string=re.compile("Tactics:"))
                if tactic_section:
                    tactic_parent = tactic_section.find_parent()
                    if tactic_parent:
                        for tactic_link in tactic_parent.find_all_next('a'):
                            if 'tactics' in tactic_link.get('href', ''):
                                tactics.append(tactic_link.get_text().strip())

                techniques.append({
                    "taxonomy": "ATT&CK",
                    "id": technique_id,
                    "name": technique_name,
                    "fromMitre": "yes",
                    "tactics": tactics
                })

        if techniques:
            print(f"  -> Scraped {len(techniques)} technique(s) from HTML page.")
        else:
            print("  -> No ATT&CK techniques found in the Taxonomy_Mappings div.")
            
        return techniques
    except Exception as e:
        print(f"  -> An unexpected error occurred during scraping: {e}")
        return []

def build_json_from_csv():
    """Parses the CSV file and builds the structured JSON output."""
    print(f"Parsing {CSV_OUTPUT_PATH} to build JSON map...")
    if not CSV_OUTPUT_PATH.exists():
        print(f"❌ ERROR: CSV file not found at {CSV_OUTPUT_PATH}. Please download it first.")
        return

    capec_map = []
    try:
        with open(CSV_OUTPUT_PATH, mode='r', encoding='utf-8-sig') as csvfile:
            content = csvfile.read().strip("'")
            reader = csv.DictReader(io.StringIO(content))
            if reader.fieldnames:
                reader.fieldnames = [header.strip() for header in reader.fieldnames]

            for row in reader:
                capec_id_str = row.get("ID", "").strip()
                if not capec_id_str:
                    continue
                capec_id_num_match = re.search(r'\d+', capec_id_str)
                if not capec_id_num_match:
                    continue
                capec_id_num = capec_id_num_match.group(0)

                techniques = parse_taxonomy_mappings(row.get("Taxonomy Mappings", ""))
                capec_url = f"https://capec.mitre.org/data/definitions/{capec_id_num}.html"

                if not techniques:
                    scraped_techniques = scrape_techniques_from_html(capec_url)
                    techniques.extend(scraped_techniques)

                capec_map.append({
                    "capec_id": f"CAPEC-{capec_id_num}",
                    "name": row.get("Name", "").strip(),
                    "url": capec_url,
                    "fromMitre": "yes",
                    "techniques": techniques
                })

        print(f"Successfully parsed {len(capec_map)} CAPEC entries.")

        # Manual mappings section
        manual_mappings = [
            {
                "capec_id": "CAPEC-51",
                "name": "Exploitation of Authentication Functions",
                "url": "https://capec.mitre.org/data/definitions/51.html",
                "fromMitre": "no",
                "techniques": [
                    {
                        "taxonomy": "ATT&CK",
                        "id": "T1556",
                        "name": "Modify Authentication Process",
                        "fromMitre": "no",
                        "tactics": []
                    }
                ]
            }
        ]
        capec_map.extend(manual_mappings)
        print(f"Added {len(manual_mappings)} manual CAPEC entries.")

        if capec_map:
            print(f"Writing JSON output to {JSON_OUTPUT_PATH}...")
            with open(JSON_OUTPUT_PATH, 'w', encoding='utf-8') as jsonfile:
                json.dump(capec_map, jsonfile, indent=4)
            print("✅ JSON file created successfully.")
        else:
            print("⚠️ WARNING: No data was parsed, JSON file was not written.")

    except FileNotFoundError:
        print(f"❌ ERROR: File not found: {CSV_OUTPUT_PATH}")
    except Exception as e:
        print(f"❌ An unexpected error occurred during parsing: {e}")

def main():
    """Main function to run the builder script."""
    print("--- Starting CAPEC to MITRE ATT&CK Builder ---")
    if download_and_unzip_capec_data():
        build_json_from_csv()
    print("--- Script Finished ---")

if __name__ == "__main__":
    main()