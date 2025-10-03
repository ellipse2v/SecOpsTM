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

import shutil
from pathlib import Path

def main():
    """
    Copies the CVE2CAPEC database into the project's external_data directory.
    """
    # Define paths relative to this script's location
    script_dir = Path(__file__).parent.resolve()
    project_root = script_dir.parent
    
    source_dir = project_root.parent / "CVE2CAPEC" / "database"
    destination_dir = project_root / "threat_analysis" / "external_data" / "cve2capec"

    print(f"Source directory: {source_dir}")
    print(f"Destination directory: {destination_dir}")

    # Check if the source directory exists
    if not source_dir.is_dir():
        print(f"❌ ERROR: Source directory not found at '{source_dir}'")
        print("Please ensure you have cloned the 'CVE2CAPEC' repository next to the 'SecOpsTM' project directory.")
        print("git clone https://github.com/Galeax/CVE2CAPEC.git")
        return

    # If the destination directory exists, remove it for a clean copy
    if destination_dir.exists():
        print(f"Destination directory '{destination_dir}' already exists. Removing it for a clean copy.")
        try:
            shutil.rmtree(destination_dir)
        except OSError as e:
            print(f"❌ ERROR: Failed to remove existing destination directory: {e}")
            return

    # Copy the directory
    try:
        print("Copying files...")
        shutil.copytree(source_dir, destination_dir)
        print("✅ Successfully copied the CVE2CAPEC database.")
    except OSError as e:
        print(f"❌ ERROR: Failed to copy directory: {e}")

if __name__ == "__main__":
    main()
