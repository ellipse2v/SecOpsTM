#!/usr/bin/env python3
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
Script to update configuration files to ensure consistency.
This script should be run before commits to keep configurations in sync.
"""

import subprocess
import sys
from pathlib import Path

def main():
    """Main function to update configurations"""
    
    # Add project root to sys.path
    project_root = Path(__file__).parent.parent
    sys.path.append(str(project_root))
    
    try:
        # Run the config generation script
        print("Generating config.js...")
        result = subprocess.run([
            sys.executable, 
            str(project_root / "threat_analysis" / "config_generator.py")
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Error generating config.js: {result.stderr}")
            return 1
        
        print(result.stdout)
        print("Configuration update completed successfully!")
        return 0
        
    except Exception as e:
        print(f"Error updating configurations: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())