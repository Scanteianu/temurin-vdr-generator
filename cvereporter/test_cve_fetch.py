import requests
import re
import json
from typing import Dict, Optional

def extract_cve_details(cve_name: str) -> Optional[Dict[str, str]]:
    """
    Parses a CVE name (e.g., CVE-2026-106016) to extract the year and prefix.
    
    The prefix is defined as all digits in the numeric ID except for the last three characters.
    
    Example 1: CVE-2026-106016 
        -> Year: 2026, Prefix: 106 (from '106016'[:-3])
    Example 2: CVE-2020-2601
        -> Year: 2020, Prefix: 2 (from '2601'[:-3])
    """
    
    # Regex pattern: 
    # 1. (\d{4}) captures the four-digit Year (Group 1)
    # 2. (\d+) captures the entire Numeric ID (Group 2)
    pattern = re.compile(r"CVE-(\d{4})-(\d+)")
    
    cve_name_upper = cve_name.upper()
    match = pattern.match(cve_name_upper)
    
    if match:
        year = match.group(1)
        full_id = match.group(2)
        
        # --- CORE FIX: Implement the specific prefix rule ---
        if len(full_id) >= 3:
            # Take all characters up to (but not including) the last 3
            prefix = full_id[:-3]
        else:
            # Fallback if the ID is too short (shouldn't happen for valid CVEs)
            prefix = full_id
            
        return {
            "year": year,
            "prefix": prefix
        }
    else:
        print(f"Error: The CVE name '{cve_name}' does not match the expected format (CVE-YYYY-NNNNNN).")
        return None

def fetch_cve_json(cve_name: str) -> Optional[Dict]:
    """
    Constructs the raw URL, fetches the JSON file, and loads it into memory.
    """
    details = extract_cve_details(cve_name)
    if not details:
        return None

    year = details["year"]
    prefix = details["prefix"]
    
    # Construct the raw URL for the specific file
    # Note: We use the 'raw.githubusercontent' URL structure.
    base_url = "https://raw.githubusercontent.com/CVEProject/cvelistV5/refs/heads/main/cves"
    file_path = f"{year}/{prefix}xxx/{cve_name}.json"
    full_url = f"{base_url}/{file_path}"
    
    print("-" * 50)
    print(f"Attempting to fetch URL: {full_url}")
    print("-" * 50)

    try:
        # Fetch the data using requests
        response = requests.get(full_url, timeout=10)
        
        # Check if the request was successful (HTTP 200)
        response.raise_for_status()
        
        # Load the JSON content directly into memory
        cve_data = response.json()
        
        print("✅ Successfully fetched and parsed the CVE JSON file.")
        return cve_data

    except requests.exceptions.HTTPError as e:
        print(f"❌ HTTP Error: Could not find the file (Status {e.response.status_code}). Check the CVE name/path.")
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"❌ Connection Error: Could not connect to GitHub. Check your internet connection. Error: {e}")
        return None
    except requests.exceptions.Timeout as e:
        print(f"❌ Timeout Error: Request took too long. Error: {e}")
        return None
    except json.JSONDecodeError:
        print("❌ JSON Decode Error: The file content was not valid JSON.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

# --- Example Usage ---

# 1. Example working CVE
target_cve_1 = "CVE-2020-2601"
target_cve_1 = "CVE-2026-106016"
data_1 = fetch_cve_json(target_cve_1)

if data_1:
    print(json.dumps(data_1, indent=True))
    print("\n--- DATA LOADED (Example Data) ---")
    # Print a snippet to prove it's loaded into memory
    print(f"Type of data: {type(data_1)}")
    # Assuming the file contains a list of CVE records:
    print(f"Number of records: {len(data_1)}")
    if data_1:
        print("First record snippet:", data_1[0])

# 2. Example of a potential failure (a non-existent CVE)
target_cve_2 = "CVE-9999-000000"
data_2 = fetch_cve_json(target_cve_2)

if not data_2:
    print("\nAs expected, data 2 was None because the file likely does not exist.")