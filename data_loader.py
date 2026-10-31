import json

def load_techniques(filepath="enterprise-attack (1).json"):
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    techniques = []
    for obj in data.get("objects", []):
        # 1. Only get active techniques (attack-pattern) and skip revoked/deprecated ones
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        # 2. Extract MITRE ID (e.g., T1059) and URL from external_references
        tech_id = "N/A"
        url = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id", "N/A")
                url = ref.get("url", "")
                break

        # 3. Extract Tactics (e.g., execution, initial-access) from kill_chain_phases
        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactics.append(phase.get("phase_name"))

        # 4. Pack clean data into the techniques list
        techniques.append({
            "id": tech_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "platforms": obj.get("x_mitre_platforms", []),
            "tactics": tactics,
            "url": url,
        })

    return techniques


# MAIN EXECUTION TO GENERATE SAMPLE DATA
if __name__ == "__main__":
    try:
        print("Reading source file and filtering data, please wait...")
        
        # 1. Call your function to parse clean data from the large file
        clean_data = load_techniques("enterprise-attack (1).json")
        
        # 2. Slice the first 20 techniques to create a lightweight sample dataset
        sample_data = clean_data[:20]
        
        # 3. Export the sample data to sample_attack.json
        with open("sample_attack.json", "w", encoding="utf-8") as f:
            json.dump(sample_data, f, ensure_ascii=False, indent=4)
            
        print("Success! 'sample_attack.json' has been created in the current directory.")
        print(f"Total techniques parsed from source: {len(clean_data)}")
        
    except FileNotFoundError:
        print("Error: 'enterprise-attack (1).json' not found in this directory.")
        print("Please ensure the MITRE STIX JSON file is placed in the same folder as this script.")
