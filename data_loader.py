import json

def load_techniques(filepath="enterprise-attack (1).json"):
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    # Mitigations and Relationships
    raw_mitigations = {}  
    relationships = []    
    
    for obj in data.get("objects", []):
        obj_type = obj.get("type")
        
        # Extract mitigation objects (course-of-action)
        if obj_type == "course-of-action" and not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
            mit_stix_id = obj.get("id")
            mit_id = "N/A"
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    mit_id = ref.get("external_id", "N/A")
                    break
            raw_mitigations[mit_stix_id] = {
                "id": mit_id,
                "name": obj.get("name", ""),
                "description": obj.get("description", "")
            }
            
        # Extract mitigation relationships
        elif obj_type == "relationship" and obj.get("relationship_type") == "mitigates":
            relationships.append({
                "source_ref": obj.get("source_ref"), 
                "target_ref": obj.get("target_ref")  
            })
            
    # Map Technique STIX IDs to their respective clean Mitigations
    tech_mitigations_map = {}
    for rel in relationships:
        source = rel["source_ref"]
        target = rel["target_ref"]
        if source in raw_mitigations:
            if target not in tech_mitigations_map:
                tech_mitigations_map[target] = []
            tech_mitigations_map[target].append(raw_mitigations[source])
    # --------------------------------------------------------------------------

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
                
        # --- ADDITION 2: Get the mapped mitigations for this specific technique ---
        stix_id = obj.get("id")
        tech_mitigations = tech_mitigations_map.get(stix_id, [])
                
        # 4. Pack clean data into the techniques list
        techniques.append({
            "id": tech_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "platforms": obj.get("x_mitre_platforms", []),
            "tactics": tactics,
            "url": url,
            "mitigations": tech_mitigations # <--- ADDITION 3: Append the mitigation list here
        })
        
    return techniques

# MAIN EXECUTION (Kept 100% identical to your screenshot)
if __name__ == "__main__":
    try:
        print("Reading source file and filtering data, please wait...")
        clean_data = load_techniques("enterprise-attack (1).json")
        sample_data = clean_data[:20]
        # Export sample data to sample_attack.json
        with open("sample_attack.json", "w", encoding="utf-8") as f:
            json.dump(sample_data, f, ensure_ascii=False, indent=4)
            
        print("Success! 'sample_attack.json' has been created in the current directory.")
        print(f"Total techniques parsed from source: {len(clean_data)}")
    except FileNotFoundError:
        print("Error 'enterprise-attack (1).json' not found in this directory.")
        print("Please ensure the MITRE STIX JSON file is placed in the same folder as this script.")

