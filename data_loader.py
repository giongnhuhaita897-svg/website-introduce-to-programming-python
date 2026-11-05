import json

class Technique:
    def __init__(self, tech_id, name, description, platforms, tactics, url, mitigations):
        self.id = tech_id
        self.name = name
        self.description = description
        self.platforms = platforms
        self.tactics = tactics
        self.url = url
        self.mitigations = mitigations

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "platforms": self.platforms,
            "tactics": self.tactics,
            "url": self.url,
            "mitigations": self.mitigations
        }

def load_techniques(filepath="enterprise-attack (1).json"):
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f) 

    # x-mitre-collection
    version_info = {
        "collection_name": "N/A",
        "version": "N/A",
        "modified": "N/A"
    }   
    
    # Mitigations and Relationships
    raw_mitigations = {}  
    relationships = []    
    
    for obj in data.get("objects", []):
        obj_type = obj.get("type")
        if obj_type == "x-mitre-collection":
            version_info["collection_name"] = obj.get("name", "N/A")
            version_info["version"] = obj.get("x_mitre_version", "N/A")
            version_info["modified"] = obj.get("modified", "N/A")

        # Extract mitigation objects (course-of-action)
        elif obj_type == "course-of-action" and not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
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
        elif (obj_type == "relationship" and obj.get("relationship_type") == "mitigates"
              and not obj.get("revoked") and not obj.get("x_mitre_deprecated")):
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
   
    # Techniques
    techniques = []
    for obj in data.get("objects", []):
        # 1. Only get active techniques (attack-pattern) and skip revoked/deprecated ones
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        # 2. Extract MITRE ID and URL from external_references
        tech_id = "N/A"
        url = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id", "N/A")
                url = ref.get("url", "")
                break 
        # 3. Extract Tactics
        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactics.append(phase.get("phase_name"))
        # Get the mapped mitigations for this specific technique ---
        stix_id = obj.get("id")
        tech_mitigations = tech_mitigations_map.get(stix_id, [])
        # 4. Pack clean data into the techniques list
        techniques.append(Technique(
            tech_id,
            obj.get("name", ""),
            obj.get("description", ""),
            obj.get("x_mitre_platforms", []),
            tactics,
            url,
            tech_mitigations
        ))
        if len(techniques) == 20:
            break
    return techniques, version_info
#MAIN EXECUTION
if __name__ == "__main__":
    file_name = "enterprise-attack (1).json"
    try:
        print("Reading source file and filtering data, please wait...")
        techniques, version_info = load_techniques(file_name)
        sample_data = [t.to_dict() for t in techniques]
        # Export sample data to sample_attack.json
        with open("sample_attack.json", "w", encoding="utf-8") as f:
            json.dump(sample_data, f, ensure_ascii=False, indent=4)
        print("Success! 'sample_attack.json' has been created.")
        print(f"Version: {version_info['version']} | Modified: {version_info['modified']}")
        print(f"Total techniques parsed and exported: {len(sample_data)}")
    except FileNotFoundError:
        print(f"Error '{file_name}' not found in the directory.")
        print("Please ensure the MITRE STIX JSON file is placed correctly.")
 