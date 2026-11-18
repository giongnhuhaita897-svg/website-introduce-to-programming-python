import json


class Technique:
    def __init__(self, tech_id, stix_id, name, description, platforms, tactics, url, mitigations):
        self.id = tech_id
        self.stix_id = stix_id
        self.name = name
        self.description = description
        self.platforms = platforms
        self.tactics = tactics
        self.url = url
        self.mitigations = mitigations

    def to_dict(self):
        return {
            "id": self.id,
            "stix_id": self.stix_id,
            "name": self.name,
            "description": self.description,
            "platforms": self.platforms,
            "tactics": self.tactics,
            "url": self.url,
            "mitigations": self.mitigations,
        }


def load_techniques(filepath):
    with open(filepath, "r", encoding="utf-8") as source_file:
        data = json.load(source_file)

    version_info = {"version": "N/A", "modified": "N/A"}
    objects = []
    if isinstance(data, dict):
        objects = data.get("objects") or []
    elif isinstance(data, list):
        objects = data

    active_mitigations = {}
    relationships = []
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if obj.get("type") == "x-mitre-collection":
            version_info["version"] = obj.get("x_mitre_version") or "N/A"
            version_info["modified"] = obj.get("modified") or "N/A"
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        if obj.get("type") == "course-of-action":
            mitigation_id = "N/A"
            for reference in obj.get("external_references") or []:
                if isinstance(reference, dict) and reference.get("source_name") == "mitre-attack":
                    mitigation_id = reference.get("external_id") or "N/A"
                    break
            active_mitigations[obj.get("id")] = {
                "id": mitigation_id,
                "name": obj.get("name") or "",
                "description": obj.get("description") or "",
            }
        elif obj.get("type") == "relationship" and obj.get("relationship_type") == "mitigates":
            relationships.append({"source_ref": obj.get("source_ref"), "target_ref": obj.get("target_ref")})

    mitigations_by_tech = {}
    for relationship in relationships:
        source_id = relationship.get("source_ref")
        target_id = relationship.get("target_ref")
        if source_id in active_mitigations and target_id:
            if target_id not in mitigations_by_tech:
                mitigations_by_tech[target_id] = []
            mitigations_by_tech[target_id].append(active_mitigations[source_id])

    techniques = []
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if "type" not in obj and "id" in obj:
            tactics = obj.get("tactics") or []
            clean_tactics = []
            for tactic in tactics:
                if tactic == "stealth":
                    tactic = "defense-evasion"
                if tactic is not None:
                    clean_tactics.append(tactic)
            tech = Technique(
                obj.get("id") or "N/A", obj.get("stix_id") or "",
                obj.get("name") or "", obj.get("description") or "",
                obj.get("platforms") or [], clean_tactics,
                obj.get("url") or "", obj.get("mitigations") or [],
            )
            techniques.append(tech.to_dict())
            continue
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        tech_id = "N/A"
        url = ""
        for reference in obj.get("external_references") or []:
            if isinstance(reference, dict) and reference.get("source_name") == "mitre-attack":
                tech_id = reference.get("external_id") or "N/A"
                url = reference.get("url") or ""
                break

        tactics = []
        for phase in obj.get("kill_chain_phases") or []:
            if isinstance(phase, dict) and phase.get("kill_chain_name") == "mitre-attack":
                tactic = phase.get("phase_name")
                if tactic == "stealth":
                    tactic = "defense-evasion"
                if tactic and tactic not in tactics:
                    tactics.append(tactic)

        platforms = obj.get("x_mitre_platforms") or []
        if not isinstance(platforms, list):
            platforms = []
        tech = Technique(
            tech_id,
            obj.get("id") or "",
            obj.get("name") or "",
            obj.get("description") or "",
            platforms,
            tactics,
            url,
            mitigations_by_tech.get(obj.get("id"), []),
        )
        techniques.append(tech.to_dict())

    return techniques, version_info


if __name__ == "__main__":
    technique_data, dataset_info = load_techniques("sample_attack.json")
    print("Techniques loaded:", len(technique_data))
    print("Version:", dataset_info.get("version"))
    print("Modified:", dataset_info.get("modified"))
