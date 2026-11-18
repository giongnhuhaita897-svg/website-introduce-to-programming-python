import json


def load_techniques(file_path="sample_attack.json"):
    try:
        with open(file_path, "r", encoding="utf-8") as source_file:
            data = json.load(source_file)
    except FileNotFoundError:
        return []
    if isinstance(data, list):
        return data
    return []


def safe_text(value):
    if value is None:
        return ""
    return str(value)


def safe_list(value):
    if isinstance(value, list):
        return value
    return []


def build_indexes(techniques):
    by_id = {}
    by_tactic = {}
    by_platform = {}
    for tech in techniques:
        if not isinstance(tech, dict):
            continue
        tech_id = safe_text(tech.get("id")).strip().upper()
        if tech_id:
            by_id[tech_id] = tech
        for tactic in safe_list(tech.get("tactics")):
            tactic_name = safe_text(tactic).strip().lower()
            if tactic_name:
                if tactic_name not in by_tactic:
                    by_tactic[tactic_name] = []
                by_tactic[tactic_name].append(tech)
        for platform in safe_list(tech.get("platforms")):
            platform_name = safe_text(platform).strip().lower()
            if platform_name:
                if platform_name not in by_platform:
                    by_platform[platform_name] = []
                by_platform[platform_name].append(tech)
    return {"by_id": by_id, "by_tactic": by_tactic, "by_platform": by_platform}


def search_by_id(techniques, tech_id):
    target_id = safe_text(tech_id).strip().upper()
    if not target_id:
        return None
    indexes = build_indexes(techniques)
    return indexes["by_id"].get(target_id)


def search_by_keyword(techniques, keyword):
    query = safe_text(keyword).strip().lower()
    results = []
    for tech in techniques:
        if not isinstance(tech, dict):
            continue
        if not query:
            results.append(tech)
            continue
        tech_id = safe_text(tech.get("id")).lower()
        name = safe_text(tech.get("name")).lower()
        description = safe_text(tech.get("description")).lower()
        if query in tech_id or query in name or query in description:
            results.append(tech)
    return results


def search_and_filter(techniques, keyword="", tactic="All", platform="All", multi_only=False, sort_by="ID (A-Z)"):
    results = search_by_keyword(techniques, keyword)
    tactic_value = safe_text(tactic).strip().lower()
    platform_value = safe_text(platform).strip().lower()
    filtered = []
    for tech in results:
        include = True
        tactics = safe_list(tech.get("tactics"))
        platforms = safe_list(tech.get("platforms"))
        if tactic_value and tactic_value != "all":
            found = False
            for item in tactics:
                if safe_text(item).strip().lower() == tactic_value:
                    found = True
            if not found:
                include = False
        if platform_value and platform_value != "all":
            found = False
            for item in platforms:
                if safe_text(item).strip().lower() == platform_value:
                    found = True
            if not found:
                include = False
        if multi_only and len(tactics) < 2:
            include = False
        if include:
            filtered.append(tech)

    sort_name = "name" in safe_text(sort_by).lower()
    for index in range(len(filtered)):
        for other_index in range(index + 1, len(filtered)):
            if sort_name:
                first = safe_text(filtered[index].get("name")).lower()
                second = safe_text(filtered[other_index].get("name")).lower()
            else:
                first = safe_text(filtered[index].get("id")).upper()
                second = safe_text(filtered[other_index].get("id")).upper()
            if first > second:
                filtered[index], filtered[other_index] = filtered[other_index], filtered[index]
    return filtered


def get_unique_tactics_and_platforms(techniques):
    tactics = set()
    platforms = set()
    for tech in techniques:
        if not isinstance(tech, dict):
            continue
        for tactic in safe_list(tech.get("tactics")):
            if safe_text(tactic):
                tactics.add(safe_text(tactic))
        for platform in safe_list(tech.get("platforms")):
            if safe_text(platform):
                platforms.add(safe_text(platform))
    return {"tactics": sorted(tactics), "platforms": sorted(platforms)}


def count_by_tactic_and_platform(techniques):
    tactic_counts = {}
    platform_counts = {}
    for tech in techniques:
        if not isinstance(tech, dict):
            continue
        for tactic in safe_list(tech.get("tactics")):
            if tactic:
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        for platform in safe_list(tech.get("platforms")):
            if platform:
                platform_counts[platform] = platform_counts.get(platform, 0) + 1
    return {"tactics": tactic_counts, "platforms": platform_counts}


if __name__ == "__main__":
    sample_data = load_techniques("sample_attack.json")
    print("Loaded techniques:", len(sample_data))
    print("Index sizes:", len(build_indexes(sample_data)["by_id"]))
