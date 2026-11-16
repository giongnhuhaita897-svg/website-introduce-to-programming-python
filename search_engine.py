"""
Search and filtering engine for MITRE ATT&CK techniques.
"""

from typing import List, Dict, Any, Optional


def search_by_id(techniques: List[Dict[str, Any]], tech_id: str) -> Optional[Dict[str, Any]]:
    """
    Find a single technique by its exact ATT&CK ID (case-insensitive, e.g., 'T1059').
    """
    if not tech_id:
        return None
    target_id = tech_id.strip().upper()
    for tech in techniques:
        if tech.get("id", "").upper() == target_id:
            return tech
    return None


def search_by_keyword(techniques: List[Dict[str, Any]], keyword: str) -> List[Dict[str, Any]]:
    """
    Search techniques where the keyword appears in the ID, name, or description.
    """
    if not keyword or not keyword.strip():
        return techniques

    query = keyword.strip().lower()
    results = []
    for tech in techniques:
        tech_id = tech.get("id", "").lower()
        name = tech.get("name", "").lower()
        description = tech.get("description", "").lower()

        if query in tech_id or query in name or query in description:
            results.append(tech)
    return results


def filter_techniques(
    techniques: List[Dict[str, Any]],
    keyword: str = "",
    tactic: str = "All",
    platform: str = "All"
) -> List[Dict[str, Any]]:
    """
    Combined search and filter function by keyword, tactic, and platform.
    """
    filtered = search_by_keyword(techniques, keyword)

    if tactic and tactic.lower() != "all":
        target_tactic = tactic.strip().lower()
        filtered = [
            tech for tech in filtered
            if any(t.lower() == target_tactic for t in tech.get("tactics", []))
        ]

    if platform and platform.lower() != "all":
        target_platform = platform.strip().lower()
        filtered = [
            tech for tech in filtered
            if any(p.lower() == target_platform for p in tech.get("platforms", []))
        ]

    return filtered


def get_unique_tactics_and_platforms(techniques: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """
    Extract sorted lists of unique tactics and platforms to populate UI dropdowns.
    """
    tactics = set()
    platforms = set()
    for tech in techniques:
        tactics.update(tech.get("tactics", []))
        platforms.update(tech.get("platforms", []))
    return {
        "tactics": sorted(list(tactics)),
        "platforms": sorted(list(platforms))
    }


def count_by_tactic_and_platform(techniques: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    """
    Generate counts of techniques grouped by tactic and platform for summary charts.
    """
    tactic_counts: Dict[str, int] = {}
    platform_counts: Dict[str, int] = {}

    for tech in techniques:
        for tactic in tech.get("tactics", []):
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        for platform in tech.get("platforms", []):
            platform_counts[platform] = platform_counts.get(platform, 0) + 1

    return {
        "tactics": tactic_counts,
        "platforms": platform_counts
    }


if __name__ == "__main__":
    sample_data = [
        {
            "id": "T1059",
            "name": "Command and Scripting Interpreter",
            "description": "Adversaries may abuse command and script interpreters to execute commands.",
            "platforms": ["Windows", "Linux", "macOS"],
            "tactics": ["execution"]
        },
        {
            "id": "T1078",
            "name": "Valid Accounts",
            "description": "Adversaries may obtain and abuse credentials of existing accounts.",
            "platforms": ["Windows", "Azure AD", "Linux"],
            "tactics": ["defense-evasion", "persistence", "privilege-escalation", "initial-access"]
        }
    ]

    print("ID Search:", search_by_id(sample_data, "t1059")["name"])
    print("Filter Count:", len(filter_techniques(sample_data, keyword="abuse", platform="Linux")))
    print("Summary Counts:", count_by_tactic_and_platform(sample_data))