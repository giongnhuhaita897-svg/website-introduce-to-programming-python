"""
Search, filtering, and analytics module for MITRE ATT&CK techniques.
"""

import json
import os
from typing import List, Dict, Any, Optional


def load_techniques(file_path: str = "sample_attack.json") -> List[Dict[str, Any]]:
    """
    Load the list of MITRE ATT&CK techniques from a JSON file.
    """
    if not os.path.exists(file_path):
        return []
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def search_by_id(techniques: List[Dict[str, Any]], tech_id: str) -> Optional[Dict[str, Any]]:
    """
    Find a single technique by its exact ATT&CK ID (case-insensitive).
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


def search_and_filter(
    techniques: List[Dict[str, Any]],
    keyword: str = "",
    tactic: str = "All",
    platform: str = "All",
    multi_only: bool = False,
    sort_by: str = "ID (A-Z)"
) -> List[Dict[str, Any]]:
    """
    Filter and sort MITRE ATT&CK techniques based on 6 parameters:
    1. techniques: List of technique dictionaries.
    2. keyword: Search term matched against ID, name, and description.
    3. tactic: Filter by specific tactic ('All' disables this filter).
    4. platform: Filter by specific platform ('All' disables this filter).
    5. multi_only: If True, keep only techniques with 2 or more tactics.
    6. sort_by: Sort order ('ID (A-Z)' or 'Name (A-Z)').
    Returns a filtered and sorted list of technique dictionaries.
    """
    # Step 1: Filter by keyword
    results = search_by_keyword(techniques, keyword)

    # Step 2: Filter by tactic
    if tactic and tactic.strip().lower() != "all":
        target_tactic = tactic.strip().lower()
        results = [
            tech for tech in results
            if any(t.lower() == target_tactic for t in tech.get("tactics", []))
        ]

    # Step 3: Filter by platform
    if platform and platform.strip().lower() != "all":
        target_platform = platform.strip().lower()
        results = [
            tech for tech in results
            if any(p.lower() == target_platform for p in tech.get("platforms", []))
        ]

    # Step 4: Filter techniques belonging to multiple tactics (len(tactics) >= 2)
    if multi_only:
        results = [
            tech for tech in results
            if len(tech.get("tactics", [])) >= 2
        ]

    # Step 5: Sort results A-Z by Name or ID
    sort_option = (sort_by or "").strip().lower()
    if "name" in sort_option:
        results = sorted(results, key=lambda item: item.get("name", "").lower())
    else:
        results = sorted(results, key=lambda item: item.get("id", "").upper())

    return results


def get_unique_tactics_and_platforms(techniques: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """
    Extract sorted lists of unique tactics and platforms for UI dropdown menus.
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
    Count the number of techniques per tactic and per platform for summary charts.
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
    sample_data = load_techniques("sample_attack.json")
    print(f"Loaded {len(sample_data)} techniques.")

    filtered = search_and_filter(
        techniques=sample_data,
        keyword="",
        tactic="All",
        platform="Windows",
        multi_only=True,
        sort_by="Name (A-Z)"
    )
    print("Filtered results:", [(item["id"], item["name"]) for item in filtered])