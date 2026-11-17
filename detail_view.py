
import streamlit as st
import numpy as np
import matplotlib.pyplot as plt



# 1. DISPLAY TECHNIQUE DETAILS

def render_technique_detail(tech):

    if tech is None:
        st.warning("Technique not found.")
        return

    st.title(tech.get("name", "Unknown Technique"))

    st.write("**Technique ID:**", tech.get("id", "N/A"))

    st.subheader("Description")
    st.write(tech.get("description", "No description available."))

    st.subheader("Platforms")
    platforms = tech.get("platforms", [])
    st.write(", ".join(platforms) if platforms else "No platform information available.")

    st.subheader("Tactics")
    tactics = tech.get("tactics", [])
    st.write(", ".join(tactics) if tactics else "No tactic information available.")

    st.subheader("Mitigations")

    mitigations = tech.get("mitigations", [])

    if mitigations:
        for mitigation in mitigations:
            st.markdown(f"**{mitigation.get('name', 'Unknown')}**")
            st.write(
                mitigation.get(
                    "description",
                    "No description available."
                )
            )
    else:
        st.info("No mitigation information available.")

    st.subheader("References")

    url = tech.get("url")

    if url:
        st.markdown(f"[View on MITRE ATT&CK]({url})")
    else:
        st.write("No reference available.")



# 2. COUNT TECHNIQUES BY TACTIC

def count_by_tactic(techniques):

    all_tactics = []

    for technique in techniques:
        tactics = technique.get("tactics", [])

        for tactic in set(tactics):
            all_tactics.append(tactic)

    if not all_tactics:
        return np.array([]), np.array([])

    tactic_names, counts = np.unique(
        all_tactics,
        return_counts=True
    )

    return tactic_names, counts



# 3. COUNT TECHNIQUES BY PLATFORM

def count_by_platform(techniques):

    all_platforms = []

    for technique in techniques:
        platforms = technique.get("platforms", [])

        for platform in set(platforms):
            all_platforms.append(platform)

    if not all_platforms:
        return np.array([]), np.array([])

    platform_names, counts = np.unique(
        all_platforms,
        return_counts=True
    )

    return platform_names, counts



# 4. COUNT SINGLE AND MULTIPLE TACTICS

def count_tactic_types(techniques):

    single_tactic = 0
    multiple_tactics = 0
    no_tactic = 0

    for technique in techniques:
        tactics = technique.get("tactics", [])

        if len(tactics) == 1:
            single_tactic += 1

        elif len(tactics) >= 2:
            multiple_tactics += 1

        else:
            no_tactic += 1

    labels = ["Single-Tactic", "Multiple-Tactic"]

    counts = np.array([
        single_tactic,
        multiple_tactics
    ])

    return labels, counts, no_tactic


# 5. PLOT TACTIC CHART

def plot_tactic_chart(tactic_names, counts):

    fig, ax = plt.subplots(figsize=(10, 5))

    ax.bar(tactic_names, counts)

    ax.set_title("Number of Techniques by Tactic")
    ax.set_xlabel("Tactic")
    ax.set_ylabel("Number of Techniques")

    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()

    st.pyplot(fig)
    plt.close(fig)



# 6. PLOT PLATFORM CHART

def plot_platform_chart(platform_names, counts):

    fig, ax = plt.subplots(figsize=(10, 5))

    ax.bar(platform_names, counts)

    ax.set_title("Number of Techniques by Platform")
    ax.set_xlabel("Platform")
    ax.set_ylabel("Number of Techniques")

    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()

    st.pyplot(fig)
    plt.close(fig)



# 7. PLOT TACTIC TYPE CHART

def plot_tactic_type_chart(labels, counts):

    fig, ax = plt.subplots(figsize=(7, 5))

    ax.pie(
        counts,
        labels=labels,
        autopct="%1.1f%%",
        startangle=90
    )

    ax.set_title("Single-Tactic vs Multiple-Tactic")

    plt.tight_layout()

    st.pyplot(fig)
    plt.close(fig)



# 8. RENDER ALL SUMMARY PLOTS

def render_summary_plots(techniques):

    if not techniques:
        st.info("No technique data available.")
        return

    # Statistics by Tactic
    st.subheader("Techniques by Tactic")

    tactic_names, tactic_counts = count_by_tactic(techniques)

    if len(tactic_names) > 0:
        plot_tactic_chart(tactic_names, tactic_counts)

        st.write("Tactic statistics:")

        for name, count in zip(tactic_names, tactic_counts):
            st.write(f"{name}: {count}")
    else:
        st.info("No tactic data available.")

    # Statistics by Platform
    st.subheader("Techniques by Platform")

    platform_names, platform_counts = count_by_platform(techniques)

    if len(platform_names) > 0:
        plot_platform_chart(platform_names, platform_counts)
    else:
        st.info("No platform data available.")

    # Single-Tactic vs Multiple-Tactic
    st.subheader("Single-Tactic vs Multiple-Tactic")

    labels, tactic_type_counts, no_tactic = count_tactic_types(techniques)

    if sum(tactic_type_counts) > 0:
        plot_tactic_type_chart(labels, tactic_type_counts)
    else:
        st.info("No tactic data available for classification.")

    st.write("Single-Tactic:", tactic_type_counts[0])
    st.write("Multiple-Tactic:", tactic_type_counts[1])
    st.write("Techniques without Tactic:", no_tactic)
