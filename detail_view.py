

import json
import streamlit as st
import numpy as np
import matplotlib.pyplot as plt



st.set_page_config(
    page_title="MITRE ATT&CK Browser",
    page_icon="🛡️",
    layout="centered"
)



st.markdown("""
<style>
    .block-container {
        max-width: 900px;
        padding-top: 2rem;
        padding-bottom: 3rem;
    }

    h1 {
        color: #1f2937;
        font-size: 2rem;
    }

    h2, h3 {
        color: #374151;
    }

    p, li {
        line-height: 1.7;
    }

    hr {
        margin-top: 1.5rem;
        margin-bottom: 1.5rem;
    }
</style>
""", unsafe_allow_html=True)



def load_techniques():
    with open("sample_attack.json", "r", encoding="utf-8") as file:
        return json.load(file)




def get_technique_detail(techniques, technique_id):
    for technique in techniques:
        if technique.get("id") == technique_id:
            return technique

    return None




def show_technique_detail(technique):

    if technique is None:
        st.warning("Technique not found.")
        return

    st.title(technique.get("name", "Unknown Technique"))

    st.write("**Technique ID:**", technique.get("id", "N/A"))

    st.subheader("Description")
    st.write(technique.get("description", "No description available."))

    st.subheader("Platforms")
    st.write(", ".join(technique.get("platforms", [])))

    st.subheader("Tactics")
    st.write(", ".join(technique.get("tactics", [])))

    st.subheader("Mitigations")

    mitigations = technique.get("mitigations", [])

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

    url = technique.get("url")

    if url:
        st.markdown(f"[View on MITRE ATT&CK]({url})")
    else:
        st.write("No reference available.")




def count_by_tactic(techniques):
    all_tactics = []

    for technique in techniques:
        tactics = technique.get("tactics", [])
        all_tactics.extend(tactics)

    tactic_names, counts = np.unique(
        all_tactics,
        return_counts=True
    )

    return tactic_names, counts




def count_by_platform(techniques):
    all_platforms = []

    for technique in techniques:
        platforms = technique.get("platforms", [])
        all_platforms.extend(platforms)

    platform_names, counts = np.unique(
        all_platforms,
        return_counts=True
    )

    return platform_names, counts



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




# Load data
techniques = load_techniques()

# Choose a technique (temporary test)
technique_id = "T1055.011"

# Find and display technique
technique = get_technique_detail(techniques, technique_id)
show_technique_detail(technique)





# Statistics by Tactic
tactic_names, tactic_counts = count_by_tactic(techniques)

st.subheader("Techniques by Tactic")
plot_tactic_chart(tactic_names, tactic_counts)

print("Tactic statistics:")
for name, count in zip(tactic_names, tactic_counts):
    print(name, ":", count)


# Statistics by Platform
platform_names, platform_counts = count_by_platform(techniques)

st.subheader("Techniques by Platform")
plot_platform_chart(platform_names, platform_counts)


# DISPLAY TACTIC TYPE STATISTICS
labels, tactic_type_counts, no_tactic = count_tactic_types(techniques)

st.subheader("Single-Tactic vs Multiple-Tactic")

plot_tactic_type_chart(labels, tactic_type_counts)

st.write("Single-Tactic:", tactic_type_counts[0])
st.write("Multiple-Tactic:", tactic_type_counts[1])
st.write("Techniques without Tactic:", no_tactic)