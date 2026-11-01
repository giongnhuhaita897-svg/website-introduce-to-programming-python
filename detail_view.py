import json
import streamlit as st      
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
 # Load data
techniques = load_techniques()

# Choose a technique
technique_id = "T1055.011"

# Find technique
technique = get_technique_detail(techniques, technique_id)

# Display technique
show_technique_detail(technique)