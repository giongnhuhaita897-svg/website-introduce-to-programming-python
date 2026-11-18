import csv
import streamlit as st

import data_loader
import search_engine
import detail_view


st.set_page_config(page_title="MITRE ATT&CK Browser", layout="wide")
st.title("MITRE ATT&CK Technique Browser")

try:
    techniques, version_info = data_loader.load_techniques("enterprise-attack-20.0.json")
    dataset_source = "Enterprise STIX 2.1"
except FileNotFoundError:
    st.warning("Không tìm thấy enterprise-attack-20.0.json. Đang dùng sample_attack.json (20 kỹ thuật mẫu).")
    techniques, version_info = data_loader.load_techniques("sample_attack.json")
    dataset_source = "Sample normalized techniques"

dataset_version = version_info.get("version") or "N/A"
dataset_date = version_info.get("modified") or "N/A"
st.caption(f"Dataset: {dataset_source} | Version: {dataset_version} | Modified: {dataset_date}")

indexes = search_engine.build_indexes(techniques)
unique_values = search_engine.get_unique_tactics_and_platforms(techniques)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Tổng kỹ thuật", len(techniques))
multi_count = 0
mitigation_count = 0
for tech in techniques:
    if len(tech.get("tactics") or []) >= 2:
        multi_count += 1
    mitigation_count += len(tech.get("mitigations") or [])
col2.metric("Có từ 2 tactics", multi_count)
col3.metric("Tactics được lập chỉ mục", len(indexes["by_tactic"]))
col4.metric("Liên kết mitigation", mitigation_count)

st.sidebar.header("Bộ lọc tra cứu")
keyword = st.sidebar.text_input("Tìm theo ID, tên hoặc mô tả:")
tactic_options = ["All"]
for tactic in unique_values["tactics"]:
    tactic_options.append(tactic)
tactic = st.sidebar.selectbox("Tactic:", tactic_options)
platform_options = ["All"]
for platform in unique_values["platforms"]:
    platform_options.append(platform)
platform = st.sidebar.selectbox("Platform:", platform_options)
multi_only = st.sidebar.checkbox("Chỉ kỹ thuật có từ 2 tactics")
sort_by = st.sidebar.selectbox("Sắp xếp:", ["ID (A-Z)", "Name (A-Z)"])

ket_qua = search_engine.search_and_filter(
    techniques,
    keyword=keyword,
    tactic=tactic,
    platform=platform,
    multi_only=multi_only,
    sort_by=sort_by,
)
st.write("Số kỹ thuật tìm thấy:", len(ket_qua))
cot_trai, cot_phai = st.columns(2)

with cot_trai:
    st.subheader("Danh sách kỹ thuật")
    rows = []
    for tech in ket_qua:
        rows.append({
            "ID": tech.get("id") or "N/A",
            "Name": tech.get("name") or "",
            "Tactics": ", ".join(tech.get("tactics") or []),
            "Platforms": ", ".join(tech.get("platforms") or []),
        })
    st.dataframe(rows)
    selected_id = ""
    if ket_qua:
        ids = []
        for tech in ket_qua:
            ids.append(tech.get("id") or "N/A")
        selected_id = st.selectbox("Chọn ATT&CK ID:", ids)
    else:
        st.info("Không tìm thấy kỹ thuật phù hợp.")

with cot_phai:
    st.subheader("Thông tin chi tiết")
    selected_tech = None
    if selected_id:
        selected_tech = indexes["by_id"].get(selected_id.upper())
    detail_view.render_technique_detail(selected_tech)

st.subheader("Thống kê và biểu đồ")
detail_view.render_summary_plots(ket_qua)

st.sidebar.subheader("Xuất báo cáo CSV")
if st.sidebar.button("Lưu normalized_techniques.csv"):
    with open("normalized_techniques.csv", "w", newline="", encoding="utf-8") as output_file:
        writer = csv.writer(output_file)
        writer.writerow([
            "dataset_version", "dataset_date", "id", "stix_id", "name",
            "description", "platforms", "tactics", "mitigations_count", "url",
        ])
        for tech in ket_qua:
            writer.writerow([
                dataset_version,
                dataset_date,
                tech.get("id") or "",
                tech.get("stix_id") or "",
                tech.get("name") or "",
                tech.get("description") or "",
                ", ".join(tech.get("platforms") or []),
                ", ".join(tech.get("tactics") or []),
                len(tech.get("mitigations") or []),
                tech.get("url") or "",
            ])
    st.sidebar.success("Đã lưu normalized_techniques.csv trong thư mục đang chạy ứng dụng.")
