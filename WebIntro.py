import csv
import json
import streamlit as st

# 1. Cau hinh trang web mo rong toan man hinh
st.set_page_config(page_title="MITRE ATT&CK Browser", layout="wide")
st.title("MITRE ATT&CK Technique Browser")
st.caption(
    "Dataset: Enterprise ATT&CK STIX 2.1 | Version: 20.0 | Release: 2026-04-25"
)

# 2. Du lieu du phong nho (Phong hờ truong hop chua copy file sample_attack.json vao thu muc)
DU_LIEU_MAC_DINH = [
    {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "description": (
            "Adversaries may abuse command and script interpreters to execute"
            " commands."
        ),
        "tactics": ["execution"],
        "platforms": ["Windows", "Linux", "macOS"],
        "url": "https://attack.mitre.org/techniques/T1059",
        "mitigations": [],
    },
    {
        "id": "T1566",
        "name": "Phishing",
        "description": (
            "Adversaries may send phishing messages to gain access to victim"
            " systems."
        ),
        "tactics": ["initial-access"],
        "platforms": ["Windows", "Linux", "macOS"],
        "url": "https://attack.mitre.org/techniques/T1566",
        "mitigations": [],
    },
]

# 3. Doc du lieu: Uu tien data_loader.py -> sample_attack.json -> DU_LIEU_MAC_DINH
Du_lieu_Gia = []

try:
  from data_loader import load_techniques

  Du_lieu_Gia = load_techniques("enterprise-attack-20.0.json")
except Exception:
  try:
    with open("sample_attack.json", "r", encoding="utf-8") as f:
      Du_lieu_Gia = json.load(f)
  except FileNotFoundError:
    st.warning(
        "Chua tim thay file sample_attack.json trong thu muc du an. Dang hien"
        " thi 2 ky thuat mac dinh."
    )
    Du_lieu_Gia = DU_LIEU_MAC_DINH

if len(Du_lieu_Gia) == 0:
  Du_lieu_Gia = DU_LIEU_MAC_DINH

# 4. Chuan hoa ten tactic bi lech ("stealth" -> "defense-evasion") theo dung chuan MITRE
for tech in Du_lieu_Gia:
  ds_tac_chuan = []
  for t in tech.get("tactics", []):
    if t == "stealth":
      ds_tac_chuan.append("defense-evasion")
    else:
      ds_tac_chuan.append(t)
  tech["tactics"] = ds_tac_chuan

# 5. Tinh toan tu dong 4 o chi so thong ke o dau trang
tong_so = len(Du_lieu_Gia)
so_da_tactic = 0
tong_so_tactic = 0
tong_so_mitigation = 0

for tech in Du_lieu_Gia:
  so_tactic_cua_tech = len(tech.get("tactics", []))
  tong_so_tactic = tong_so_tactic + so_tactic_cua_tech
  if so_tactic_cua_tech >= 2:
    so_da_tactic = so_da_tactic + 1
  tong_so_mitigation = tong_so_mitigation + len(tech.get("mitigations", []))

if tong_so > 0:
  trung_binh_tactic = round(tong_so_tactic / tong_so, 2)
else:
  trung_binh_tactic = 0

col1, col2, col3, col4 = st.columns(4)
col1.metric("Tong so Ky thuat", tong_so)
col2.metric("Da chien thuat (>= 2)", so_da_tactic)
col3.metric("TB Tactic / Ky thuat", trung_binh_tactic)
col4.metric("Tong lien ket Mitigation", tong_so_mitigation)

# 6. Tao thanh bo loc o ben trai (Sidebar)
st.sidebar.header("Bo loc tra cuu")

tu_khoa = st.sidebar.text_input("Tim theo ID hoac Ten:")

ds_tactics = ["All"]
for tech in Du_lieu_Gia:
  for t in tech.get("tactics", []):
    if t not in ds_tactics:
      ds_tactics.append(t)
chon_tactic = st.sidebar.selectbox("Chon Tactic:", ds_tactics)

ds_platforms = ["All"]
for tech in Du_lieu_Gia:
  for p in tech.get("platforms", []):
    if p not in ds_platforms:
      ds_platforms.append(p)
chon_platform = st.sidebar.selectbox("Chon Platform:", ds_platforms)

da_tactic = st.sidebar.checkbox("Chi hien ky thuat co nhieu Tactic (>= 2)")
kieu_sap_xep = st.sidebar.selectbox(
    "Sap xep theo:", ["Ma ID (A-Z)", "Ten ky thuat (A-Z)"]
)

# 7. Loc danh sach ky thuat theo cac dieu kien nguoi dung chon
ket_qua = []
tu_khoa_thuong = tu_khoa.strip().lower()

for tech in Du_lieu_Gia:
  if tu_khoa_thuong != "":
    ma_id = tech.get("id", "").lower()
    ten_kt = tech.get("name", "").lower()
    mo_ta = tech.get("description", "").lower()
    if (
        tu_khoa_thuong not in ma_id
        and tu_khoa_thuong not in ten_kt
        and tu_khoa_thuong not in mo_ta
    ):
      continue

  if chon_tactic != "All":
    if chon_tactic not in tech.get("tactics", []):
      continue

  if chon_platform != "All":
    if chon_platform not in tech.get("platforms", []):
      continue

  if da_tactic == True:
    if len(tech.get("tactics", [])) < 2:
      continue

  ket_qua.append(tech)

# 8. Sap xep danh sach ket_qua theo lua chon
n = len(ket_qua)
for i in range(n):
  for j in range(i + 1, n):
    if kieu_sap_xep == "Ma ID (A-Z)":
      if ket_qua[i].get("id", "") > ket_qua[j].get("id", ""):
        tam = ket_qua[i]
        ket_qua[i] = ket_qua[j]
        ket_qua[j] = tam
    else:
      if ket_qua[i].get("name", "") > ket_qua[j].get("name", ""):
        tam = ket_qua[i]
        ket_qua[i] = ket_qua[j]
        ket_qua[j] = tam

# 9. Chia 2 cot man hinh: Cot trai (Bang danh sach) va Cot phai (Chi tiet)
st.write("So ky thuat tim thay:", len(ket_qua))
cot_trai, cot_phai = st.columns(2)

with cot_trai:
  st.subheader("Danh sach ky thuat")

  if len(ket_qua) > 0:
    bang_tom_tat = []
    for tech in ket_qua:
      bang_tom_tat.append({
          "ID": tech.get("id", "N/A"),
          "Name": tech.get("name", ""),
          "Tactics": ", ".join(tech.get("tactics", [])),
          "Platforms": ", ".join(tech.get("platforms", [])),
      })
    st.dataframe(bang_tom_tat)

    ds_id = []
    for tech in ket_qua:
      ds_id.append(tech.get("id", "N/A"))

    id_dang_chon = st.selectbox("Chon ma ID de xem chi tiet:", ds_id)
  else:
    st.write("Khong tim thay ky thuat nao phu hop.")
    id_dang_chon = ""

with cot_phai:
  st.subheader("Thong tin chi tiet")

  for tech in ket_qua:
    if tech.get("id") == id_dang_chon:
      st.write("Ma ky thuat:", tech.get("id", "N/A"))
      st.write("Ten ky thuat:", tech.get("name", ""))
      st.write("Tactics:", ", ".join(tech.get("tactics", [])))
      st.write("Platforms:", ", ".join(tech.get("platforms", [])))
      st.write("Link:", tech.get("url", ""))
      st.write("Mo ta:", tech.get("description", ""))

      st.subheader("Bien phap phong chong (Mitigations)")
      ds_miti = tech.get("mitigations", [])
      if len(ds_miti) > 0:
        for m in ds_miti:
          st.write(
              "- **" + m.get("id", "") + " - " + m.get("name", "") + "**:"
          )
          st.write(m.get("description", ""))
      else:
        st.write("Chua co bien phap phong chong cu the.")

# 10. Nut xuat file normalized_techniques.csv o cuoi thanh Sidebar
st.sidebar.subheader("Xuat bao cao CSV")

if st.sidebar.button("Luu file normalized_techniques.csv"):
  with open(
      "normalized_techniques.csv", "w", newline="", encoding="utf-8"
  ) as f:
    writer = csv.writer(f)
    writer.writerow(
        ["id", "name", "tactics", "platforms", "mitigations_count", "url"]
    )

    for tech in ket_qua:
      chuoi_tactics = ", ".join(tech.get("tactics", []))
      chuoi_platforms = ", ".join(tech.get("platforms", []))
      so_mitigation = len(tech.get("mitigations", []))

      writer.writerow([
          tech.get("id", ""),
          tech.get("name", ""),
          chuoi_tactics,
          chuoi_platforms,
          so_mitigation,
          tech.get("url", ""),
      ])

  st.sidebar.success("Da luu file normalized_techniques.csv thanh cong!")