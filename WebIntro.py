import streamlit as st

st.title("Trình duyệt MITRE ATT&CK")
st.write("Xin chào! Đây là bản chạy thử đầu tiên của nhóm.")

tu_khoa = st.text_input("Nhập thử một mã kỹ thuật (ví dụ: T1059):")
if tu_khoa:
    st.success(f"Bạn vừa tìm kiếm mã: {tu_khoa}")