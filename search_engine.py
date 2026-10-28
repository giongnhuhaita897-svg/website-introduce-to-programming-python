import json

with open('enterprise-attack-20.0.json', 'r', encoding='utf-8') as file:
    data = json.load(file)
print(data.keys())

import json

def load_attack_data(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def search_techniques(data, keyword=None, technique_id=None, tactic=None):
    results = []
    objects = data.get('objects', [])
    
    for obj in objects:
        # Chỉ xét các đối tượng là 'attack-pattern' (đại diện cho kỹ thuật)
        if obj.get('type') == 'attack-pattern':
            match = True
            
            # 1. Lọc theo Mã ID (ví dụ: T1059)
            if technique_id:
                id_match = False
                for ref in obj.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack' and ref.get('external_id') == technique_id:
                        id_match = True
                        break
                if not id_match:
                    match = False
            
            # 2. Lọc theo Từ khóa trong tên hoặc mô tả
            if keyword and match:
                kw = keyword.lower()
                name = obj.get('name', '').lower()
                description = obj.get('description', '').lower()
                if kw not in name and kw not in description:
                    match = False
            
            # 3. Lọc theo Tactic (Chiến thuật)
            if tactic and match:
                tactic_match = False
                for phase in obj.get('kill_chain_phases', []):
                    if phase.get('kill_chain_name') == 'mitre-attack' and phase.get('phase_name') == tactic:
                        tactic_match = True
                        break
                if not tactic_match:
                    match = False
            
            if match:
                results.append({
                    'id': next((ref.get('external_id') for ref in obj.get('external_references', []) if ref.get('source_name') == 'mitre-attack'), 'N/A'),
                    'name': obj.get('name')
                })
                
    return results

# --- PHẦN CHẠY THỬ ---
if __name__ == '__main__':
    # Đọc dữ liệu từ file JSON của bạn
    data = load_attack_data('enterprise-attack-20.0.json')
    
    # Ví dụ 1: Tìm kiếm theo mã ID 'T1059'
    print("--- Tìm theo ID T1059 ---")
    print(search_techniques(data, technique_id='T1059'))
    
    # Ví dụ 2: Tìm kiếm theo từ khóa 'execution'
    print("--- Tìm theo từ khóa 'execution' ---")
    print(search_techniques(data, keyword='execution')[:5]) # In ra 5 kết quả đầu tiên