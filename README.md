# Website-introduce-to-programming-python

## 1. Project Overview & Dataset Version

- Our team is developing an offline lookup tool based on the MITRE ATT&CK Enterprise dataset
- The main source that we use is: https://github.com/mitre-attack/attack-stix-data
- Fixed file: enterprise-attack-20.0.json (STIX 2.1)
- The latest version and time: The latest version is currently ATT&CK version 20.0, with the most recent modifications made between November 9 and November 14, 2026

## 2. Data-Model Note

| Json field name                              | Meaning and how our team processes it                                                                                                                                                        |
| -------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `objects`                                    | The root list containing all objects in the STIX JSON file.                                                                                                                                  |
| `type == "attack-pattern"`                   | Used to identify objects representing attack techniques (Techniques). At the same time, objects marked with revoked: true or x_mitre_deprecated: true are excluded.                          |
| `id`                                         | A unique internal identifier used to connect related objects through relationship objects                                                                                                    |
| `external_references`                        | The field from which our team filters entries with source_name == "mitre-attack" to retrieve the ATT&CK ID (e.g., T1059) and the corresponding url.                                          |
| `kill_chain_phases ` and `x_mitre_platforms` | Used to extract lists of Tactics (phase_name, such as execution and initial-access) and affected operating systems or platforms (Windows, Linux, and macOS).                                 |
| `type == "relationship"`                     | Identifies relationship objects that use the source_ref and target_ref fields to link a Technique (attack-pattern) to a Mitigation (course-of-action) or an Adversary Group (intrusion-set). |
| `type == "x-mitre-collection"`               | Extracts dataset metadata including `x_mitre_version` (e.g., 20.0) and `modified` timestamp for report headers.                                                                              |

## 3. Manual Cross-Check (20 Techniques Validation)

We manually cross-checked 20 extracted techniques from our parser against the official MITRE ATT&CK Enterprise knowledge base and raw STIX JSON:

## 3. Manual Cross-Check (20 Techniques Validation)

We manually cross-checked the 20 extracted techniques in `sample_attack.json` against the official MITRE ATT&CK Enterprise knowledge base:

| #   | ATT&CK ID   | Technique Name                       | Extracted Tactics                                       | Extracted Platforms                          | Verification Result                                                      |
| :-- | :---------- | :----------------------------------- | :------------------------------------------------------ | :------------------------------------------- | :----------------------------------------------------------------------- |
| 1   | `T1055.011` | Extra Window Memory Injection        | `defense-evasion`, `privilege-escalation`               | Windows                                      | Matched ([Official Page](https://attack.mitre.org/techniques/T1055/011)) |
| 2   | `T1053.005` | Scheduled Task                       | `execution`, `persistence`, `privilege-escalation`      | Windows                                      | Matched ([Official Page](https://attack.mitre.org/techniques/T1053/005)) |
| 3   | `T1205.002` | Socket Filters                       | `defense-evasion`, `persistence`, `command-and-control` | Linux, macOS, Windows                        | Matched ([Official Page](https://attack.mitre.org/techniques/T1205/002)) |
| 4   | `T1560.001` | Archive via Utility                  | `collection`                                            | Linux, macOS, Windows                        | Matched ([Official Page](https://attack.mitre.org/techniques/T1560/001)) |
| 5   | `T1021.005` | VNC                                  | `lateral-movement`                                      | Linux, Windows, macOS                        | Matched ([Official Page](https://attack.mitre.org/techniques/T1021/005)) |
| 6   | `T1047`     | Windows Management Instrumentation   | `execution`                                             | Windows                                      | Matched ([Official Page](https://attack.mitre.org/techniques/T1047))     |
| 7   | `T1687`     | Exploitation for Defense Impairment  | `defense-impairment`                                    | IaaS, Linux, macOS, SaaS, Windows            | Matched ([Official Page](https://attack.mitre.org/techniques/T1687))     |
| 8   | `T1113`     | Screen Capture                       | `collection`                                            | Linux, macOS, Windows                        | Matched ([Official Page](https://attack.mitre.org/techniques/T1113))     |
| 9   | `T1027.011` | Fileless Storage                     | `defense-evasion`                                       | Linux, Windows                               | Matched ([Official Page](https://attack.mitre.org/techniques/T1027/011)) |
| 10  | `T1037`     | Boot or Logon Initialization Scripts | `persistence`, `privilege-escalation`                   | ESXi, Linux, macOS, Network Devices, Windows | Matched ([Official Page](https://attack.mitre.org/techniques/T1037))     |
| 11  | `T1557`     | Adversary-in-the-Middle              | `credential-access`, `collection`                       | Linux, macOS, Network Devices, Windows       | Matched ([Official Page](https://attack.mitre.org/techniques/T1557))     |
| 12  | `T1033`     | System Owner/User Discovery          | `discovery`                                             | Linux, macOS, Network Devices, Windows       | Matched ([Official Page](https://attack.mitre.org/techniques/T1033))     |
| 13  | `T1583`     | Acquire Infrastructure               | `resource-development`                                  | PRE                                          | Matched ([Official Page](https://attack.mitre.org/techniques/T1583))     |
| 14  | `T1218.011` | Rundll32                             | `defense-evasion`                                       | Windows                                      | Matched ([Official Page](https://attack.mitre.org/techniques/T1218/011)) |
| 15  | `T1613`     | Container and Resource Discovery     | `discovery`                                             | Containers                                   | Matched ([Official Page](https://attack.mitre.org/techniques/T1613))     |
| 16  | `T1583.007` | Serverless                           | `resource-development`                                  | PRE                                          | Matched ([Official Page](https://attack.mitre.org/techniques/T1583/007)) |
| 17  | `T1132.001` | Standard Encoding                    | `command-and-control`                                   | ESXi, Linux, macOS, Windows                  | Matched ([Official Page](https://attack.mitre.org/techniques/T1132/001)) |
| 18  | `T1027.009` | Embedded Payloads                    | `defense-evasion`                                       | Linux, macOS, Windows                        | Matched ([Official Page](https://attack.mitre.org/techniques/T1027/009)) |
| 19  | `T1556.003` | Pluggable Authentication Modules     | `defense-evasion`, `persistence`, `credential-access`   | Linux, macOS                                 | Matched ([Official Page](https://attack.mitre.org/techniques/T1556/003)) |
| 20  | `T1578.004` | Revert Cloud Instance                | `defense-evasion`                                       | IaaS                                         | Matched ([Official Page](https://attack.mitre.org/techniques/T1578/004)) |

## 4. Setup & Team Split

### 4.1. Setup & Execution

- Environment: Python 3.11+, standard json & csv modules, numpy, matplotlib, and streamlit.

```bash
pip install streamlit numpy matplotlib
streamlit run WebIntro.py
```

### 4.2 Team Split

| Role         | Branch                | File                   | Key Responsibilities                                                                                                                                                  |
| ------------ | --------------------- | ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Ngoc(leader) | giao-dien-chinh       | WebIntro.py, README.md | Responsible for the main interface, displaying the dataset version and date, exporting the normalized_techniques.csv file, and validating 20 attack techniques.       |
| Ha           | feature/data-loader   | data_loader.py         | Responsible for reading STIX JSON files, filtering out revoked/deprecated objects, and implementing the Technique class using Object-Oriented Programming (OOP).      |
| Tu           | feature/search-filter | search_engine.py       | Responsible for building search indexes (indexes), implementing filtering and sorting functions, and linking relationships using STIX Object IDs.                     |
| Dung         | dung-attack-details   | detail_view.py         | Responsible for displaying detailed attack technique information, using NumPy to perform multi-tactic statistics, and creating three visualizations using Matplotlib. |
