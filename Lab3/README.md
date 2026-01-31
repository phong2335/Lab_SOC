# Lab 3: Giám sát thay đổi Windows Registry bằng Splunk

# I. Mục tiêu

- Mục tiêu của lab giám sát và phát hiện các hành vi liên quan đến thay đổi Windows registry liên quan đến cơ chế persistence, Defense Evasion, Anti-forensics. Cụ thể, bài lab tập trung vào việc phát hiện hành vi thêm registry value độc hại vào các Run/RunOnce key, sửa và xóa các registry quan trọng và tạo service thông qua registry**.** Bài lab sử dụng Sysmon để ghi log và Splunk để giám sát và phát hiện hành vi này.

# II. Kiến thức nền

## 1. Windows Registry là gì?

- Registry là một cơ sở dữ liệu dùng để lưu trữ thông số kỹ thuật của Windows. Nó ghi nhận tất cả các thông tin và cài đặt cho những phần mềm bạn cài trên máy, các thiết bị phần cứng, hồ sơ người dùng, cấu hình hệ điều hành và nhiều thông tin khác nữa.
- Registry luôn được cập nhật khi người dùng có sự thay đổi trong các thành phần của Control Panel, File Associations và một số thay đổi trong Menu Options của một số ứng dụng,…

## 2. Cấu trúc key-value

- Registry có 2 thành phần chính: **key** và **value**. Trong đó key giống như thư mục. Một key có thể chứa thêm nhiều key khác (thư mục cha, thư mục con) hoặc chứa các value (giá trị, có thể là file text nhưng chỉ 1 dòng đơn giản).
- Đường dẫn đi từ key cha sang key con hơi giống với đường dẫn của thư mục trong Windows và tên của nó không quan trọng có viết hoa hay không.

  ![windows-registry-la-gi-dung-ra-sao-luu-y-khi-chi.jpg](images/3d8ca774-6b56-4b0c-9547-8c77ce42327c.png)
- Có tất cả **7 root key** trong Windows, bao gồm:
  - HKEY_LOCAL_MACHINE hoặc viết tắt là HKLM - hệ thống
  - HKEY_CURRENT_CONFIG hoặc HKCC (chỉ có trong Windows 9x và NT) - HARDWARE PROFILE
  - HKEY_CLASSES_ROOT hoặc HKCR - FILE / COM / ASSOCIATION
  - HKEY_CURRENT_USER hoặc HKCU - người dùng hiện tại
  - HKEY_USERS hoặc HKU - tất cả user
  - HKEY_PERFORMANCE_DATA (chỉ có trong Windows NT)
  - HKEY_DYN_DATA (chỉ có trong Windows 9x)
- Với mỗi root key nói riêng và các key nói chung, sẽ chỉ có những phần mềm nhất định được truy cập vào vì lý do bảo mật. Chính vì thế mà mỗi người dùng, phần mềm, dịch vụ sẽ chỉ thấy những key mà chúng được phép xem mà thôi.
- Value lại được lưu trữ theo dạng name/data, tức là mỗi value sẽ có tên của nó kèm theo giá trị thật. Một value có thể chứa data thuộc một trong các loại như:
  - REG_NONE: không có loại
  - REG_SZ: một chuỗi kí tự bất kì
  - REG_BINARY: dữ liệu nhị phân
  - REG_DWORD: một số nguyên
  - REG_LINK: một đường link dẫn tới một key Registry khác

# III. Sơ đồ mạng

![image.png](images/image.png)

# IV. Tiến hành thay đổi Windows registry

## 1. Persistence via Registry Run Key (HKCU) – Create Registry Value

- Chạy lệnh sau để thêm value trên Powershell
  ```powershell
  New-ItemProperty `
   -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
   -Name "SOC_Run_Test" `
   -Value "C:\Windows\System32\notepad.exe" `
   -PropertyType String -Force
  ```
- `New-ItemProperty`
  - Tạo property mới trong Registry
  - Trong Registry:
    - Item = Key
    - ItemProperty = Value
- `PropertyType String`
  - Kiểu dữ liệu của registry value
  - `String` = `REG_SZ`
- `-Force`
  - Nếu value `"SOC_Run_Test"` đã tồn tại:
    - Ghi đè giá trị cũ
  - Nếu chưa tồn tại:
    - Tạo mới

## 2. Persistence via Registry RunOnce Key (HKCU) - Create Registry Value

- Chạy lệnh sau trong Powershell
  ```powershell
  New-ItemProperty `
   -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" `
   -Name "SOC_RunOnce_Test" `
   -Value "C:\Windows\System32\calc.exe" `
   -PropertyType String -Force
  ```

## 3. Persistence via Windows Service – **Create Registry Key**

- Chạy lệnh sau trong Powershell as Administrator
  ```powershell
  sc.exe create SOCServiceTest binPath= "C:\Windows\System32\notepad.exe" start= auto
  sc.exe start SOCServiceTest
  ```
- `sc.exe`
  - **Service Control (SC)** utility của Windows. Dùng để tạo, cấu hình, sửa, xóa, điều khiển Windows services
- Khi chạy `sc create`, Windows sẽ:
  - Tạo key mới:
  ```
  HKLM\SYSTEM\CurrentControlSet\Services\SOCServiceTest
  ```

## 4. Defense Evasion via Registry Modification – Create Registry Key & Value

Disable Windows Defender

- Chạy lệnh sau trên Powershell
  ```powershell
  New-Item `
   "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force

  Set-ItemProperty `
   -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" `
   -Name "DisableAntiSpyware" `
   -Value 1 `
  ```
- `Value 1`
  - Dữ liệu của registry value
  - Ý nghĩa:
    - `0` → Defender bật
    - `1` → Defender bị vô hiệu hóa

## 5. Defense Evasion via Registry Deletion – Delete Registry Key

Remove Windows Defender Policies

- Chạy lệnh sau
  ```powershell
  Remove-Item `
   -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" `
   -Recurse -Force
  ```
- `Recurse`
  - Xóa toàn bộ subkey và value bên trong
  - Nếu không có `Recurse`:
    - PowerShell sẽ báo lỗi vì key không rỗng
- Đây là lệnh xóa toàn bộ registry key chính sách của Windows Defender, bao gồm tất cả subkey và value bên trong.

# V. Phát hiện và giám sát các hành vi độc hại này bằng Splunk

- Các `event ID` hay `EventCode` của sysmon
  | Event ID | Ý nghĩa                               |
  | -------- | ------------------------------------- |
  | **12**   | Create / Delete **Registry Key**      |
  | **13**   | Set (Add / Modify) **Registry Value** |
  | **14**   | Delete **Registry Value**             |

- Các `EventType` của sysmon
  - `1`: Critical (Nghiêm trọng)
  - `2`: Error (Lỗi)
  - `3`: Warning (Cảnh báo)
  - `4`: Information (Thông tin)

## 1. Phát hiện Persistence – Run

- `index=sysmon EventCode=13`
- Log
  ```powershell
  12/22/2025 03:27:58.616 PM
  LogName=Microsoft-Windows-Sysmon/Operational
  EventCode=13
  EventType=4
  ComputerName=DESKTOP-NDBEF0H
  User=NOT_TRANSLATED
  Sid=S-1-5-18
  SidType=0
  SourceName=Microsoft-Windows-Sysmon
  Type=Information
  RecordNumber=9406
  Keywords=None
  TaskCategory=Registry value set (rule: RegistryEvent)
  OpCode=Info
  Message=Registry value set:
  RuleName: T1060,RunKey
  EventType: SetValue
  UtcTime: 2025-12-22 08:27:58.603
  ProcessGuid: {e237abb6-00ff-6949-2301-000000002100}
  ProcessId: 7132
  Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  TargetObject: HKU\S-1-5-21-89911650-480286385-2846434076-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SOC_Run_Test
  Details: C:\Windows\System32\notepad.exe
  User: DESKTOP-NDBEF0H\po230
  ```
- Tóm tắt: Một tiến trình PowerShell đã tạo registry Run Key ở HKCU để thiết lập persistence cho user `po230`, trỏ tới `notepad.exe`.
- Thời gian
  - **UTC:** `2025-12-22 08:27:58`
  - **Local:** `03:27:58 PM`
- **ComputerName:** `DESKTOP-NDBEF0H`
- User context
  - **User:** `DESKTOP-NDBEF0H\po230`
  - **SID:** `S-1-5-21-...-1001` → **user thường**
  - **Sid=S-1-5-18** (LocalSystem) → do Sysmon log dưới SYSTEM
- Process thực hiện
  - **Image:**
    ```
    C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
    ```
  - **ProcessId:** `7132`
  - **(Process Globally Unique Identifier)ProcessGuid:** `{e237abb6-00ff-6949-2301-000000002100}`
- Hành vi : Tiến trình Registry đã tạo hoặc chỉnh sửa một giá trị trong Registry tại vị trí Run Key
  ```powershell
  TargetObject: HKU\S-1-5-21-89911650-480286385-2846434076-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SOC_Run_Test
  ```
- Giá trị registry: nghĩa là mỗi khi user logon, windows sẽ chạy notepad.exe
  ```
  Details: C:\Windows\System32\notepad.exe
  ```
- MAPPING MITRE ATT&CK
  - **Tactic:** Persistence
  - **Technique:**
    - **T1547.001 – Registry Run Keys / Startup Folder (MITTRE mới không còn là T1060)**

## 2. Phát hiện Persistence – RunOnce

- `index=sysmon EventCode=13`
- Log
  ```powershell
  12/22/2025 03:32:59.114 PM
  LogName=Microsoft-Windows-Sysmon/Operational
  EventCode=13
  EventType=4
  ComputerName=DESKTOP-NDBEF0H
  User=NOT_TRANSLATED
  Sid=S-1-5-18
  SidType=0
  SourceName=Microsoft-Windows-Sysmon
  Type=Information
  RecordNumber=9493
  Keywords=None
  TaskCategory=Registry value set (rule: RegistryEvent)
  OpCode=Info
  Message=Registry value set:
  RuleName: T1060,RunKey
  EventType: SetValue
  UtcTime: 2025-12-22 08:32:59.104
  ProcessGuid: {e237abb6-00ff-6949-2301-000000002100}
  ProcessId: 7132
  Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  TargetObject: HKU\S-1-5-21-89911650-480286385-2846434076-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\SOC_RunOnce_Test
  Details: C:\Windows\System32\calc.exe
  User: DESKTOP-NDBEF0H\po230
  ```
- Tóm tắt: Một tiến trình powershell đã tạo thêm registry Run Once ở HKCU để thiết lập persistance cho user po230, tự khởi động `calc.exe`
- Time:
  - UTC: `2025-12-22 08:32:59.104`
  - Local: `12/22/2025 03:32:59.114 PM`
- ComputerName=`DESKTOP-NDBEF0H`
- User context:
  - User: `DESKTOP-NDBEF0H\po230`
  - Sid=S-1-5-18 (đây là sid của sysmon)
- Process thực hiện
  ```powershell
  Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  ```
  - ProcessId: `7132`
  - ProcessGuid: `{e237abb6-00ff-6949-2301-000000002100}`
- Hành vi: tiến trình registry đã tạo hoặc chỉnh sửa một giá trị trong Registry tại vị trí RunOnce
  ```powershell
  TargetObject: HKU\S-1-5-21-89911650-480286385-2846434076-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\SOC_RunOnce_Test
  ```
- Giá trị Registry: khi windows khởi động lần đầu tiên sau khi registry này được tạo thì nó sẽ tự khởi động `calc.exe` (khác với Run Key là RunOnce chỉ khởi động một lần)
  ```powershell
  Details: C:\Windows\System32\calc.exe
  ```
- MAPPING MITRE ATT&CK
  - **Tactic:** Persistence
  - **Technique:**
    - **T1547.001 – Registry Run Keys / Startup Folder (MITTRE mới không còn là T1060)**

## 3. Phát hiện Persistence – Services

-
- Log
  ```powershell
  12/22/2025 03:33:41.869 PM
  LogName=Microsoft-Windows-Sysmon/Operational
  EventCode=13
  EventType=4
  ComputerName=DESKTOP-NDBEF0H
  User=NOT_TRANSLATED
  Sid=S-1-5-18
  SidType=0
  SourceName=Microsoft-Windows-Sysmon
  Type=Information
  RecordNumber=9536
  Keywords=None
  TaskCategory=Registry value set (rule: RegistryEvent)
  OpCode=Info
  Message=Registry value set:
  RuleName: T1031,T1050
  EventType: SetValue
  UtcTime: 2025-12-22 08:33:41.854
  ProcessGuid: {e237abb6-00cf-6949-0b00-000000002100}
  ProcessId: 644
  Image: C:\Windows\system32\services.exe
  TargetObject: HKLM\System\CurrentControlSet\Services\SOCServiceTest\ImagePath
  Details: C:\Windows\System32\notepad.exe
  User: NT AUTHORITY\SYSTEM
  ```
  ```powershell
  12/22/2025 03:33:41.869 PM
  LogName=Microsoft-Windows-Sysmon/Operational
  EventCode=13
  EventType=4
  ComputerName=DESKTOP-NDBEF0H
  User=NOT_TRANSLATED
  Sid=S-1-5-18
  SidType=0
  SourceName=Microsoft-Windows-Sysmon
  Type=Information
  RecordNumber=9535
  Keywords=None
  TaskCategory=Registry value set (rule: RegistryEvent)
  OpCode=Info
  Message=Registry value set:
  RuleName: T1031,T1050
  EventType: SetValue
  UtcTime: 2025-12-22 08:33:41.854
  ProcessGuid: {e237abb6-00cf-6949-0b00-000000002100}
  ProcessId: 644
  Image: C:\Windows\system32\services.exe
  TargetObject: HKLM\System\CurrentControlSet\Services\SOCServiceTest\Start
  Details: DWORD (0x00000002)
  User: NT AUTHORITY\SYSTEM
  ```
- Tóm tắt: Windows Service `SOCServiceTest` đã được cấu hình để tự khởi động cùng hệ thống bằng cách chỉnh sửa các registry value quan trọng (`ImagePath` và `Start`) dưới nhánh `HKLM\SYSTEM\CurrentControlSet\Services`.
  Hành vi này được thực hiện bởi tiến trình `services.exe` với quyền SYSTEM, cho thấy persistence cấp hệ thống (system-level persistence).
- Khi tạo service (`sc create`), Windows sẽ:
  1. Tạo **ImagePath** → binary sẽ chạy
  2. Tạo **Start** → xác định khi nào service chạy


      ➡️ Sysmon ghi nhận mỗi registry value set là 1 event riêng
- Time:
  - UtcTime: `2025-12-22 08:33:41.854`
  - Local: `12/22/2025 03:33:41.869 PM`
- ComputerName=`DESKTOP-NDBEF0H`
- User: NT AUTHORITY\SYSTEM (hacker tạo tiến service (`sc create`) thì hệ thống sẽ tự set các value Register này)
- Register bị chỉnh tại log tạo ImagePath:
  ```powershell
  TargetObject: HKLM\System\CurrentControlSet\Services\SOCServiceTest\ImagePath
  ```
  - Giá trị registry chi tiết là:
  ```powershell
  Details: C:\Windows\System32\notepad.exe
  ```
- Giá trị Registry bị chỉnh tại log tạo Start
  ```powershell
  TargetObject: HKLM\System\CurrentControlSet\Services\SOCServiceTest\Start
  ```
  - Giá trị registry chi tiết là:
  ```powershell
  Details: DWORD (0x00000002)
  ```
  - Ý nghĩa `Start=2`
    | Giá trị | Ý nghĩa                      |
    | ------- | ---------------------------- |
    | 0       | Boot                         |
    | 1       | System                       |
    | **`2`** | **`Automatic (Auto-start)`** |
    | 3       | Manual                       |
    | 4       | Disabled                     |
  `0x2` = **Service sẽ tự khởi động khi boot**
- MAPPING MITRE ATT&CK
  - Tactic: Persistence
  - Technique: Create or Modify System Process
  - Sub-technique: Windows Service
  - ID: T1543.003

## 4. Phát hiện Disable Windows Defender

-
- Log
  ```powershell
  12/22/2025 03:38:11.747 PM
  LogName=Microsoft-Windows-Sysmon/Operational
  EventCode=13
  EventType=4
  ComputerName=DESKTOP-NDBEF0H
  User=NOT_TRANSLATED
  Sid=S-1-5-18
  SidType=0
  SourceName=Microsoft-Windows-Sysmon
  Type=Information
  RecordNumber=9639
  Keywords=None
  TaskCategory=Registry value set (rule: RegistryEvent)
  OpCode=Info
  Message=Registry value set:
  RuleName: T1089,Tamper-Defender
  EventType: SetValue
  UtcTime: 2025-12-22 08:38:11.745
  ProcessGuid: {e237abb6-00ff-6949-2301-000000002100}
  ProcessId: 7132
  Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  TargetObject: HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware
  Details: DWORD (0x00000001)
  User: DESKTOP-NDBEF0H\po230
  ```
- Tóm tắt: Tiến trình powershell đã sửa Registry ở mức hệ thống (HKLM) để vô hiệu hóa Windows Defender bằng cách đặt DisableAntiSpyware=1. Đây là hành vi né tránh phòng thủ (Defense Evasion) có mức độ rủi ro cao/
- Time:
  - UtcTime: `2025-12-22 08:38:11.745`
  - Local: `12/22/2025 03:38:11.747 PM`
- ComputerName=`DESKTOP-NDBEF0H`
- User: `DESKTOP-NDBEF0H\po230`
- Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- Hành vi: đặt value `DisableAntiSpyware=1`
  ```powershell
  TargetObject: HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware
  ```
  ```powershell
  Details: DWORD (0x00000001)
  ```
- Mapping MITTRE ATT&CK
  - Tactic: Defense Evasion
  - Technique: Impair Defense
  - Sub-technique: Disable or Modify tools
  - ID: T1562.001

