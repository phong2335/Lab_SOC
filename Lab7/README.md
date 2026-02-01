# Lab 7: Phát hiện và điều các tác vụ lên lịch đáng ngờ trên Windows

## I. Mục tiêu

- Mục tiêu của lab này là phát hiện và điều tra và ứng phó với các Schedule Task đáng ngờ trên Windows, có thể được sử dụng cho mục đích persistence. Sử dụng Sysmon và Splunk để giám sát và phân tích log.

## II. Sơ đồ mạng, môi trường và công cụ

![image.png](image.png)

- Schedule Task (hay chính xác là công cụ Task Scheduler) trên Windows là một tiện ích hệ thống cho phép tự động hóa việc thực thi các chương trình, tập lệnh hoặc tác vụ cụ thể vào một thời điểm hoặc sau một sự kiện nhất định. Ví dụ:
  - Hẹn giờ tắt máy hoặc khởi động lại định kỳ.
  - Tự động dọn dẹp rác hệ thống hoặc sao lưu dữ liệu hàng ngày/tuần.
  - Chạy script (như Python, PowerShell) hoặc mở ứng dụng ngay khi máy tính khởi động hoặc người dùng đăng nhập.
  - Gửi thông báo hoặc email (trong các phiên bản Windows cũ) dựa trên các sự kiện lỗi hệ thống.

## III. Mô phỏng hành động lên lịch độc hại

1. Tạo một tác vụ lên lịch mới

   ```
   schtasks /create /tn "MaliciousTask" /tr "C:\malware.exe" /sc once /st 12:00
   ```

   - `/create`: Tạo mới.
   - `/tn` (Task Name): Đặt tên là `MaliciousTask` (Hacker thường đặt tên giả như `WinUpdate`, `SystemHealth` để lừa admin).
   - `/tr` (Task Run): Đường dẫn file cần chạy.
   - `/sc` (Schedule): Tần suất (ở đây là `once` - một lần). Thường hacker sẽ dùng `onlogon` (khi đăng nhập) hoặc `daily` (hàng ngày).
   - `/st` (Start Time): Thời gian bắt đầu.

2. Thay đổi một Schedule Task có sẵn

   ```
   schtasks /change /tn "MaliciousTask" /tr "C:\evil_script.ps1"
   ```

3. Thực thi một Schedule Task

   ```powershell
   schtasks /run /tn "MaliciousTask"
   ```

4. Xóa một Schedule Task

   ```
   schtasks /delete /tn "MaliciousTask" /f
   ```

   - `/f` là Force: ép buộc, cưỡng chế

## IV. Phát hiện và điều tra

- SPL
  ```powershell
  index=sysmon EventCode=1 Image="*schtasks.exe"
  ```
- Log
  ```powershell
  01/31/2026 10:38:34.049 PM
  LogName=Microsoft-Windows-Sysmon/Operational
  EventCode=1
  EventType=4
  ComputerName=DESKTOP-NDBEF0H
  User=NOT_TRANSLATED
  Sid=S-1-5-18
  SidType=0
  SourceName=Microsoft-Windows-Sysmon
  Type=Information
  RecordNumber=15445
  Keywords=None
  TaskCategory=Process Create (rule: ProcessCreate)
  OpCode=Info
  Message=Process Create:
  RuleName: -
  UtcTime: 2026-01-31 15:38:34.036
  ProcessGuid: {e237abb6-21fa-697e-0b01-000000002600}
  ProcessId: 6452
  Image: C:\Windows\System32\schtasks.exe
  FileVersion: 10.0.19041.5965 (WinBuild.160101.0800)
  Description: Task Scheduler Configuration Tool
  Product: Microsoft® Windows® Operating System
  Company: Microsoft Corporation
  OriginalFileName: schtasks.exe
  CommandLine: schtasks  /create /tn "MaliciousTask" /tr "C:\malware.exe" /sc once /st 12:00
  CurrentDirectory: C:\Users\po230\
  User: DESKTOP-NDBEF0H\po230
  LogonGuid: {e237abb6-21c7-697e-a45d-050000000000}
  LogonId: 0x55DA4
  TerminalSessionId: 1
  IntegrityLevel: Medium
  Hashes: MD5=2C400322E4F96C1FEDB0F890C7668C92,SHA256=2327E073DCF25AE03DC851EA0F3414980D3168FA959F42C5F77BE1381AE6C41D,IMPHASH=7C296BC1AA0738F0783F000C5982A642
  ParentProcessGuid: {e237abb6-21e8-697e-0801-000000002600}
  ParentProcessId: 8744
  ParentImage: C:\Windows\System32\cmd.exe
  ParentCommandLine: "C:\Windows\system32\cmd.exe"
  ParentUser: DESKTOP-NDBEF0H\po230
  ```
  ```powershell
  01/31/2026 10:39:37.220 PM
  LogName=Microsoft-Windows-Sysmon/Operational
  EventCode=1
  EventType=4
  ComputerName=DESKTOP-NDBEF0H
  User=NOT_TRANSLATED
  Sid=S-1-5-18
  SidType=0
  SourceName=Microsoft-Windows-Sysmon
  Type=Information
  RecordNumber=15464
  Keywords=None
  TaskCategory=Process Create (rule: ProcessCreate)
  OpCode=Info
  Message=Process Create:
  RuleName: -
  UtcTime: 2026-01-31 15:39:37.214
  ProcessGuid: {e237abb6-2239-697e-2401-000000002600}
  ProcessId: 3548
  Image: C:\Windows\System32\schtasks.exe
  FileVersion: 10.0.19041.5965 (WinBuild.160101.0800)
  Description: Task Scheduler Configuration Tool
  Product: Microsoft® Windows® Operating System
  Company: Microsoft Corporation
  OriginalFileName: schtasks.exe
  CommandLine: schtasks  /change /tn "MaliciousTask" /tr "C:\evil_script.ps1"
  CurrentDirectory: C:\Users\po230\
  User: DESKTOP-NDBEF0H\po230
  LogonGuid: {e237abb6-21c7-697e-a45d-050000000000}
  LogonId: 0x55DA4
  TerminalSessionId: 1
  IntegrityLevel: Medium
  Hashes: MD5=2C400322E4F96C1FEDB0F890C7668C92,SHA256=2327E073DCF25AE03DC851EA0F3414980D3168FA959F42C5F77BE1381AE6C41D,IMPHASH=7C296BC1AA0738F0783F000C5982A642
  ParentProcessGuid: {e237abb6-21e8-697e-0801-000000002600}
  ParentProcessId: 8744
  ParentImage: C:\Windows\System32\cmd.exe
  ParentCommandLine: "C:\Windows\system32\cmd.exe"
  ParentUser: DESKTOP-NDBEF0H\po230
  ```
  ```powershell
  01/31/2026 10:40:40.356 PM
  LogName=Microsoft-Windows-Sysmon/Operational
  EventCode=1
  EventType=4
  ComputerName=DESKTOP-NDBEF0H
  User=NOT_TRANSLATED
  Sid=S-1-5-18
  SidType=0
  SourceName=Microsoft-Windows-Sysmon
  Type=Information
  RecordNumber=15477
  Keywords=None
  TaskCategory=Process Create (rule: ProcessCreate)
  OpCode=Info
  Message=Process Create:
  RuleName: -
  UtcTime: 2026-01-31 15:40:40.351
  ProcessGuid: {e237abb6-2278-697e-3401-000000002600}
  ProcessId: 2724
  Image: C:\Windows\System32\schtasks.exe
  FileVersion: 10.0.19041.5965 (WinBuild.160101.0800)
  Description: Task Scheduler Configuration Tool
  Product: Microsoft® Windows® Operating System
  Company: Microsoft Corporation
  OriginalFileName: schtasks.exe
  CommandLine: schtasks  /run /tn "MaliciousTask"
  CurrentDirectory: C:\Users\po230\
  User: DESKTOP-NDBEF0H\po230
  LogonGuid: {e237abb6-21c7-697e-a45d-050000000000}
  LogonId: 0x55DA4
  TerminalSessionId: 1
  IntegrityLevel: Medium
  Hashes: MD5=2C400322E4F96C1FEDB0F890C7668C92,SHA256=2327E073DCF25AE03DC851EA0F3414980D3168FA959F42C5F77BE1381AE6C41D,IMPHASH=7C296BC1AA0738F0783F000C5982A642
  ParentProcessGuid: {e237abb6-21e8-697e-0801-000000002600}
  ParentProcessId: 8744
  ParentImage: C:\Windows\System32\cmd.exe
  ParentCommandLine: "C:\Windows\system32\cmd.exe"
  ParentUser: DESKTOP-NDBEF0H\po230
  ```
  ```powershell
  01/31/2026 10:40:58.009 PM
  LogName=Microsoft-Windows-Sysmon/Operational
  EventCode=1
  EventType=4
  ComputerName=DESKTOP-NDBEF0H
  User=NOT_TRANSLATED
  Sid=S-1-5-18
  SidType=0
  SourceName=Microsoft-Windows-Sysmon
  Type=Information
  RecordNumber=15480
  Keywords=None
  TaskCategory=Process Create (rule: ProcessCreate)
  OpCode=Info
  Message=Process Create:
  RuleName: -
  UtcTime: 2026-01-31 15:40:58.005
  ProcessGuid: {e237abb6-228a-697e-3801-000000002600}
  ProcessId: 6072
  Image: C:\Windows\System32\schtasks.exe
  FileVersion: 10.0.19041.5965 (WinBuild.160101.0800)
  Description: Task Scheduler Configuration Tool
  Product: Microsoft® Windows® Operating System
  Company: Microsoft Corporation
  OriginalFileName: schtasks.exe
  CommandLine: schtasks  /delete /tn "MaliciousTask" /f
  CurrentDirectory: C:\Users\po230\
  User: DESKTOP-NDBEF0H\po230
  LogonGuid: {e237abb6-21c7-697e-a45d-050000000000}
  LogonId: 0x55DA4
  TerminalSessionId: 1
  IntegrityLevel: Medium
  Hashes: MD5=2C400322E4F96C1FEDB0F890C7668C92,SHA256=2327E073DCF25AE03DC851EA0F3414980D3168FA959F42C5F77BE1381AE6C41D,IMPHASH=7C296BC1AA0738F0783F000C5982A642
  ParentProcessGuid: {e237abb6-21e8-697e-0801-000000002600}
  ParentProcessId: 8744
  ParentImage: C:\Windows\System32\cmd.exe
  ParentCommandLine: "C:\Windows\system32\cmd.exe"
  ParentUser: DESKTOP-NDBEF0H\po230
  ```
- Time `01/31/2026 10:40:58.009 PM`
- EventCode=`1` (create process)
- ComputerName=`DESKTOP-NDBEF0H`
- Image: `C:\Windows\System32\schtasks.exe`
- User: `DESKTOP-NDBEF0H\po230`
- ParentImage: `C:\Windows\System32\cmd.exe`
- Có 4 lệnh được chạy để hành động lên Task Schedule
  - `schtasks  /create /tn "MaliciousTask" /tr "C:\malware.exe" /sc once /st 12:00`
  - `schtasks  /change /tn "MaliciousTask" /tr "C:\evil_script.ps1"`
  - `schtasks  /run /tn "MaliciousTask"`
  - `schtasks  /delete /tn "MaliciousTask" /f`
- Mapping ATT&CK
  - Tactic: Persistence
  - Technique: Scheduled Task/Job: Scheduled Task
  - ID: T1053.005
