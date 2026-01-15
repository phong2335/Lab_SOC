# Lab 2: Phát hiện và điều tra tấn công Brute-Force dịch vụ RDP trên Windows

# I. Mục tiêu

- Mục tiêu của bài lab là xây dựng một môi trường SOC cơ bản để mô phỏng, thu thập và phát hiện tấn công Brute-Force RDP trên hệ điều hành Windows, thông qua việc sử dụng Sysmon để ghi nhận hành vi trên endpoint và Splunk để tập trung log, phân tích và cảnh báo sự kiện an ninh.

# II. Sơ đồ mạng, môi trường và công cụ

![image.png](images/image.png)

- RDP (Remote Desktop Protocol) là giao thức của Microsoft dùng để điều khiển máy Windows từ xa (nhìn màn hình, dùng chuột/phím như ngồi trước máy).

# III. Tiến hành mô phỏng cuộc tấn công và phân tích

## 1. Trên máy kali, sử dụng hydra để tấn công brute force vào máy windows bằng dịch vụ rdp

- Cú pháp cơ bản của hydra
  `hydra [tùy_chọn] <dịch_vụ>://<target>`
  - `l user` : 1 username
  - `L users.txt` : danh sách username
  - `p pass` : 1 mật khẩu
  - `P passwords.txt` : danh sách mật khẩu
  - `s port` : chỉ định cổng
  - `t n` : số thread (mặc định 16)
  - `V` : hiển thị chi tiết từng lần thử
  - `f` : dừng khi tìm thấy mật khẩu đúng
- Kiểm tra cổng RDP trên máy victim có mở không
  `nmap -p 3389 192.168.60.30`
- Tắt NLA( Network Level Authentication ) trên windows
- Chạy lệnh sau để tấn công
  ```powershell
  hydra -L users.txt -P passwords.txt -V -f rdp://192.168.60.30
  ```
- Tấn công brute force và tìm ra username và password

![image.png](images/image%201.png)

- Đăng nhập RDP vào user đó, sử dụng xfreerdp3
  `xfreerdp3 /v:192.168.60.30 /u:po230 /p:'phong123' /cert:ignore`
- RDP thành công vào máy windows

![image.png](images/image%202.png)

## 2. Phân tích SOC

### 1. DETECTION (Phát hiện)

- Phát hiện đăng nhập thất bại bất thường
  - `index=security_events EventCode=4625 Logon_Type IN(10, 3)`
    Logon_Type=10 là RDP, Logon_Type=3 là Network. Thông thường dùng hydra để brute force chỉ sinh ra Logon_Type=3 , chỉ khi tạo phiên đăng nhập vào hẳn RDP thì mới chắc chắn có Logon_Type=10
    ![image.png](images/image%203.png)
  - Ta thấy 13 log đăng nhập thất bại đều là Logon_Type=3
  - `log`
    ![image.png](images/image%204.png)
    ![image.png](images/image%205.png)
  - Time: `2025-12-21 09:30:07`
  - Host: `DESKTOP-NDBEF0H`
  - EventCode: `4625` (Audit Failure)
  - Logon_Type: `3` (Network)
  - User: `po230`
  - Source IP: `192.168.60.10` (Workstation: `kali`)
  - Failure Reason: `Unknown user name or bad password`
  - Auth Package: `NTLM`
- Đếm số lần thất bại
  ```powershell
  index=security_events EventCode=4625
  | where Logon_Type IN (3,10)
  | stats count by Source_Network_Address Account_Name Logon_Type
  | sort -count
  ```
  ![image.png](images/image%206.png)
  ⇒ Dấu hiệu brute-force
  - Một IP (`192.168.60.10`)
  - Thử nhiều lần với cùng / nhiều user

### 2. INVESTIGATION (Điều tra)

- Xác nhận có đăng nhập bất thường thành công
  `index=security_events EventCode=4624 Logon_Type IN(10,3 )`
  ![image.png](images/image%207.png)
- `log (Logon_Type=3)` **Xác thực** (network logon) → tạo token/phiên phụ trợ → **4624 Type 3**
  ```powershell
  12/21/2025 09:34:27.069 AM
  LogName=Security
  EventCode=4624
  EventType=0
  ComputerName=DESKTOP-NDBEF0H
  SourceName=Microsoft Windows security auditing.
  Type=Information
  RecordNumber=38367
  Keywords=Audit Success
  TaskCategory=Logon
  OpCode=Info
  Message=An account was successfully logged on.

  Subject:
  	Security ID:		S-1-0-0
  	Account Name:		-
  	Account Domain:		-
  	Logon ID:		0x0

  Logon Information:
  	Logon Type:		3
  	Restricted Admin Mode:	-
  	Virtual Account:		No
  	Elevated Token:		No

  Impersonation Level:		Impersonation

  New Logon:
  	Security ID:		S-1-5-21-89911650-480286385-2846434076-1001
  	Account Name:		po230
  	Account Domain:		DESKTOP-NDBEF0H
  	Logon ID:		0x219511
  	Linked Logon ID:		0x0
  	Network Account Name:	-
  	Network Account Domain:	-
  	Logon GUID:		{00000000-0000-0000-0000-000000000000}

  Process Information:
  	Process ID:		0x0
  	Process Name:		-

  Network Information:
  	Workstation Name:	kali
  	Source Network Address:	192.168.60.10
  	Source Port:		0

  Detailed Authentication Information:
  	Logon Process:		NtLmSsp
  	Authentication Package:	NTLM
  	Transited Services:	-
  	Package Name (NTLM only):	NTLM V2
  	Key Length:		128

  This event is generated when a logon session is created. It is generated on the computer that was accessed.

  The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

  The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

  The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

  The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

  The impersonation level field indicates the extent to which a process in the logon session can impersonate.

  The authentication information fields provide detailed information about this specific logon request.
  	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
  	- Transited services indicate which intermediate services have participated in this logon request.
  	- Package name indicates which sub-protocol was used among the NTLM protocols.
  	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.
  Collapse
  host = DESKTOP-NDBEF0Hsource = WinEventLog:Securitysourcetype = XmlWinEventLog:Security
  host = DESKTOP-NDBEF0Hsource = WinEventLog:Securitysourcetype = XmlWinEventLog:Security

  ```
- `log (Logon_Type=10)` **Tạo phiên Remote Desktop** (remote interactive) → **4624 Type 10**
  ```powershell
  12/21/2025 09:34:29.504 AM
  LogName=Security
  EventCode=4624
  EventType=0
  ComputerName=DESKTOP-NDBEF0H
  SourceName=Microsoft Windows security auditing.
  Type=Information
  RecordNumber=38381
  Keywords=Audit Success
  TaskCategory=Logon
  OpCode=Info
  Message=An account was successfully logged on.

  Subject:
  	Security ID:		S-1-5-18
  	Account Name:		DESKTOP-NDBEF0H$
  	Account Domain:		WORKGROUP
  	Logon ID:		0x3E7

  Logon Information:
  	Logon Type:		10
  	Restricted Admin Mode:	No
  	Virtual Account:		No
  	Elevated Token:		No

  Impersonation Level:		Impersonation

  New Logon:
  	Security ID:		S-1-5-21-89911650-480286385-2846434076-1001
  	Account Name:		po23032005@gmail.com
  	Account Domain:		MicrosoftAccount
  	Logon ID:		0x23AFD6
  	Linked Logon ID:		0x23AF7B
  	Network Account Name:	-
  	Network Account Domain:	-
  	Logon GUID:		{00000000-0000-0000-0000-000000000000}

  Process Information:
  	Process ID:		0x820
  	Process Name:		C:\Windows\System32\svchost.exe

  Network Information:
  	Workstation Name:	DESKTOP-NDBEF0H
  	Source Network Address:	192.168.60.10
  	Source Port:		0

  Detailed Authentication Information:
  	Logon Process:		User32
  	Authentication Package:	Negotiate
  	Transited Services:	-
  	Package Name (NTLM only):	-
  	Key Length:		0

  This event is generated when a logon session is created. It is generated on the computer that was accessed.

  The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

  The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

  The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

  The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

  The impersonation level field indicates the extent to which a process in the logon session can impersonate.

  The authentication information fields provide detailed information about this specific logon request.
  	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
  	- Transited services indicate which intermediate services have participated in this logon request.
  	- Package name indicates which sub-protocol was used among the NTLM protocols.
  	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.
  Collapse
  host = DESKTOP-NDBEF0Hsource = WinEventLog:Securitysourcetype = XmlWinEventLog:Security
  ```
- Kết luận:
  - Trùng ip brute-force
  - Có 4624 sau nhiều 4625

⇒ Xác nhận **Compromise**

### 3. IMPACT ASSESSMENT (Đánh giá ảnh hưởng)

| Tiêu chí      | Giá trị            |
| ------------- | ------------------ |
| Kiểu tấn công | RDP brute-force    |
| Tài khoản     | po230              |
| Kết quả       | Login thành công   |
| Quyền         | Local user / admin |
| Phạm vi       | 1 host             |
| Severity      | **HIGH**           |

MITRE ATT&CK

- [\*\*Credential Access](https://attack.mitre.org/tactics/TA0006)\*\* – Brute Force - T1110
- **[Lateral Movement](https://attack.mitre.org/tactics/TA0008)** – Remote Services (RDP) - **T1021.001**
- [\*\*Initial Access](https://attack.mitre.org/tactics/TA0001)** - External Remote Services - \*\***T1133
- [\*\*Initial Access](https://attack.mitre.org/tactics/TA0001)** – Valid Accounts (dùng tài khoản hợp lệ sau khi brute force) - **T1078\*\*

### 4. RESPONSE & RECOMMENDATION

- Kiểm tra hành vi sau khi attacker đăng nhập
  ```powershell
  index=sysmon EventCode=1
  | search User="*po230*"
  | table _time Image CommandLine ParentImage
  ```
- Các cách xử lý
  - Disable / reset password `po230`
  - Block IP `192.168.60.10`
  - Enable **Account Lockout Policy**
  - Restrict RDP by firewall
  - Enable MFA cho RDP
