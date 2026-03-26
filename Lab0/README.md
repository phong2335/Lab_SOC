# Lab 0: Môi trường và công cụ

Cài đặt và cấu hình hệ thống SIEM bằng Splunk cùng với các công cụ như Sysmon.

## 1. Kiến thức nền tảng

- Sysmon (System Monitor) là công cụ của Microsoft Sysinternals (cài như một service) giúp ghi log chi tiết hành vi trên Windows vào Event Log.
  Sysmon thường ghi các sự kiện như:
  - Tạo process (Event ID 1)
  - Kết nối mạng (Event ID 3)
  - Tạo file, registry, v.v. 
- Splunk Universal Forwarder (UF) là gì?
  Splunk Universal Forwarder là một “agent nhẹ” cài trên máy cần giám sát để:
  - Thu thập log trên các máy
  - Gửi log về Splunk Server qua mạng
- Splunk Enterprise là nền tảng trung tâm để:
  - Nhận log
  - Lưu trữ / index
  - Tìm kiếm & phân tích bằng SPL (Search Processing Language)
  - Dashboard, Alert, Report

## 2. Cài đặt 4 máy ảo

- Ubuntu Server 24.04.3
- Kali linux 2025.4
- Windows 10
- Ubuntu desktop

## 3. Cài đặt và cấu hình Splunk Enterprise trên Ubuntu Server

- Thiết lập ip tĩnh trên Ubuntu Server
  1. Xem file netplan:
     - `ls /etc/netplan`
       ![image.png](images/image.png)
  2. Mở file đó ra và chỉnh sửa
  - `nano /etc/netplan/50-cloud-init.yaml`
  - sửa file đó thành
    ```powershell
    network:
      version: 2
      ethernets:
        ens33:
          dhcp4: no
          addresses:
            - 192.168.60.20/24
          routes:
            - to: default
              via: 192.168.60.2
          nameservers:
            addresses:
              - 8.8.8.8
              - 1.1.1.1
    ```
  1. Áp dụng
  - `netplan apply`

### Bước 1:

- tải file `.deb` Splunk Enterprise

  wget -O /tmp/splunk-10.0.2-e2d18b4767e9-linux-amd64.deb "[https://download.splunk.com/products/splunk/releases/10.0.2/linux/splunk-10.0.2-e2d18b4767e9-linux-amd64.deb](https://download.splunk.com/products/splunk/releases/10.0.2/linux/splunk-10.0.2-e2d18b4767e9-linux-amd64.deb)"

### Bước 2: Cài Splunk

```bash
cd /tmp
sudo dpkg -i splunk-*.deb
sudo apt -f install -y
```

### Bước 3: Start lần đầu (accept license + tạo admin)

```bash
sudo /opt/splunk/bin/splunk start --accept-license
```

- Tạo username/password admin

### Bước 4: Cho Splunk tự chạy theo boot

```bash
sudo /opt/splunk/bin/splunk enable boot-start
```

### Bước 5: Mở port cần thiết

```bash
sudo ufw allow 8000/tcp# Splunk Web
sudo ufw allow 9997/tcp# Receiving from Forwarder
sudo ufw enable
sudo ufw status
```

### Bước 6: Vào Splunk Web

Trên máy host mở:

- `http://192.168.60.20:8000` (hoặc https tùy cấu hình)

### Bước 7: Bật “Receiving” (port 9997)

Splunk Web → **Settings → Forwarding and receiving → Configure receiving → New Receiving Port** → nhập **9997**.

### Bước 8: Tạo Index

Splunk Web → **Settings → Indexes → New Index**

- `windows_system_logs`
- `security_events`
- `sysmon`

## 4. Cài đặt Sysmon trên máy windows 10

- Bước 1: [https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- Bước 2: Tải thêm file cấu hình Sysmon (Sysmon config). Sysmon cần “config” để log đầy đủ và sạch (thường dùng **SwiftOnSecurity sysmon-config**). Tải file `sysmonconfig.xml` từ repo SwiftOnSecurity (GitHub)
  [https://github.com/SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
- Bước 3: Cài đặt Sysmon
  - Mở cmd bằng quyền admin rồi vào thư mục chứa sysmon rồi chạy lệnh sau
    ```powershell
    sysmon64.exe -i sysmonconfig-export.xml
    ```
- Nếu thành công, Sysmon sẽ bắt đầu ghi lại các sự kiện vào Windows Event Log, mục **"Microsoft-Windows-Sysmon/Operational"**.
- **Kiểm tra:** Mở Event Viewer > Applications and Services Logs > Microsoft > Windows > Sysmon > Operational.

![image.png](images/image%201.png)

## 5. Cài & cấu hình Splunk Universal Forwarder trên Windows 10

### Bước 1: Cài UF

Tải **Splunk Universal Forwarder for Windows** trên Slplunk download và cài như bình thường.

### Bước 2: Cấu hình gửi về Splunk Server (192.168.60.20:9997)

Mở CMD/PowerShell **Run as Administrator**:

```bash
cd "C:\Program Files\SplunkUniversalForwarder\bin"
splunk enable boot-start
splunk start
splunk add forward-server 192.168.60.20:9997 -auth <admin_user>:<admin_pass>
```

> Lưu ý: <admin_user>:<admin_pass> ở đây là user của UF local, không nhất thiết phải giống Splunk Server.

### Bước 3: Cấu hình thu thập Windows Event Logs

- Tạo/sửa file:

`C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`

- Nội dung:

  ```
  [WinEventLog://Security]
  disabled =0
  index = security_events
  sourcetype = XmlWinEventLog:Security

  [WinEventLog://System]
  disabled =0
  index = windows_system_logs
  sourcetype = XmlWinEventLog:System

  [WinEventLog://Application]
  disabled =0
  index = windows_system_logs
  sourcetype = XmlWinEventLog:Application

  [WinEventLog://Microsoft-Windows-Sysmon/Operational]
  disabled =0
  index = sysmon
  sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  ```

- Restart UF
  ```bash
  cd "C:\Program Files\SplunkUniversalForwarder\bin"
  splunk restart
  ```
- Lưu ý khi tải UF: để chế độ **Local System Account** thì mới đủ quyền đọc log Event Viewer ở `Microsoft-Windows-Sysmon/Operational`
- Nếu lỡ để chế độ khác thì

  - Kiểm tra lại account đang chạy Splunk Forwarder:

  ```powershell
  Get-WmiObject win32_service | Where-Object { $_.Name -eq "SplunkForwarder" } | Select-Object StartName

  ```

  - Nếu không thấy `LocalSystem`, bạn cần sửa:
    - Nhấn `Win + R`, nhập: `services.msc`
    - Tìm dịch vụ **"SplunkForwarder"**
    - Chuột phải → `Properties`
    - Chuyển sang tab **Log On**
    - Chọn: Local System account
    - Khởi động lại Splunk Forwarder
  - `$SPLUNK_HOME` của UF và các file quan trọng
    - Trên Windows, $SPLUNK_HOME của UF thường là:
      `C:\Program Files\SplunkUniversalForwarder`
    - `%SPLUNK_HOME%\etc\system\local\outputs.conf` , Dùng để:
      - cấu hình forward tới Splunk Indexer/Server (9997)
      - SSL, load balance, multiple indexers…
    - `%SPLUNK_HOME%\etc\system\local\inputs.conf` , Dùng để:
      - monitor file/folder
      - thu Windows Event Logs (WinEventLog)
      - đặt `index`, `sourcetype`, `host`, whitelist…

## 6. Cài đặt và cấu hình Splunk Universal Forwarder trên Ubuntu (desktop)

- Tải file `.deb` từ trang Splunk
- Cài gói `.deb`
  ```powershell
  sudo dpkg -i splunkforwarder*.deb
  ```
- Khởi động Splunk Forwarder lần đầu (accept license)
  ```powershell
  sudo /opt/splunkforwarder/bin/splunk start --accept-license
  ```
- Kiểm tra Forwarder đang chạy
  ```bash
  sudo /opt/splunkforwarder/bin/splunk status
  ```
- Cấu hình gửi về Splunk Server
  ```bash
  sudo /opt/splunkforwarder/bin/splunk add forward-server 192.168.60.20:9997
  ```
- Add các log cần theo dõi
  ```powershell
  sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/auth.log -sourcetype linux_secure -index linux_logs
  sudo /opt/splunkforwarder/bin/splunk restart
  ```
- `$SPLUNK_HOME` của UF và các file quan trọng
  - **`$SPLUNK_HOME = /opt/splunkforwarder`**
  - file config nằm ở: `/opt/splunkforwarder/etc/...`
    - `outputs.conf` : dùng để khai báo gửi đi đâu (Forwarding), Splunk Server nhận log
    - `inputs.conf` : để đọc cái gì, monitor file/thư mục log, đặt sourcetype, index, host,…
  - log của forwarder nằm ở: `/opt/splunkforwarder/var/log/splunk/...`
  - lệnh splunk nằm ở: `/opt/splunkforwarder/bin/splunk`

## 7. Verify dữ liệu vào Splunk

Trên Splunk Web chạy:

- Kiểm tra có data không
  ```
  index=* | stats count by index
  ```
- Check security events
  ```
  index=security_events | stats count by sourcetype
  ```
- Check sysmon
