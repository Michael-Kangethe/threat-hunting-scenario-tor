<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Michael-Kangethe/threat-hunting-scenario-tor/tree/main) 

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “knu” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping-list” on the desktop at 2025-04-23T12:52:46.9014467Z. These events began at: 2025-04-23T12:37:01.7842979Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "knu"
| where FileName contains "tor"
| order by Timestamp desc
| where Timestamp >= datetime(2025-04-23T12:37:01.7842979Z)
| where InitiatingProcessAccountName == "knu"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/dc56d2e0-c86e-4529-a3b3-a94d120fa9a2">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProccessCommandLine that contained string “tor-browser-windows-x86_64-portable-14.5.exe” based on the logs returned at 2025-04-23T12:39:58.1533961Z, a user named Knu downloaded and silently installed the Tor Browser on their computer. The file, named "tor-browser-windows-x86_64-portable-14.5.exe," was launched from the Downloads folder using a command that didn’t show any installation windows or prompts.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "knu"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/fcda7db3-c9fb-4c6e-a1b1-5efdbb3fba86">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “knu” actually opened the Tor browsers. There was evidence that they did open it at 2025-04-23T12:40:31.7667211Z. There were several other instances of FireFox as well as Tor.exe spawned afterward.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "knu"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/76d87216-7c68-407e-9c3b-053680884010">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the Tor browser was used to establish a connection using any of the known Tor port numbers. At 2025-04-23T12:41:42.3579958Z, a user named knu successfully connected to the IP address 73.61.87.62 on port 9001 using a program called tor.exe. There were a few other connections to sites over port 443 as well. 

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "knu"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl , InitiatingProcessFileName  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/12cf1611-261a-4526-a19c-a9a6d27ddb78">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-04-23T12:52:46.9014467Z`
- **Event:** The user "knu" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\knu\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-04-23T12:39:58.1533961Z`
- **Event:** The user "knu" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\knu\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-04-23T12:40:31.7667211Z`
- **Event:** User "knu" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\knu\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-04-23T12:41:42.3579958Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\knu\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-04-23T12:41:42.3579958Z` - Connected to `194.164.169.85` on port `443`.
  - `2025-04-23T12:41:42.3579958Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-04-23T12:52:46.9014467Z`
- **Event:** The user "knu" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\knu\Desktop\tor-shopping-list.txt`

---

## Summary

User "knu" downloaded and silently installed the Tor Browser on their computer at 12:39 UTC on April 23, 2025, without any user prompts. Within minutes, they launched the browser and successfully connected to the Tor network via port 9001. Following this, a file named “tor-shopping-list” was created on the desktop, which may indicate planned usage of the Tor network for anonymous or potentially illicit activity. All actions appear deliberate and were carried out in a short timeframe, demonstrating intent and technical knowledge.

---

## Response Taken

TOR usage was confirmed on the endpoint knu. The device was isolated and the user's direct manager was notified.

---
