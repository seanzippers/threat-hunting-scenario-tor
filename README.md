<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/seanzippers/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md) 

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

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “employee” downloaded a Tor installer and did something that resulted in tor-related files being copied to the Desktop and the creation of a file called “tor-shopping-list”. These events began at:2025-03-21T18:54:10.2470437Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "sz-threat-lab"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-03-21T18:54:10.2470437Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountDomain
![image](https://github.com/user-attachments/assets/dea45a4c-3215-4538-976e-e28ba1575fed)

```

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcess Events table for any ProcessCommandLine that contains the string “tor-browser-windows-x86_64-portable-14.0.7.exe”. On the device named 'sz-threat-lab', the user 'labuser' initiated the execution of the file 'tor-browser-windows-x86_64-portable-14.0.7.exe' located in the 'C:\Users\labuser\Downloads' directory. This was done using silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "sz-threat-lab"
| where ProcessCommandLine  contains "tor-browser-windows-x86_64-portable-14.0.7.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine 

```

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that the user actually opened the Tor browser. There was evidence that they did open it at 2025-03-21T18:57:47.8172069Z. There were several other instances of Firefox and Tor.exe spawned afterwards.


**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "sz-threat-lab"
| where FileName has_any ("tor.exe","firefox.exe","tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256,
ProcessCommandLine 
| order by Timestamp desc 

```

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections
Search the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports.

At 11:58:09 AM on March 21, 2025, on the device 'sz-threat-lab', the user 'labuser' successfully established a connection using the process 'tor.exe' to the remote IP address 45.88.104.74 on port 9001. Port 9001 is commonly associated with Tor network traffic.There was also a couple of other connections to sites over port 443.
![image](https://github.com/user-attachments/assets/fea50ed4-a22b-4cc2-83ff-a17df014ecd9)


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "sz-threat-lab"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "443")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc 

```

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.7.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.7.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.7.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.7.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.7.exe`

### 3. Process Execution - TOR Browser Launch


- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

-
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "sz-threat-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
