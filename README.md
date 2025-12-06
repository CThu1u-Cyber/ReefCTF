# ReefCTF
```go
    ____            ____   __________________
   / __ \___  ___  / __/  / ____/_  __/ ____/
  / /_/ / _ \/ _ \/ /_   / /     / / / /_
 / _, _/  __/  __/ __/  / /___  / / / __/
/_/ |_|\___/\___/_/     \____/ /_/ /_/

[+] Active Directory Pentest Automation Framework for Lazy Hackers ;) Happy Hunting!
[+] Developer : CThu1hu
```
# Description

**Reef CTF** is a lightweight CLI tool built for automating the repetitive and time-consuming parts of **Active Directory enumeration & exploitation** — designed for CTFs (Hack The Box, TryHackMe, etc.), home labs, and educational use.

# Dependencies

- `Impacket`, `nxc`, `bloodyAD`, `rusthound-ce` are required

# Features

- CLI-driven interface with menu-based module execution
- Stores credentials, target IPs, and domain info for later use
- Supports **anonymous enumeration** (null sessions, guest login)
- Generates `targets.txt`, `creds.txt`, and `users.txt` on the fly
- Integrates external tools like `nxc`, `smbclient`, etc.
- Fast, portable, and built in Golang

** The project is still in the works and no where near finished. More features are yet to come **


# Installation

Clone the repository:

```go
git clone https://github.com/CThu1u-Cyber/ReefCTF.git
```

If the binary isn’t present, run:

```go
go build -o reef main.go
```

If you want to run the tool anywhere, run:

```go
cp /current/path/ReefCTF ~/.local/bin/
```

## Installing RustHound:

```go
// You must have the Rust toolchain installed on your system to use either installation method. We recommend using rustup to manage your installation
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

//simplest way to install and update the latest stable version of RustHound-CE.
cargo install rusthound-ce

//test it
rusthound-ce --version
```

# Usage

Launch:

```go
./reef

    ____            ____   __________________
   / __ \___  ___  / __/  / ____/_  __/ ____/
  / /_/ / _ \/ _ \/ /_   / /     / / / /_
 / _, _/  __/  __/ __/  / /___  / / / __/
/_/ |_|\___/\___/_/     \____/ /_/ /_/

[+] Active Directory Pentest Automation Framework for Lazy Hackers ;) Happy Hunting!
[+] Developer : CThu1hu

DISCLAIMER:
[+] Reef-CTF is designed exclusively for use in Capture The Flag (CTF) environments, home labs, and
    education scenarios. Do NOT use this tool against any system you do not own or have explicit,
    written permission to test.
[+] The creator(s) of this tool are not responsible for any misuse or damage resulting from its use.

[*] Enter path to Nmap file: 
```
NMAP FILE : `company.nmap`
```go
[*] Parsing target domain data from Nmap output...

Parsed Domain Controllers:
-------------------------------------------------------------
IP Address      | FQDN                           | Domain
-------------------------------------------------------------
10.0.0.1        | DC01.company.local             | COMPANY.local
-------------------------------------------------------------

[+] targets.txt created

[!] COPY/PASTE THIS to /etc/hosts:
10.0.0.1 DC01.company.local

[?] Add this DC to host entries? (y/n): y
[+] Added host entry: 10.0.0.1 -> DC01.company.local
[*] targets.txt updated with all current IPs.

[*] You can add additional workstations, webhosts, etc. via the 'Hosts' menu.

[+] Starting Reef... Type 'help' or 'exit'.

    [1]  Hosts                    (Host Entry, List)
    [2]  Users                    (Add / List)
    [3]  No Creds                 (Null/Guest, anonymous shares)
    [4]  Valid Creds
    [5]  BloodHound Collector     (Rusthound-ce is required)
    [6]  Password Crack           (Crack hashes in a file, or standalone.)
    [7]  Privilege Abuse          (Bloodhound Outbound Controls)
    [8]  work in progress
    [9]  work in progress
    [x]  Exit Reef                (Leave the trench)

~ Reef ~ >
```

## Initial Setup

The framework will require you to have an NMAP file already generated. 

As of right now, the tool will only parse domain data from a `DOMAIN CONTROLLER` 
I recommend running the following nmap scan on the domain controller and saving the output to a `.nmap` file.

```go
nmap -sC -sV -vv -oA company 10.0.0.1
```

Company → “company name” or whatever name you prefer.


## CLI Navigation

```go
    [1]  Hosts                    (Host Entry, List)
    [2]  Users                    (Add / List)
    [3]  No Creds                 (Null/Guest, anonymous shares)
    [4]  Valid Creds
    [5]  BloodHound Collector     (Rusthound-ce is required)
    [6]  Password Crack           (Crack hashes in a file, or standalone.)
    [7]  Privilege Abuse          (Bloodhound Outbound Controls)
    [8]  work in progress
    [9]  work in progress
    [x]  Exit Reef                (Leave the trench)
```

## Adding Additional Hosts

If you want to add more hosts other than the DC, you can choose the first option from the menu after you’ve submitted an accepted nmap file.

Sample output (adding a host):

```go
~ Reef ~ > 1

[Hosts Module]
Options:
  add  - Add a new host entry
  list - List stored hosts
  back - Return to main menu

[hosts] > add
IP Address: 10.0.0.2
Hostname: ws01.company.local
[+] Added host entry: 10.0.0.2 -> ws01.company.local
[*] targets.txt updated with all current IPs.

[Hosts Module]
Options:
  add  - Add a new host entry
  list - List stored hosts
  back - Return to main menu

[hosts] > list

Host Entries:
-------------------------------------
[1] 10.0.0.1         dc01.company.local
[2] 10.0.0.2         ws01.company.local

[Hosts Module]
Options:
  add  - Add a new host entry
  list - List stored hosts
  back - Return to main menu

[hosts] >
```

## Generated Files

| File | Purpose |
| --- | --- |
| `targets.txt` | Used by tools like `nxc` |
| `creds.txt` | Full credential dump |
| `users.txt` | Only usernames for sprays |

# Legal Disclaimer & Ethical Use

Reef-CTF is designed exclusively for use in Capture The Flag (CTF) environments, home labs, and
education scenarios. Do NOT use this tool against any system you do not own or have explicit,
written permission to test. The creator(s) of this tool are not responsible for any misuse or damage resulting from its use.
