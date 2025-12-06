package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
)

var banner = `
    ____            ____   __________________
   / __ \___  ___  / __/  / ____/_  __/ ____/
  / /_/ / _ \/ _ \/ /_   / /     / / / /_    
 / _, _/  __/  __/ __/  / /___  / / / __/    
/_/ |_|\___/\___/_/     \____/ /_/ /_/       
`

var promptString = color.CyanString("~ Reef ~ > ")

type Credential struct {
	Username string
	Password string
}

type HostEntry struct {
	IP       string
	Hostname string
}

var credentials []Credential //store creds in a slice
var hostEntries []HostEntry  //store target information in a slice
var domainName string
var usernames []string

func parseNmapFileAndSetup() {
	reader := bufio.NewScanner(os.Stdin)
	fmt.Print(color.CyanString("[*] Enter path to Nmap file: "))
	reader.Scan()
	filePath := strings.TrimSpace(reader.Text())

	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Println(color.RedString("[-] Failed to read file: %s", err))
		os.Exit(1)
	}
	fmt.Println(color.GreenString("\n[*] Parsing target domain data from Nmap output...\n"))
	content := string(data)

	type DCEntry struct {
		IP     string
		Domain string
		FQDN   string
	}

	var dcEntries []DCEntry
	seen := make(map[string]bool)

	// Split by "Nmap scan report for"
	hostSections := strings.Split(content, "Nmap scan report for")
	for _, block := range hostSections[1:] { // skip the first chunk (header)
		lines := strings.Split(block, "\n")
		if len(lines) < 1 {
			continue
		}

		// Extract IP from the first line
		ipLine := strings.TrimSpace(lines[0])
		ipRegex := regexp.MustCompile(`(\d{1,3}(?:\.\d{1,3}){3})`)
		ipMatch := ipRegex.FindStringSubmatch(ipLine)
		if len(ipMatch) < 2 {
			continue
		}
		ip := ipMatch[1]

		// Check if it's likely a DC based on port & LDAP hints
		isDC := false
		for _, line := range lines {
			if strings.Contains(line, "Active Directory LDAP") ||
				strings.Contains(line, "ldap") ||
				strings.Contains(line, "kerberos") {
				isDC = true
				break
			}
		}
		if !isDC {
			continue
		}

		blockText := strings.Join(lines, "\n")

		// Try to extract domain and FQDN from this block
		domain := extractFirstMatch(blockText, `DNS_Domain_Name:\s+([^\s]+)`)
		if domain == "" {
			domain = extractFirstMatch(blockText, `Domain:\s+([^\s]+)`)
		}

		fqdn := extractFirstMatch(blockText, `DNS_Computer_Name:\s+([^\s]+)`)
		if fqdn == "" {
			fqdn = extractFirstMatch(blockText, `NetBIOS_Computer_Name:\s+([^\s]+)`)
			if fqdn != "" {
				fmt.Println(color.YellowString("[*] FQDN fallback used NetBIOS: %s", fqdn))
			}
		}
		if fqdn == "" {
			fqdn = extractFirstMatch(blockText, `commonName=([^\s]+)`)
			if fqdn != "" {
				fmt.Println(color.YellowString("[*] FQDN fallback used SSL cert: %s", fqdn))
			}
		}
		if fqdn == "" {
			fqdn = extractFirstMatch(blockText, `Target_Name:\s+([^\s]+)`)
			if fqdn != "" {
				fmt.Println(color.YellowString("[*] FQDN fallback used RDP Target_Name: %s", fqdn))
			}
		}

		if domain == "" || fqdn == "" {
			continue
		}

		key := ip + "|" + fqdn
		if seen[key] {
			continue
		}
		seen[key] = true

		dcEntries = append(dcEntries, DCEntry{IP: ip, Domain: domain, FQDN: fqdn})
	}

	if len(dcEntries) == 0 {
		fmt.Println(color.RedString("[-] No domain controller entries found in the file."))
		os.Exit(1)
	}

	// Print table
	fmt.Println(color.YellowString("Parsed Domain Controllers:"))
	fmt.Println("-------------------------------------------------------------")
	fmt.Printf("%-15s | %-30s | %-20s\n", "IP Address", "FQDN", "Domain")
	fmt.Println("-------------------------------------------------------------")
	for _, dc := range dcEntries {
		fmt.Printf("%-15s | %-30s | %-20s\n", dc.IP, dc.FQDN, dc.Domain)
	}
	fmt.Println("-------------------------------------------------------------")
	fmt.Println()

	// Write targets.txt
	var ips []string
	for _, dc := range dcEntries {
		ips = append(ips, dc.IP)
	}
	err = os.WriteFile("targets.txt", []byte(strings.Join(ips, "\n")+"\n"), 0644)
	if err != nil {
		fmt.Println(color.RedString("[-] Failed to write to targets.txt: %s", err))
		os.Exit(1)
	}
	fmt.Println(color.GreenString("[+] targets.txt created"))

	// Prompt user to add entries
	fmt.Println()
	for _, dc := range dcEntries {
		fmt.Println(color.HiMagentaString("[!] COPY/PASTE THIS to /etc/hosts:"))
		fmt.Println(color.HiWhiteString(dc.IP + " " + dc.FQDN))
		fmt.Println()
		fmt.Print(color.CyanString("[?] Add this DC to host entries? (y/n): "))
		reader.Scan()
		if strings.ToLower(strings.TrimSpace(reader.Text())) == "y" {
			AddHostEntry(dc.IP, dc.FQDN)
			if domainName == "" {
				domainName = dc.Domain
			}
		}
		fmt.Println()
	}

	fmt.Println(color.YellowString("[*] You can add additional workstations, webhosts, etc. via the 'Hosts' menu."))
	fmt.Println()
}

func extractFirstMatch(input, pattern string) string {
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(input)
	if len(match) > 1 {
		return match[1]
	}
	return ""
}

func AddCredential(username, password string) {
	cred := Credential{
		Username: username,
		Password: password,
	}
	credentials = append(credentials, cred)

	// Add username to list if not already present
	if !stringInSlice(username, usernames) {
		usernames = append(usernames, username)
	}

	// Save to files
	_ = exportCredsToFile("creds.txt")
	_ = exportUsernamesToFile("users.txt")

	fmt.Println(color.GreenString("[+] Credential added: %s", username))
	fmt.Println(color.YellowString("[*] creds.txt and users.txt updated."))
}

func exportCredsToFile(filename string) error {
	var lines []string
	for _, cred := range credentials {
		lines = append(lines, fmt.Sprintf("%s:%s", cred.Username, cred.Password))
	}
	content := strings.Join(lines, "\n")
	return os.WriteFile(filename, []byte(content), 0644)
}

func exportUsernamesToFile(filename string) error {
	content := strings.Join(usernames, "\n")
	return os.WriteFile(filename, []byte(content), 0644)
}

func stringInSlice(str string, list []string) bool {
	for _, item := range list {
		if item == str {
			return true
		}
	}
	return false
}

func ListCredentials() {
	fmt.Println(color.YellowString("\nCaptured Credentials:"))
	fmt.Println("-------------------------------------")

	for i, cred := range credentials {
		fmt.Printf("[%d] %s : %s\n", i, cred.Username, cred.Password)
	}

	fmt.Println()
}

func AddHostEntry(ip, hostname string) {
	entry := HostEntry{
		IP:       ip,
		Hostname: hostname,
	}
	hostEntries = append(hostEntries, entry)
	// Export IPs to targets.txt after every add
	err := exportAllIPsToFile("targets.txt")
	if err != nil {
		fmt.Println(color.RedString("[-] Failed to export IPs to targets.txt: %s", err))
	} else {
		fmt.Println(color.GreenString("[+] Added host entry: %s -> %s", ip, hostname))
		fmt.Println(color.YellowString("[*] targets.txt updated with all current IPs."))
	}
}

func exportAllIPsToFile(filename string) error {
	var lines []string
	for _, entry := range hostEntries {
		lines = append(lines, entry.IP)
	}
	content := strings.Join(lines, "\n")
	return os.WriteFile(filename, []byte(content), 0644)
}

func ListHostEntries() {
	fmt.Println(color.YellowString("\nHost Entries:"))
	fmt.Println("-------------------------------------")

	for i, entry := range hostEntries {
		fmt.Printf("[%d] %-15s  %s\n", i+1, entry.IP, entry.Hostname)
	}

	fmt.Println()
}

func promptDomainName() {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print(color.CyanString("[domain] > Enter target domain name (e.g., company.local): "))

		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if input != "" {
			domainName = input
			fmt.Println(color.GreenString("[+] Domain name set to: %s", domainName))
			break
		}
		fmt.Println(color.RedString("[-] Domain name cannot be empty."))
	}
	fmt.Println()
}

func menu() {
	fmt.Println(color.HiWhiteString(`
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
	`))
}

func promptInitialHosts() {
	fmt.Println(color.CyanString("[*] Enter target host(s). Format: <ip> <hostname>"))
	fmt.Println(color.CyanString("[*] Type 'done' when finished.\n"))

	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print(color.CyanString("[host entry] > "))

		if !scanner.Scan() {
			break
		}

		line := strings.TrimSpace(scanner.Text())
		if strings.ToLower(line) == "done" {
			break
		}

		parts := strings.Fields(line)
		if len(parts) != 2 {
			fmt.Println(color.RedString("[-] Invalid format. Use: <ip> <hostname>"))
			continue
		}

		ip := parts[0]
		hostname := parts[1]

		AddHostEntry(ip, hostname)
	}

	fmt.Println()
}

func handleUsersSubcommand() {
	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Println(color.YellowString("\n[Users Module]"))
		fmt.Println("Options:")
		fmt.Println("  add  - Add credentials")
		fmt.Println("  list - List stored credentials")
		fmt.Println("  back - Return to main menu")
		fmt.Println()
		fmt.Print(color.CyanString("[users] > "))

		if !scanner.Scan() {
			break
		}
		input := strings.TrimSpace(scanner.Text())

		switch input {
		case "add":
			fmt.Print("Username: ")
			scanner.Scan()
			username := strings.TrimSpace(scanner.Text())

			fmt.Print("Password: ")
			scanner.Scan()
			password := strings.TrimSpace(scanner.Text())

			AddCredential(username, password)

		case "list":
			ListCredentials()

		case "back", "exit":
			return

		default:
			fmt.Println(color.RedString("[-] Unknown subcommand"))
		}
	}
}

func handleHostsSubcommand() {
	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Println(color.YellowString("\n[Hosts Module]"))
		fmt.Println("Options:")
		fmt.Println("  add  - Add a new host entry")
		fmt.Println("  list - List stored hosts")
		fmt.Println("  back - Return to main menu")
		fmt.Println()
		fmt.Print(color.CyanString("[hosts] > "))

		if !scanner.Scan() {
			break
		}
		input := strings.TrimSpace(scanner.Text())

		switch input {
		case "add":
			fmt.Print("IP Address: ")
			scanner.Scan()
			ip := strings.TrimSpace(scanner.Text())

			fmt.Print("Hostname: ")
			scanner.Scan()
			hostname := strings.TrimSpace(scanner.Text())

			AddHostEntry(ip, hostname)

		case "list":
			ListHostEntries()

		case "back", "exit":
			return

		default:
			fmt.Println(color.RedString("[-] Unknown subcommand"))
		}
	}
}

func handleEnumNoCreds() {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println(color.WhiteString("Please choose an enumeration option [first] and a host entry [second]"))
	fmt.Println(color.WhiteString("Sample Outout: 1 1"))
	fmt.Println(color.WhiteString("1 1 -> [1] anon/guest [1] dc01.company.local"))
	fmt.Println(color.WhiteString("2 1 -> [2] smb share  [1] dc01.company.local"))
	fmt.Println(color.YellowString(`
[Enumeration: No Credentials]
  [1] Anonymous/Guest login test
  [2] SMB Share Listing (smbclient -L)
  [3] SID/Users Lookup
  [back] Return to main menu
	`))
	for {

		fmt.Print(color.CyanString("~ reef ~ [no-creds] > "))
		if !scanner.Scan() {
			return
		}
		choice := strings.TrimSpace(scanner.Text())
		if choice == "back" {
			return
		}

		parts := strings.Fields(choice)
		if len(parts) != 2 {
			fmt.Println(color.RedString("[-] Invalid format. Use: <option> <host_entry> or <option> all (ex. 1 1, 1 2,...)"))
			continue
		}

		option := parts[0]
		targetInput := parts[1]

		var targets []string
		if targetInput == "all" {
			targets = []string{"targets.txt"}
		} else {
			index, err := strconv.Atoi(targetInput)
			if err != nil || index < 1 || index > len(hostEntries) {
				fmt.Println(color.RedString("[-] Invalid host index"))
				continue
			}
			targets = []string{hostEntries[index-1].IP}
		}
		switch option {
		case "1": //anonymous/guest
			for _, target := range targets {
				if target == "targets.txt" {
					fmt.Println(color.GreenString("[*] Running netexec...%s", target))
					cmd := exec.Command("nxc", "smb", "targets.txt", "-u", "", "-p", "")
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stderr
					_ = cmd.Run()
					fmt.Println()
					cmd2 := exec.Command("nxc", "smb", "targets.txt", "-u", "guest", "-p", "")
					cmd2.Stdout = os.Stdout
					cmd2.Stderr = os.Stderr
					_ = cmd2.Run()
					fmt.Println()
				} else {
					fmt.Println(color.GreenString("[*] Running netexec...%s", target))
					cmd := exec.Command("nxc", "smb", target, "-u", "", "-p", "")
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stderr
					_ = cmd.Run()
					fmt.Println()
					cmd2 := exec.Command("nxc", "smb", "targets.txt", "-u", "guest", "-p", "")
					cmd2.Stdout = os.Stdout
					cmd2.Stderr = os.Stderr
					_ = cmd2.Run()
					fmt.Println()
				}
			}
		case "2": //smb share listing / optional share access
			for _, target := range targets {
				if target == "targets.txt" {
					fmt.Println(color.RedString("[-] Share listing requires a single target, not 'all'"))
					continue
				}

				fmt.Println(color.GreenString("[*] Running smbclient...%s", target))
				cmd := exec.Command("smbclient", "-L", "//"+target, "-N")
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				_ = cmd.Run()

				// Ask if user wants to access a specific share
				fmt.Print(color.CyanString("[?] Try to access a share on %s? (y/n): ", target))
				scanner.Scan()
				resp := strings.ToLower(strings.TrimSpace(scanner.Text()))
				if resp == "y" {
					fmt.Print(color.CyanString("Enter share name: "))
					scanner.Scan()
					share := strings.TrimSpace(scanner.Text())

					fmt.Println(color.GreenString("[*] Running: smbclient...%s Share: %s", target, share))
					cmd := exec.Command("smbclient", fmt.Sprintf("//%s/%s", target, share), "-U", "anon")
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stderr
					_ = cmd.Run()
				}
			}
		case "3":
			for _, target := range targets {
				if target == "targets.txt" {
					fmt.Println(color.RedString("[-] DC target only. Select a single target."))
					continue
				}

				fmt.Println(color.GreenString("[*] Running impacket-lookupsid against %s", target))

				cmd := exec.Command("impacket-lookupsid", fmt.Sprintf("%s/guest:''@%s", domainName, target))
				output, err := cmd.Output()
				if err != nil {
					fmt.Println(color.RedString("[-] Error running impacket-lookupsid: %s", err))
					continue
				}

				// Print raw output to user
				fmt.Println(string(output))

				// Parse usernames from output
				lines := strings.Split(string(output), "\n")
				for _, line := range lines {
					// Basic check for RID/User pattern, e.g. "SID: S-1-5-21...-500 -> DOMAIN\\Administrator"
					if strings.Contains(line, "\\") {
						parts := strings.Split(line, "\\")
						if len(parts) == 2 {
							user := strings.TrimSpace(parts[1])
							// Avoid duplicates
							if !stringInSlice(user, usernames) {
								usernames = append(usernames, user)
								fmt.Println(color.GreenString("[+] Found user: %s", user))
							}
						}
					}
				}

				// Write updated user list to file
				err = exportUsernamesToFile("users.txt")
				if err != nil {
					fmt.Println(color.RedString("[-] Failed to update users.txt: %s", err))
				} else {
					fmt.Println(color.YellowString("[*] users.txt updated."))
				}
			}

		default:
			fmt.Println(color.RedString("[-] Unknown option. Use 1 or 2."))
		}
	}
}

func main() {

	color.Cyan(banner)
	fmt.Println()
	fmt.Printf("%s Active Directory Pentest Automation Framework for Lazy Hackers ;) Happy Hunting!\n", color.CyanString("[+]"))
	fmt.Printf("%s Developer : %s\n", color.CyanString("[+]"), color.CyanString("CThu1hu"))
	fmt.Println()
	fmt.Println("DISCLAIMER:")
	fmt.Printf("%s Reef-CTF is designed exclusively for use in Capture The Flag (CTF) environments, home labs, and\n", color.CyanString("[+]"))
	fmt.Println("    education scenarios. Do NOT use this tool against any system you do not own or have explicit,")
	fmt.Println("    written permission to test.")
	fmt.Printf("%s The creator(s) of this tool are not responsible for any misuse or damage resulting from its use.\n", color.CyanString("[+]"))
	fmt.Println()

	parseNmapFileAndSetup()
	if domainName == "" {
		promptDomainName()
	}
	if len(hostEntries) == 0 {
		promptInitialHosts()
	}

	fmt.Println()
	fmt.Printf("%s Starting Reef... Type 'help' or 'exit'.\n", color.CyanString("[+]"))
	time.Sleep(2 * time.Second)
	fmt.Println()
	menu()
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print(promptString)

		if !scanner.Scan() {
			break //EOF or error
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		//process command
		if !handleCommand(line) {
			break
		}
	}
}

func credsMenu() {
	fmt.Println(color.HiWhiteString(`
    [1]  Password Reuse      (Password Spray against users.txt)                        
    [2]  RDP & MSSQL         (Test for RDP/MSSQL privileges against targets.txt)			      
	[3]  SMB                 (Users/Shares, password policy, smbclient, Kerberos Authentication 'NTLM Disabled')
	[4]  Kerberoast/AS-REP   (Target kerb auth to extract service tickets & extract TGTs from users with kerberos preauth disabled)
	[5]  Ldapdomaindump      ()
	[6]  Legacy Computers    (pre2k)

	`))
}

func handleCommand(line string) bool {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return true
	}
	cmd := parts[0]

	switch cmd {
	case "exit", "quit", "x":
		fmt.Println(color.CyanString("[*] Exiting Reef..."))
		time.Sleep(3 * time.Second)
		return false
	case "help":
		menu()
	case "1":
		handleHostsSubcommand()
		fmt.Println()
	case "2":
		handleUsersSubcommand()
		fmt.Println()
	case "3":
		ListHostEntries()
		handleEnumNoCreds()
	case "4":
		ListCredentials()
		fmt.Println()
		credsMenu()

	case "5":
		fmt.Println(color.WhiteString("\n[Bloodhound Collector]"))
		ListHostEntries()
		reader := bufio.NewScanner(os.Stdin)
		fmt.Print(color.GreenString("Host Index (FQDN): "))
		reader.Scan()
		hostChoice := strings.TrimSpace(reader.Text())

		hostIndex, err := strconv.Atoi(hostChoice)
		if err != nil || hostIndex < 1 || hostIndex > len(hostEntries) {
			fmt.Println(color.RedString("[-] Invalid host index"))
			break
		}
		selectedHost := hostEntries[hostIndex-1]

		ListCredentials()
		fmt.Print(color.GreenString("Credential Index: "))
		reader.Scan()
		credChoice := strings.TrimSpace(reader.Text())

		credIndex, err := strconv.Atoi(credChoice)
		if err != nil || credIndex < 0 || credIndex >= len(credentials) {
			fmt.Println(color.RedString("[-] Invalid credential index"))
			break
		}
		selectedCred := credentials[credIndex]
		outputDir := "bloodhound"
		if _, err := os.Stat(outputDir); os.IsNotExist(err) {
			err := os.Mkdir(outputDir, 0755)
			if err != nil {
				fmt.Println(color.RedString("[-] Failed to create bloodhound directory: %s", err))
				break
			}
		}
		timestamp := time.Now().Format("20060102-150405")
		outFile := fmt.Sprintf("%s/%s-%s", outputDir, selectedHost.Hostname, timestamp)
		// Build and run command
		fmt.Println(color.GreenString(
			"[*] Running rusthound-ce...",
		))

		cmd := exec.Command(
			"rusthound-ce",
			"--domain", domainName,
			"-f", selectedHost.Hostname,
			"-u", selectedCred.Username,
			"-p", selectedCred.Password,
			"-o", outFile,
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run()
		fmt.Println(color.GreenString("[+] Collection saved to %s directory.", outFile))

	// --- SCANNER COMMANDS ---
	case "scan":

	case "threads":

	// ------------------------

	case "connect":
		fmt.Println(color.YellowString("[!] Command not implemented yet. Use 'connect <ip> <user> <pass>'"))
	default:
		fmt.Printf(color.RedString("[-] Unknown command: %s\n"), cmd)
		fmt.Println(color.WhiteString("Type 'help' for menu."))
	}
	return true
}
