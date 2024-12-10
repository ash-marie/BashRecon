#!/bin/bash

# Check if a target IP is provided
if [ -z "$1" ]; then
    echo "Usage: ./Xplorr.sh <Target IP>"
    exit 1
fi

# Assign the target IP
TARGET=$1

# Initialize results file
RESULTS_FILE="results"
RESULTS_HTML="results.html"
printf "\n----- SCAN RESULTS FOR $TARGET -----\n\n" > "$RESULTS_FILE"

# Add formatted headers 
add_header() {
    printf "\n\n=====  $1  =====\n\n" >> "$RESULTS_FILE"
}

# Run Nmap for detailed port scan and service detection
echo "Running Nmap... curiosity may get you into trouble, but with Nmap, at least it will show you what kind of trouble..."
nmap -sV -A  -T4 "$TARGET" > nmap_temp
add_header "NMAP RESULTS"
cat nmap_temp >> "$RESULTS_FILE"

# Extract OS details
OS=$(grep "OS details" nmap_temp | cut -d: -f2 | xargs)
printf "\nDetected OS: $OS\n" >> "$RESULTS_FILE"

# Process Nmap results
while read -r line; do
    if [[ $line == *open* ]]; then
        # Extract port number
        PORT=$(echo "$line" | grep -oE '^[0-9]+')

        # HTTP services on port 80 and 8180
        if [[ $line == *http* ]]; then
            add_header " HTTP Service detected on port $PORT "
            # printf "\nHTTP service detected on port $PORT\n" >> "$RESULTS_FILE"
            echo "- Potential Apache Tomcat Exploitation (Metasploit: exploit/multi/http/tomcat_mgr_upload)" >> "$RESULTS_FILE"
            echo " -Potential HTTP Server Exploitation (Metasploit: exploit/unix/webapp/joomla_sql_injection)" >> "$RESULTS_FILE"

            # Run Gobuster for directory enumeration
            # echo "Running Gobuster for directory enumeration on port $PORT..."
            gobuster dir -u http://"$TARGET" -w /usr/share/seclists/Discovery/Web-Content/big.txt -qz > gobuster_temp 2>/dev/null
            if [ -s gobuster_temp ]; then
                printf "\n----- GOBUSTER RESULTS (Port $PORT) -----\n\n" >> "$RESULTS_FILE"
                cat gobuster_temp >> "$RESULTS_FILE"
            else
                printf "\n----- GOBUSTER RESULTS (Port $PORT) -----\nNo directories found.\n\n" >> "$RESULTS_FILE"
            fi
            rm gobuster_temp

            # Run WhatWeb for web fingerprinting
            # echo "Running WhatWeb for web fingerprinting..."
            whatweb -v http://"$TARGET" > whatweb_temp 2>/dev/null
            if [ -s whatweb_temp ]; then
                printf "\n----- WHATWEB RESULTS (Port $PORT) -----\n\n" >> "$RESULTS_FILE"
                cat whatweb_temp >> "$RESULTS_FILE"
            else
                printf "\n----- WHATWEB RESULTS (Port $PORT) -----\nNo web application data found.\n\n" >> "$RESULTS_FILE"
            fi
            rm whatweb_temp
        fi

        # SSH services on port 22
        if [[ $line == *ssh* ]] && [[ $line == *22/tcp* ]]; then
            printf "\nSSH service detected on port $PORT\n" >> "$RESULTS_FILE"
            # echo "- Exploit weaknesses in the SSH (Secure Shell) protocol or poorly configured SSH key-based authentication." >> "$RESULTS_FILE"
            # echo "- Manual enumeration recommended for credential brute-forcing or privilege escalation." >> "$RESULTS_FILE"
            ssh-keyscan -H $TARGET > ssh_keys_temp 2>/dev/null
            echo " -Potential SSH Brute Force (Metasploit: auxiliary/scanner/ssh/ssh_login)" >> "$RESULTS_FILE"
            echo " -Potential SSH Keys (Metasploit: auxiliary/scanner/ssh/ssh_keyscan)" >> "$RESULTS_FILE"
            add_header "SSH KEYS (Port $PORT)"
            printf "\n----- SSH KEYS -----\n\n" >> "$RESULTS_FILE"
            cat ssh_keys_temp >> "$RESULTS_FILE"
        fi

        # IRC services (detects potential backdoors)
        if [[ $line == *irc* ]]; then
            printf "\nIRC backdoor service detected on port $PORT\n" >> "$RESULTS_FILE"
            echo "- Potential IRC Exploit: UnrealIRCd 3.2.8.1 Backdoor Command Execution (Metasploit: exploit/unix/irc/unreal_ircd_3281_backdoor)" >> "$RESULTS_FILE"
        fi

        # FTP services on port 21
        if [[ $line == *ftp* ]] && [[ $line == *21/tcp* ]]; then
            printf "\nFTP service detected on port $PORT\n" >> "$RESULTS_FILE"
            echo "- Potential FTP Exploit: vsftpd 2.3.4 Backdoor Command Execution (Metasploit: exploit/unix/ftp/vsftpd_234_backdoor)" >> "$RESULTS_FILE"
        fi

        # Telnet services on port 23 (backdoor exploitation)
        if [[ $line == *telnet* ]] && [[ $line == *23/tcp* ]]; then
            printf "\nTelnet service detected on port $PORT\n" >> "$RESULTS_FILE"
            echo "- Potential TCP Exploit: Netgear TelnetEnable Command Injection (Metasploit: exploit/linux/telnet/netgear_telnetenable)" >> "$RESULTS_FILE"
        fi
    fi
done < nmap_temp
rm nmap_temp

# Generate HTML output 
echo "<html><body><h1>Scan Results for $TARGET</h1><pre>" > "$RESULTS_HTML"
cat "$RESULTS_FILE" >> "$RESULTS_HTML"

# Display final results
cat "$RESULTS_FILE"
