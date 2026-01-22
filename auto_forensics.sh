#!/bin/bash
#By Avishay Wietschner TMagen773639.s8 

# ==============================================================================
# WINDOWS FORENSIC AUTOMATION PROJECT
# VISION: Cyber units operating in an automated way
# MISSION: Automatic analysis of Memory and HDD files
# ==============================================================================

# --- Global Variables ---
REPORT_DIR=""
TARGET_FILE=""
START_TIME=$(date +%s)
LOG_FILE=""

# --- Colors for Output ---
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ==============================================================================
# 1. INITIALIZATION & CHECKS
# ==============================================================================

# 1.1 Check current user; exit if not root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[!] Error: This script must be run as root.${NC}" 
        echo "Try: sudo ./auto_forensics.sh"
        exit 1
    else
        echo -e "${GREEN}[+] Running as root.${NC}"
    fi
}

# 1.2 Allow user to specify filename; check if exists
get_input_file() {
    if [ -z "$1" ]; then
        read -p "Enter the full path to the forensic image/memory file: " TARGET_FILE
    else
        TARGET_FILE="$1"
    fi

    if [[ ! -f "$TARGET_FILE" ]]; then
        echo -e "${RED}[!] Error: File '$TARGET_FILE' does not exist.${NC}"
        exit 1
    fi
    echo -e "${GREEN}[+] Target file located: $TARGET_FILE${NC}"
}

# 1.3 Function to install forensics tools if missing
check_and_install_tools() {
    echo -e "${BLUE}[*] Checking for required tools...${NC}"
    
    # Added 'unzip' and 'wget' to the list as they are needed for the Volatility install
    TOOLS=("foremost" "bulk_extractor" "strings" "zip" "grep" "wget" "unzip")
    
    UPDATED=false

    for tool in "${TOOLS[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${YELLOW}[!] $tool is missing. Attempting to install...${NC}"
            if [ "$UPDATED" = false ]; then
                apt-get update -y > /dev/null 2>&1
                UPDATED=true
            fi
            apt-get install -y "$tool"
        fi
    done

    # --- VOLATILITY AUTO-INSTALL LOGIC ---
    if ! command -v volatility &> /dev/null; then
        echo -e "${YELLOW}[!] Volatility 2 not found. Downloading Standalone Binary...${NC}"
        
        # 1. Download the Standalone Zip from Volatility Foundation
        # We use the official standalone version to avoid Python 2 dependency errors
        wget -q --show-progress "http://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_lin64_standalone.zip" -O volatility_standalone.zip
        
        # 2. Unzip it
        echo -e "${BLUE}[*] Extracting Volatility...${NC}"
        unzip -o volatility_standalone.zip -d ./vol_temp > /dev/null
        
        # 3. Move to /usr/bin/ and make executable
        # The unzip creates a specific folder structure, we move the binary out
        mv ./vol_temp/volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone /usr/bin/volatility
        chmod +x /usr/bin/volatility
        
        # 4. Cleanup
        rm -rf volatility_standalone.zip ./vol_temp
        
        # 5. Verify
        if command -v volatility &> /dev/null; then
             echo -e "${GREEN}[+] Volatility installed successfully!${NC}"
        else
             echo -e "${RED}[!] Failed to install Volatility. Check internet connection.${NC}"
             exit 1
        fi
    else
         echo -e "${GREEN}[+] Volatility is already installed.${NC}"
    fi
    
    echo -e "${GREEN}[+] All tools verified.${NC}"
}

setup_directories() {
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    REPORT_DIR="./Forensic_Report_$TIMESTAMP"
    mkdir -p "$REPORT_DIR"
    mkdir -p "$REPORT_DIR/Carved_Data"
    mkdir -p "$REPORT_DIR/Extracted_Text"
    mkdir -p "$REPORT_DIR/Volatility_Output"
    
    LOG_FILE="$REPORT_DIR/analysis_log.txt"
    touch "$LOG_FILE"
    
    echo "Analysis started at: $(date)" > "$LOG_FILE"
    echo "Target File: $TARGET_FILE" >> "$LOG_FILE"
    echo "------------------------------------------------" >> "$LOG_FILE"
}

log_message() {
    echo -e "$1"
    # Strip color codes for the log file
    echo -e "$1" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE"
}

# ==============================================================================
# 2. AUTOMATE HDD ANALYSIS (CARVING & EXTRACTION)
# ==============================================================================

run_file_analysis() {
    log_message "${BLUE}[*] Starting File/HDD Analysis...${NC}"

    # 1.4 Use different carvers to automatically extract data
    log_message "${YELLOW}[*] Running Foremost carver...${NC}"
    foremost -t all -i "$TARGET_FILE" -o "$REPORT_DIR/Carved_Data/Foremost" &> /dev/null
    log_message "${GREEN}[+] Foremost carving complete.${NC}"

    # 1.5 Data is being saved into $REPORT_DIR/Carved_Data

    # 1.6 Attempt to extract network traffic (PCAP) using bulk_extractor
    log_message "${YELLOW}[*] Running Bulk Extractor (this may take time)...${NC}"
    bulk_extractor -o "$REPORT_DIR/Carved_Data/BulkExtractor" "$TARGET_FILE" -E net &> /dev/null
    
    # Check for PCAP files
    PCAP_COUNT=$(find "$REPORT_DIR/Carved_Data/BulkExtractor" -name "*.pcap" | wc -l)
    if [[ $PCAP_COUNT -gt 0 ]]; then
        log_message "${GREEN}[+] Network traffic detected! Found $PCAP_COUNT pcap files.${NC}"
        log_message "    Location: $REPORT_DIR/Carved_Data/BulkExtractor/packets.pcap"
    else
        log_message "${YELLOW}[-] No direct PCAP files extracted.${NC}"
    fi

    # 1.7 Check for human-readable strings
    log_message "${YELLOW}[*] Extracting human-readable strings...${NC}"
    strings "$TARGET_FILE" > "$REPORT_DIR/Extracted_Text/all_strings.txt"
    
    # Scan for specifics
    log_message "[*] Scanning strings for sensitive info..."
    
    echo "--- Potential Credentials/Usernames ---" >> "$REPORT_DIR/Extracted_Text/sensitive_findings.txt"
    grep -E -i "password|username|passwd|login" "$REPORT_DIR/Extracted_Text/all_strings.txt" | head -n 20 >> "$REPORT_DIR/Extracted_Text/sensitive_findings.txt"
    
    echo "--- Potential Executables (.exe references) ---" >> "$REPORT_DIR/Extracted_Text/sensitive_findings.txt"
    grep -i "\.exe" "$REPORT_DIR/Extracted_Text/all_strings.txt" | head -n 20 >> "$REPORT_DIR/Extracted_Text/sensitive_findings.txt"

    log_message "${GREEN}[+] String analysis complete. Saved to Extracted_Text folder.${NC}"
}

# ==============================================================================
# 3. MEMORY ANALYSIS WITH VOLATILITY
# ==============================================================================

run_memory_analysis() {
    log_message "${BLUE}[*] Starting Memory Analysis with Volatility...${NC}"
    
    # Use 'volatility' command. Adjust if using vol.py
    VOL_CMD="volatility"
    if ! command -v volatility &> /dev/null; then
        if command -v vol.py &> /dev/null; then
            VOL_CMD="vol.py"
        else
            log_message "${RED}[!] Volatility not found. Skipping memory analysis.${NC}"
            return
        fi
    fi

    # 2.1 Check if file can be analyzed (Image Identification)
    log_message "${YELLOW}[*] Identifying image profile...${NC}"
    IMAGE_INFO=$($VOL_CMD -f "$TARGET_FILE" imageinfo 2>/dev/null)
    
    # 2.2 Find memory profile
    # Extract the first suggested profile
    PROFILE=$(echo "$IMAGE_INFO" | grep "Suggested Profile(s)" | awk -F : '{print $2}' | awk -F , '{print $1}' | xargs)

    if [ -z "$PROFILE" ] || [ "$PROFILE" == "No" ]; then
        log_message "${RED}[!] Could not identify a valid Windows memory profile. Skipping Volatility.${NC}"
        log_message "    (Note: If this is an HDD image, Volatility will fail naturally.)"
    else
        log_message "${GREEN}[+] Profile Identified: $PROFILE${NC}"
        
        # 2.3 Display running processes
        log_message "${YELLOW}[*] Extracting Process List (pslist)...${NC}"
        $VOL_CMD -f "$TARGET_FILE" --profile="$PROFILE" pslist > "$REPORT_DIR/Volatility_Output/pslist.txt" 2>/dev/null
        log_message "    Saved to Volatility_Output/pslist.txt"

        # 2.4 Display network connections
        log_message "${YELLOW}[*] Extracting Network Connections (netscan/connscan)...${NC}"
        # Try netscan first (Win7+), fallback to connscan (XP/2003)
        $VOL_CMD -f "$TARGET_FILE" --profile="$PROFILE" netscan > "$REPORT_DIR/Volatility_Output/network.txt" 2>/dev/null
        if [ ! -s "$REPORT_DIR/Volatility_Output/network.txt" ]; then
             $VOL_CMD -f "$TARGET_FILE" --profile="$PROFILE" connscan > "$REPORT_DIR/Volatility_Output/network.txt" 2>/dev/null
        fi
        log_message "    Saved to Volatility_Output/network.txt"

        # 2.5 Attempt to extract registry information
        log_message "${YELLOW}[*] Extracting Registry Hives (hivelist)...${NC}"
        $VOL_CMD -f "$TARGET_FILE" --profile="$PROFILE" hivelist > "$REPORT_DIR/Volatility_Output/hivelist.txt" 2>/dev/null
        log_message "    Saved to Volatility_Output/hivelist.txt"
    fi
}

# ==============================================================================
# 4. RESULTS & CLEANUP
# ==============================================================================

generate_report() {
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    
    log_message "${BLUE}[*] Generatng Final Report...${NC}"
    
    # 3.1 Display general statistics
    NUM_FILES=$(find "$REPORT_DIR" -type f | wc -l)
    
    echo "==========================================" >> "$LOG_FILE"
    echo "ANALYSIS SUMMARY" >> "$LOG_FILE"
    echo "==========================================" >> "$LOG_FILE"
    echo "Time taken: ${DURATION} seconds" >> "$LOG_FILE"
    echo "Total files generated: $NUM_FILES" >> "$LOG_FILE"
    echo "Report Directory: $REPORT_DIR" >> "$LOG_FILE"
    
    log_message "${GREEN}[+] Analysis Complete.${NC}"
    log_message "    Time taken: ${DURATION} seconds"
    log_message "    Files Extracted: $NUM_FILES"

    # 3.3 Zip the extracted files and report
    log_message "${YELLOW}[*] Archiving results...${NC}"
    ZIP_NAME="Forensics_Report_$(date +"%Y%m%d_%H%M%S").zip"
    zip -r "$ZIP_NAME" "$REPORT_DIR" &> /dev/null
    
    log_message "${GREEN}[+] Results Archived: $ZIP_NAME${NC}"
}

# ==============================================================================
# MAIN EXECUTION FLOW
# ==============================================================================

check_root
get_input_file "$1"
check_and_install_tools
setup_directories
run_file_analysis
run_memory_analysis
generate_report
