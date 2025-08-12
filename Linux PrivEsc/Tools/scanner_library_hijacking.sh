#!/bin/bash

# SETUID Library Hijacking Scanner
# Searches for SETUID binaries vulnerable to library hijacking

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== SETUID Library Hijacking Scanner ===${NC}"
echo -e "${YELLOW}Searching for SETUID binaries vulnerable to library hijacking...${NC}\n"

# Function to check if a directory is writable by current user
check_writable() {
    local dir="$1"
    if [ -d "$dir" ] && [ -w "$dir" ]; then
        return 0
    fi
    return 1
}

# Function to check RUNPATH/RPATH
check_runpath() {
    local binary="$1"
    local runpath=$(readelf -d "$binary" 2>/dev/null | grep -E "(RUNPATH|RPATH)" | sed 's/.*\[\(.*\)\].*/\1/' | tr ':' '\n')
    
    if [ -n "$runpath" ]; then
        echo "$runpath"
    fi
}

# Function to get libraries from a binary
get_libraries() {
    local binary="$1"
    ldd "$binary" 2>/dev/null | grep '=>' | awk '{print $3}' | grep -v '^$'
}

# Counter for found vulnerabilities
vuln_count=0
vulnerable_binaries=()

echo -e "${BLUE}Searching for SETUID binaries...${NC}"
find / -type f -perm -4000 2>/dev/null | while read -r binary; do
    
    # Check if file exists and is executable
    if [ ! -x "$binary" ]; then
        continue
    fi
    
    binary_vulnerable=false
    
    # Check for custom RUNPATH/RPATH
    runpaths=$(check_runpath "$binary")
    if [ -n "$runpaths" ]; then
        echo "$runpaths" | while read -r path; do
            if [ -n "$path" ] && check_writable "$path"; then
                # Find libraries in this writable RUNPATH
                libraries=$(get_libraries "$binary")
                echo "$libraries" | while read -r lib; do
                    if [ -n "$lib" ] && [[ "$lib" == "$path"* ]]; then
                        echo -e "${RED}[VULNERABLE] $binary${NC}"
                        echo -e "${RED}  -> Library: $lib${NC}"
                        echo -e "${RED}  -> Writable RUNPATH: $path${NC}"
                        break
                    fi
                done
                binary_vulnerable=true
                break
            fi
        done
    fi
    
    # Skip further checks if already found vulnerable via RUNPATH
    if [ "$binary_vulnerable" = true ]; then
        continue
    fi
    
    # Get libraries used by binary
    libraries=$(get_libraries "$binary")
    
    if [ -n "$libraries" ]; then
        echo "$libraries" | while read -r lib; do
            if [ -n "$lib" ] && [ -f "$lib" ]; then
                lib_dir=$(dirname "$lib")
                
                # Check if library directory is writable
                if check_writable "$lib_dir"; then
                    echo -e "${RED}[VULNERABLE] $binary${NC}"
                    echo -e "${RED}  -> Library: $lib${NC}"
                    echo -e "${RED}  -> Writable library path: $lib_dir${NC}"
                    binary_vulnerable=true
                    break
                fi
                
                # Check if library itself is writable
                if [ -w "$lib" ]; then
                    echo -e "${RED}[VULNERABLE] $binary${NC}"
                    echo -e "${RED}  -> Library: $lib${NC}"
                    echo -e "${RED}  -> Writable library file${NC}"
                    binary_vulnerable=true
                    break
                fi
            fi
        done
    fi
    
    # Check standard library directories
    standard_lib_dirs="/lib /lib64 /usr/lib /usr/lib64 /usr/local/lib /opt/lib"
    for lib_dir in $standard_lib_dirs; do
        if check_writable "$lib_dir"; then
            # Show which libraries from this binary use this writable directory
            libraries=$(get_libraries "$binary")
            echo "$libraries" | while read -r lib; do
                if [ -n "$lib" ] && [[ "$lib" == "$lib_dir"* ]]; then
                    echo -e "${RED}[CRITICAL] $binary${NC}"
                    echo -e "${RED}  -> Library: $lib${NC}"
                    echo -e "${RED}  -> System library directory writable: $lib_dir${NC}"
                    binary_vulnerable=true
                    break
                fi
            done
            if [ "$binary_vulnerable" = true ]; then
                break
            fi
        fi
    done
    
done

# Check linker configuration files
echo -e "\n${YELLOW}Checking linker configuration...${NC}"
if [ -f "/etc/ld.so.conf" ]; then
    cat /etc/ld.so.conf 2>/dev/null | while read -r line; do
        if [ -d "$line" ] && check_writable "$line"; then
            echo -e "${RED}[SYSTEM VULNERABLE] Writable library path in ld.so.conf: $line${NC}"
        fi
    done
fi

if [ -d "/etc/ld.so.conf.d" ]; then
    find /etc/ld.so.conf.d/ -name "*.conf" 2>/dev/null | while read -r conf_file; do
        cat "$conf_file" 2>/dev/null | while read -r line; do
            if [ -d "$line" ] && check_writable "$line"; then
                echo -e "${RED}[SYSTEM VULNERABLE] Writable library path in $conf_file: $line${NC}"
            fi
        done
    done
fi

echo -e "\n${BLUE}=== Scan Complete ===${NC}"
