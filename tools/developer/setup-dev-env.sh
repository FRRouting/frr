#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2026 Subodh Wagh <subodhwagh1122@gmail.com>
#
# This file is part of FRRouting (FRR).

set -e

# --- Colors ---
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}Starting FRR developer environment setup...${NC}"

# 1. Ensure Local Dev Config Directory Exists
CONFIG_DIR="$HOME/.frr_local"
mkdir -p "$CONFIG_DIR"

# 2. Check for FRR Build Dependencies (Aligned with doc/developer/building-frr-for-ubuntu2x04.rst)
# Added compilers, texinfo, and libraries
REQS=("git" "curl" "python3" "bison" "flex" "make" "gcc" "g++" "pkg-config" "libtool" "automake" "autoconf" "texinfo" "install-info" "perl")
LIBS=("libjson-c-dev" "libelf-dev" "libreadline-dev" "libc-ares-dev" "libpam0g-dev" "libsnmp-dev" "libcap-dev" "libunwind-dev")

MISSING_COUNT=0

echo -e "\nChecking build tools..."
for tool in "${REQS[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        echo -e "${RED}[MISSING]${NC} $tool"
        MISSING_COUNT=$((MISSING_COUNT + 1))
    else
        echo -e "${GREEN}[FOUND]${NC} $tool"
    fi
done

echo -e "\nChecking required libraries (dpkg check)..."
for lib in "${LIBS[@]}"; do
    if ! dpkg -s "$lib" >/dev/null 2>&1; then
        echo -e "${RED}[MISSING]${NC} $lib"
        MISSING_COUNT=$((MISSING_COUNT + 1))
    else
        echo -e "${GREEN}[FOUND]${NC} $lib"
    fi
done

if [ $MISSING_COUNT -gt 0 ]; then
    echo -e "\n${YELLOW}To install all dependencies, run:${NC}"
    echo -e "sudo apt update && sudo apt install -y ${REQS[*]} ${LIBS[*]}"
fi

# 3. Setup Placeholder Configuration (Security Fixed: No hardcoded password)
CONF_FILE="$CONFIG_DIR/zebra.conf"
if [ ! -f "$CONF_FILE" ]; then
    echo -e "\n${YELLOW}Initializing default zebra settings...${NC}"
    echo "! Default Zebra Configuration" > "$CONF_FILE"
    echo "! Please set your own password below" >> "$CONF_FILE"
    echo "! password YOUR_PASSWORD_HERE" >> "$CONF_FILE"
    echo "line vty" >> "$CONF_FILE"
    echo -e "${GREEN}Default zebra.conf created (passwords commented out for security).${NC}"
fi

echo -e "-----------------------------------------------"
echo -e "${GREEN}Setup process complete!${NC}"
