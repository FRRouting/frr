#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2026 Subodh Wagh <subodhwagh1122@gmail.com>
#
# This file is part of FRRouting (FRR).

# Exit immediately if a command fails
set -e

# --- Colors for Output ---
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}Starting FRR developer environment setup...${NC}"

# 1. Ensure Local Dev Config Directory Exists
# This allows devs to test zebra/bgp without touching /etc/frr
CONFIG_DIR="$HOME/.frr_local"
if [ ! -d "$CONFIG_DIR" ]; then
    echo -e "${YELLOW}Creating local dev config directory at $CONFIG_DIR...${NC}"
    mkdir -p "$CONFIG_DIR"
else
    echo -e "${GREEN}Config directory already exists.${NC}"
fi

# 2. Check for FRR Build Dependencies
# These are the actual packages required to compile FRR from source
REQS=("git" "curl" "python3" "bison" "flex" "make" "pkg-config" "libtool" "automake" "autoconf")
MISSING_COUNT=0

echo -e "\nChecking build dependencies..."
for tool in "${REQS[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        echo -e "${RED}[MISSING]${NC} $tool"
        MISSING_COUNT=$((MISSING_COUNT + 1))
    else
        echo -e "${GREEN}[FOUND]${NC} $tool"
    fi
done

# Provide a helpful install command if things are missing
if [ $MISSING_COUNT -gt 0 ]; then
    echo -e "\n${YELLOW}Suggested command to install missing tools (Debian/Ubuntu):${NC}"
    echo -e "sudo apt update && sudo apt install -y ${REQS[*]} libjson-c-dev libelf-dev libreadline-dev"
fi

# 3. Setup Placeholder Configuration Files
CONF_FILE="$CONFIG_DIR/zebra.conf"
if [ ! -f "$CONF_FILE" ]; then
    echo -e "\n${YELLOW}Initializing default zebra settings...${NC}"
    echo "! Default Zebra Configuration" > "$CONF_FILE"
    echo "password zebra" >> "$CONF_FILE"
    echo "line vty" >> "$CONF_FILE"
    echo -e "${GREEN}Default zebra.conf created at $CONF_FILE${NC}"
else
    echo -e "\n${GREEN}zebra.conf already exists. Skipping.${NC}"
fi

echo -e "-----------------------------------------------"
echo -e "${GREEN}Setup process complete!${NC}"
