#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2026 Your Name <subodhwagh1122@gmail.com>
#
# This file is part of FRRouting (FRR).
# setup-dev-env.sh - Initializes the developer environment
# Location: tools/developer/setup-dev-env.sh

# Exit immediately if a command fails
set -e

# --- Colors for Output ---
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}Starting developer environment setup...${NC}"

# 1. Ensure Config Directory Exists
CONFIG_DIR="$HOME/.config/dev-tools"
if [ ! -d "$CONFIG_DIR" ]; then
    echo -e "${YELLOW}Creating config directory at $CONFIG_DIR...${NC}"
    mkdir -p "$CONFIG_DIR"
else
    echo -e "${GREEN}Config directory already exists.${NC}"
fi

# 2. Check for Required Dependencies (Example: git, curl)
REQS=("git" "curl")
for tool in "${REQS[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        echo -e "${YELLOW}Warning: $tool is not installed. Please install it to use all features.${NC}"
    else
        echo -e "${GREEN}Check passed: $tool is installed.${NC}"
    fi
done

# 3. Setup Configuration Files
# Logic: Only copy/download if the file doesn't exist
CONF_FILE="$CONFIG_DIR/settings.conf"
if [ ! -f "$CONF_FILE" ]; then
    echo -e "${YELLOW}Initializing default settings...${NC}"
    # Example: Create a placeholder or download from the repo
    echo "USER_MODE=developer" > "$CONF_FILE"
    echo "DEBUG_LEVEL=info" >> "$CONF_FILE"
    echo -e "${GREEN}Default settings created.${NC}"
else
    echo -e "${GREEN}Settings file already exists. Skipping initialization.${NC}"
fi

# 4. Final Success Message
echo -e "-----------------------------------------------"
echo -e "${GREEN}Setup complete!${NC}"
echo -e "Your environment is ready. Configs located in: ${BLUE}$CONFIG_DIR${NC}"
