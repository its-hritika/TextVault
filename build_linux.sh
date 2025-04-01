#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Building TextVault for Linux...${NC}"

# Check if Python3 is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python3 is not installed${NC}"
    exit 1
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo -e "${RED}Error: pip3 is not installed${NC}"
    exit 1
fi

# Install required packages
echo -e "${YELLOW}Installing required packages...${NC}"
pip3 install -r requirements.txt
pip3 install pyinstaller

# Clean previous builds
echo -e "${YELLOW}Cleaning previous builds...${NC}"
rm -rf build dist

# Build the executable
echo -e "${YELLOW}Building executable...${NC}"
pyinstaller textvault.spec

# Check if build was successful
if [ -f "dist/textvault" ]; then
    echo -e "${GREEN}Build successful!${NC}"
    echo -e "${GREEN}Executable location: dist/textvault${NC}"
    echo -e "\n${YELLOW}Usage:${NC}"
    echo -e "  ./dist/textvault --gui"
    echo -e "  ./dist/textvault --encrypt \"Hello World\" --password \"mypassword\""
    echo -e "  ./dist/textvault --decrypt \"encrypted_text\" --password \"mypassword\""
else
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi 