#!/bin/bash
# ============================================================================
# Package Lambda Function
# ============================================================================
# Usage: ./scripts/package-lambda.sh
# Output: dist/lambda.zip
# ============================================================================

set -e  # Exit on error

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== Packaging Lambda Function ===${NC}"

# Paths
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
DIST_DIR="$PROJECT_ROOT/dist"
LAMBDA_ZIP="$DIST_DIR/lambda.zip"

# 1. Clean build directory
echo -e "${YELLOW}Cleaning build directory...${NC}"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# 2. Copy source files
echo -e "${YELLOW}Copying source files...${NC}"
cp -r "$PROJECT_ROOT/src" "$BUILD_DIR/"
cp "$PROJECT_ROOT/package.json" "$BUILD_DIR/"
cp "$PROJECT_ROOT/package-lock.json" "$BUILD_DIR/"

# 3. Install production dependencies
echo -e "${YELLOW}Installing production dependencies...${NC}"
cd "$BUILD_DIR"
npm install --production

# 4. Create ZIP from the build directory
echo -e "${YELLOW}Creating ZIP archive...${NC}"
mkdir -p "$DIST_DIR"
zip -r "$LAMBDA_ZIP" . -x "*.git*" "*.env*" "test/*" "*.swp"

# 5. Show contents
echo -e "${YELLOW}ZIP contents:${NC}"
unzip -l "$LAMBDA_ZIP" | head -30

echo -e "${GREEN}✅ Lambda package created: $LAMBDA_ZIP${NC}"
echo -e "${GREEN}   Size: $(du -h "$LAMBDA_ZIP" | cut -f1)${NC}"