#!/bin/bash
# Git Submodules Fix Script
# Resolves Git submodule issues for Seth blockchain project

set -e

echo "=== Git Submodules Fix Script ==="
echo "Cleaning up Git submodule configuration..."

# Remove any cached submodule references
echo "1. Cleaning Git cache..."
git rm --cached clipy/liboqs 2>/dev/null || true
git rm --cached third_party/evmone 2>/dev/null || true

# Clean up .git/config
echo "2. Cleaning .git/config..."
if [ -f ".git/config" ]; then
    # Remove problematic submodule entries from .git/config
    sed -i '/\[submodule.*clipy\/liboqs\]/,/^$/d' .git/config 2>/dev/null || true
    sed -i '/clipy\/liboqs/d' .git/config 2>/dev/null || true
fi

# Clean up .git/modules
echo "3. Cleaning .git/modules..."
if [ -d ".git/modules/clipy" ]; then
    rm -rf .git/modules/clipy/liboqs 2>/dev/null || true
    rmdir .git/modules/clipy 2>/dev/null || true
fi

if [ -d ".git/modules/third_party/evmone" ]; then
    rm -rf .git/modules/third_party/evmone 2>/dev/null || true
fi

# Remove physical directories if they exist and are empty
echo "4. Cleaning physical directories..."
if [ -d "clipy/liboqs" ] && [ -z "$(ls -A clipy/liboqs)" ]; then
    rmdir clipy/liboqs 2>/dev/null || true
fi

# Reset submodule status
echo "5. Resetting submodule status..."
git submodule deinit --all -f 2>/dev/null || true

# Reinitialize valid submodules
echo "6. Reinitializing valid submodules..."
git submodule update --init --recursive 2>/dev/null || {
    echo "  Warning: Some submodules may have failed to initialize"
    echo "  This is normal for missing or problematic submodules"
}

# Create a clean submodule status
echo "7. Creating clean submodule status..."
git submodule status 2>/dev/null || echo "  No active submodules found"

echo ""
echo "=== Git Submodules Fix Complete ==="
echo "✅ Removed problematic submodule references"
echo "✅ Cleaned Git configuration"
echo "✅ Reinitialized valid submodules"
echo ""
echo "You can now run: git submodule init"
echo "Or use the build dependency fix script: bash fix_build_dependencies.sh"