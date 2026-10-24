#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/saifelarifi/cyberlog-analyzer.git"
APP_DIR="$HOME/.local/share/newbiesaif"
BIN_DIR="$HOME/.local/bin"

echo
echo "======================================"
echo "       NewbieSaif Installer"
echo "======================================"
echo

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: Python 3 is required."
    exit 1
fi

if ! command -v git >/dev/null 2>&1; then
    echo "Error: Git is required. Install Git first."
    exit 1
fi

mkdir -p "$(dirname "$APP_DIR")" "$BIN_DIR"

if [ -d "$APP_DIR/.git" ]; then
    echo "Updating NewbieSaif..."
    git -C "$APP_DIR" pull --ff-only
else
    echo "Downloading NewbieSaif..."
    git clone "$REPO_URL" "$APP_DIR"
fi

echo "Creating Python environment..."
python3 -m venv "$APP_DIR/.venv"

echo "Installing NewbieSaif..."
"$APP_DIR/.venv/bin/python" -m pip install --upgrade pip
"$APP_DIR/.venv/bin/python" -m pip install "$APP_DIR"

cat > "$BIN_DIR/newbiesaif" <<EOF
#!/usr/bin/env bash
exec "$APP_DIR/.venv/bin/newbiesaif" "\$@"
EOF

chmod +x "$BIN_DIR/newbiesaif"

echo
echo "Installation completed!"
echo "Run: $BIN_DIR/newbiesaif"
echo

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *)
        echo 'Add this line to ~/.zshrc or ~/.bashrc:'
        echo 'export PATH="$HOME/.local/bin:$PATH"'
        echo
        echo "Or run the tool using: $BIN_DIR/newbiesaif"
        ;;
esac
