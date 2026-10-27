#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/saifelarifi/cyberlog-analyzer.git"
APP_DIR="$HOME/.local/share/newbiesaif"
BIN_DIR="$HOME/.local/bin"

usage() {
    echo "Usage: $0 vMAJOR.MINOR.PATCH"
    echo "Example: $0 v0.2.0"
}

if [[ $# -ne 1 ]]; then
    echo "Error: provide an exact semantic version tag (for example v0.2.0)." >&2
    usage >&2
    exit 2
fi
if [[ "$1" =~ ^v?([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
    TAG="v${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}"
else
    echo "Error: provide an exact semantic version tag (for example v0.2.0)." >&2
    usage >&2
    exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: Python 3 is required." >&2
    exit 1
fi
if ! command -v git >/dev/null 2>&1; then
    echo "Error: Git is required. Install Git first." >&2
    exit 1
fi

mkdir -p "$(dirname "$APP_DIR")" "$BIN_DIR"

if [[ -d "$APP_DIR/.git" ]]; then
    if [[ -n "$(git -C "$APP_DIR" status --porcelain --untracked-files=normal)" ]]; then
        echo "Error: $APP_DIR has local changes. Move or commit them before updating." >&2
        exit 1
    fi
    echo "Fetching release $TAG..."
    git -C "$APP_DIR" fetch --depth 1 origin "refs/tags/$TAG:refs/tags/$TAG"
    git -C "$APP_DIR" checkout --detach "$TAG"
elif [[ -e "$APP_DIR" ]]; then
    echo "Error: $APP_DIR exists but is not a Git checkout; move it before installing." >&2
    exit 1
else
    echo "Downloading release $TAG..."
    git clone --depth 1 --branch "$TAG" --single-branch "$REPO_URL" "$APP_DIR"
fi

echo "Creating Python environment..."
python3 -m venv "$APP_DIR/.venv"

echo "Installing NewbieSaif $TAG..."
"$APP_DIR/.venv/bin/python" -m pip install --upgrade pip
"$APP_DIR/.venv/bin/python" -m pip install --upgrade "$APP_DIR"

cat > "$BIN_DIR/newbiesaif" <<EOF
#!/usr/bin/env bash
exec "$APP_DIR/.venv/bin/newbiesaif" "\$@"
EOF

chmod +x "$BIN_DIR/newbiesaif"

echo
echo "Installation completed: $TAG"
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
