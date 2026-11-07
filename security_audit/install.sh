#!/bin/sh
# Install local scanner binaries and, when asked, a 02:00 scheduler.
# The audit itself does not need this script. Built-in checks run with Python 3.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
TOOLS="$ROOT/security_audit/.tools/bin"
mkdir -p \
  "$TOOLS" \
  "$ROOT/logs" \
  "$ROOT/alerts/history" \
  "$ROOT/history" \
  "$ROOT/security_reports" \
  "$ROOT/reports" \
  "$ROOT/knowledge_base" \
  "$ROOT/vulnerability_patterns" \
  "$ROOT/trend_analysis"

install_tools=0
scheduler=none

while [ $# -gt 0 ]; do
  case "$1" in
    --install-tools)
      install_tools=1
      shift
      ;;
    --scheduler)
      scheduler=${2:-}
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      echo "Usage: $0 [--install-tools] [--scheduler cron|systemd]" >&2
      exit 2
      ;;
  esac
done

fetch_archive() {
  url=$1
  sha=$2
  archive=$3
  binary=$4
  tmp=$(mktemp -d)
  curl -fsSL "$url" -o "$tmp/$archive"
  echo "$sha  $tmp/$archive" | sha256sum -c -
  tar -xzf "$tmp/$archive" -C "$tmp"
  if [ ! -f "$tmp/$binary" ]; then
    echo "Archive did not contain $binary" >&2
    rm -rf "$tmp"
    exit 1
  fi
  mv "$tmp/$binary" "$TOOLS/$binary"
  chmod 755 "$TOOLS/$binary"
  rm -rf "$tmp"
}

fetch_binary() {
  url=$1
  sha=$2
  binary=$3
  tmp=$(mktemp)
  curl -fsSL "$url" -o "$tmp"
  echo "$sha  $tmp" | sha256sum -c -
  mv "$tmp" "$TOOLS/$binary"
  chmod 755 "$TOOLS/$binary"
}

if [ "$install_tools" -eq 1 ]; then
  fetch_archive \
    "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz" \
    "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb" \
    "gitleaks.tar.gz" \
    "gitleaks"
  fetch_archive \
    "https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_Linux-64bit.tar.gz" \
    "bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf" \
    "trivy.tar.gz" \
    "trivy"
  fetch_binary \
    "https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_linux_amd64" \
    "160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b" \
    "osv-scanner"
  echo "Installed gitleaks, trivy, and osv-scanner into security_audit/.tools/bin"
fi

case "$scheduler" in
  none)
    ;;
  cron)
    line="0 2 * * * cd $ROOT && /usr/bin/python3 -m security_audit >> $ROOT/logs/cron.log 2>&1"
    (crontab -l 2>/dev/null | grep -v 'python3 -m security_audit' || true; echo "$line") | crontab -
    echo "Installed a user crontab entry for 02:00 local time."
    ;;
  systemd)
    unit_dir=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user
    mkdir -p "$unit_dir"
    sed "s|@REPO_ROOT@|$ROOT|g" "$ROOT/security_audit/scheduler/security-audit.service" > "$unit_dir/portfolio-security-audit.service"
    sed "s|@REPO_ROOT@|$ROOT|g" "$ROOT/security_audit/scheduler/security-audit.timer" > "$unit_dir/portfolio-security-audit.timer"
    systemctl --user daemon-reload
    systemctl --user enable --now portfolio-security-audit.timer
    echo "Enabled the user systemd timer for 02:00 local time."
    ;;
  *)
    echo "Unsupported scheduler: $scheduler" >&2
    exit 2
    ;;
esac

echo "Audit command: python3 -m security_audit"
echo "GitHub Actions runs the same command daily at 02:00 UTC once this workflow is on the default branch."
