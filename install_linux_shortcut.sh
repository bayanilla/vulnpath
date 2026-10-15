#!/bin/sh
# Adds VulnPath to the Linux application menu with the Múcaro M icon, so the launcher window
# shows that icon in the dock/taskbar (GNOME on Wayland takes it from this entry, not the window).
# Per user, no root needed. Remove with: rm ~/.local/share/applications/vulnpath.desktop
set -e
here=$(cd "$(dirname "$0")" && pwd)
dir="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
mkdir -p "$dir"
cat > "$dir/vulnpath.desktop" <<ENTRY
[Desktop Entry]
Type=Application
Name=VulnPath
Comment=Rank the vulnerable services that hostile traffic targets
Exec="$here/run_vulnpath.sh"
Icon=$here/assets/vulnpath-256.png
Terminal=false
Categories=Utility;Security;
StartupWMClass=Vulnpath
ENTRY
chmod +x "$dir/vulnpath.desktop" "$here/run_vulnpath.sh"
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$dir" >/dev/null 2>&1 || true
echo "Added VulnPath to the application menu ($dir/vulnpath.desktop)."
