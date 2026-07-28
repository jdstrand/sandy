#!/bin/bash
set -e

AI_USER="%%MACHINE_USER%%"
AI_LOCALE="en_US.UTF-8"

if [[ ! "$AI_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
    echo "E: Invalid machine user" >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

# If running under Ghostty, fall back to xterm-256color since the container
# will not have the xterm-ghostty terminfo entry.
if [ "${TERM:-}" = "xterm-ghostty" ]; then
    export TERM=xterm-256color
fi

echo "I: Setting up the minimal sandbox environment"
if grep -q "^ID=ubuntu$" /etc/os-release; then
    echo -e "\nI: Adding Ubuntu security and updates repositories"
    CODENAME=$(grep "^deb .* main" /etc/apt/sources.list 2>/dev/null | head -1 | awk '{print $3}')
    if [ -n "$CODENAME" ]; then
        cat >> /etc/apt/sources.list <<EOF
# Security updates
deb http://security.ubuntu.com/ubuntu $CODENAME-security main universe
# Regular updates
deb http://archive.ubuntu.com/ubuntu $CODENAME-updates main universe
EOF
        echo "I: Added security and updates repositories for Ubuntu $CODENAME"
    else
        echo "W: Could not determine Ubuntu codename from sources.list"
    fi
fi

echo -e "\nI: apt-get update && apt-get dist-upgrade"
apt-get update
apt-get dist-upgrade -y

echo -e "\nI: Install required packages for the system"
apt-get install -y \
    adduser \
    ca-certificates \
    curl \
    iproute2 \
    locales \
    python3 \
    tzdata

getent passwd "$AI_USER" >/dev/null || {
    echo "I: Add '$AI_USER' user"
    adduser --disabled-password --gecos "AI User,,," "$AI_USER"
}

install -d -m 0755 -o "$AI_USER" -g "$AI_USER" \
    "/home/$AI_USER/workspace" \
    "/home/$AI_USER/shared"

echo -e "\nI: Generate locale for $AI_LOCALE"
echo "$AI_LOCALE UTF-8" > /etc/locale.gen
locale-gen "$AI_LOCALE"
update-locale LANG="$AI_LOCALE"

echo -e "\nI: Add xterm-ghostty TERM fallback to /etc/bash.bashrc"
cat >> /etc/bash.bashrc <<'EOF'
# xterm-ghostty terminfo is not available in the container
if [ "$TERM" = "xterm-ghostty" ]; then export TERM=xterm-256color; fi
EOF

echo -e "\nI: Add set_title helper to /etc/bash.bashrc"
cat >> /etc/bash.bashrc <<'EOF'

# set_title <text> (preserves the original PS1 across repeated updates)
set_title() {
    if [[ -z "$ORIG_PS1" ]]; then
        ORIG_PS1="$PS1"
    fi
    local TITLE="\[\e]2;$*\a\]"
    PS1="${ORIG_PS1}${TITLE}"
    export CLAUDE_CODE_DISABLE_TERMINAL_TITLE=1
}
EOF

echo "I: Minimal sandbox setup complete"
