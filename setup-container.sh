#!/bin/bash
set -e

AI_USER="%%MACHINE_USER%%"
AI_LOCALE="en_US.UTF-8"
AI_NODEJS_VERSION="22"
RUSTUP_VERSION="1.28.2"
RUSTUP_SHA256="17247e4bcacf6027ec2e11c79a72c494c9af69ac8d1abcc1b271fa4375a106c2"
GOLANG_VERSION="1.26.3"
GOLANG_ARCH="amd64"
GOLANG_SHA256="2b2cfc7148493da5e73981bffbf3353af381d5f93e789c82c79aff64962eb556"
ARCH=$(uname -m)
if [ "$ARCH" = "aarch64" ]; then
    GOLANG_SHA256="9d89a3ea57d141c2b22d70083f2c8459ba3890f2d9e818e7e933b75614936565"
    GOLANG_ARCH="arm64"
fi

export DEBIAN_FRONTEND=noninteractive

# If running under Ghostty, fall back to xterm-256color since the container
# won't have the xterm-ghostty terminfo entry.
if [ "$TERM" = "xterm-ghostty" ]; then
    export TERM=xterm-256color
fi

echo "I: Setting up the sandbox environment"
if grep -q "^ID=ubuntu$" /etc/os-release; then
    echo -e "\n# Adding Ubuntu security and updates repositories"
    # Get the codename from existing sources.list
    CODENAME=$(grep "^deb .* main" /etc/apt/sources.list | head -1 | awk '{print $3}')
    if [ -n "$CODENAME" ]; then
        cat >> /etc/apt/sources.list << EOF
# Security updates
deb http://security.ubuntu.com/ubuntu $CODENAME-security main universe
# Regular updates
deb http://archive.ubuntu.com/ubuntu $CODENAME-updates main universe
EOF
        echo "Added security and updates repos for Ubuntu $CODENAME"
    else
        echo "W: Could not determine Ubuntu codename from sources.list"
    fi
fi
echo -e "\nI: apt-get update && apt-get dist-upgrade"
apt-get update
apt-get dist-upgrade -y

# While cn-debootstrap.sh uses --include=locale,tzdata, we include them here
# since OCI images might need it
echo -e "\nI: Install required packages for the system"
apt-get install -y \
  adduser \
  iproute2 \
  locales \
  tzdata

# Add the user
getent passwd "$AI_USER" || {
  echo -e "I: Add \"$AI_USER\" user"
  adduser --disabled-password --gecos "AI User,,," "$AI_USER"
}

# Setup the workspace directory
if [ ! -e "/home/$AI_USER/workspace" ]; then
  su -l "$AI_USER" -c "mkdir /home/$AI_USER/workspace"
fi

# Setup the shared directory
if [ ! -e "/home/$AI_USER/shared" ]; then
  su -l "$AI_USER" -c "mkdir /home/$AI_USER/shared"
fi

echo -e "\nI: Generate locale for $AI_LOCALE"
echo "$AI_LOCALE UTF-8" > /etc/locale.gen
locale-gen "$AI_LOCALE"
update-locale LANG="$AI_LOCALE"

# Ensure interactive shells fall back from xterm-ghostty to xterm-256color
echo -e "\nI: Add xterm-ghostty TERM fallback to /etc/bash.bashrc"
echo '# xterm-ghostty terminfo is not available in the container' >> /etc/bash.bashrc
echo 'if [ "$TERM" = "xterm-ghostty" ]; then export TERM=xterm-256color; fi' >> /etc/bash.bashrc

# Add set_title helper for setting the host terminal title.
echo -e "\nI: Add set_title helper to /etc/bash.bashrc"
cat >> /etc/bash.bashrc <<'EOF'

# set_title <text> (preserves original PS1 so we can repeatedly update
set_title() {
    if [[ -z "$ORIG_PS1" ]]; then
        ORIG_PS1="$PS1"
    fi
    local TITLE="\[\e]2;$*\a\]"
    PS1="${ORIG_PS1}${TITLE}"
    export CLAUDE_CODE_DISABLE_TERMINAL_TITLE=1
}
EOF

echo -e "\nI: Install handy tools"
apt-get install -y \
  bash-completion \
  bc \
  bind9-dnsutils \
  bind9-host \
  command-not-found \
  gh \
  less \
  lsb-base \
  neovim \
  netcat-openbsd \
  patchelf \
  poppler-utils \
  procps
apt-get update  # for command-not-found

echo -e "\nI: Install tools for AI"
apt-get install -y \
  ca-certificates \
  curl \
  fd-find \
  file \
  git \
  incus-client \
  iputils-ping \
  jq \
  manpages-dev \
  patch \
  ripgrep \
  rsync \
  shellcheck \
  sqlite3 \
  wget

echo -e "\nI: Install build tools"
apt-get install -y \
  build-essential \
  clang \
  libssl-dev \
  lld \
  pkg-config \
  protobuf-compiler \
  python3-dev \
  python3-venv \
  python3-pip

# cleanup
apt-get clean

TMPDIR=$(mktemp -d)
chmod 1777 "$TMPDIR"

# Install rust
echo -e "\nI: Install rust"
cd "$TMPDIR"
curl -L --proto "=https" --tlsv1.2 -sSf "https://raw.githubusercontent.com/rust-lang/rustup/${RUSTUP_VERSION}/rustup-init.sh" -o ./rustup-init.sh
echo "$RUSTUP_SHA256  rustup-init.sh" | sha256sum -c -- || exit 1
mv "$TMPDIR"/rustup-init.sh /usr/local/bin
chmod 755 /usr/local/bin/rustup-init.sh
su -l "$AI_USER" -c "rustup-init.sh -y"
su -l "$AI_USER" -c "rustup default stable"
su -l "$AI_USER" -c "rustc --version"
su -l "$AI_USER" -c "rustup component add rust-analyzer"
cd - > /dev/null

# Install golang
echo -e "\nI: Install golang"
cd "$TMPDIR"
GOLANG_TARBALL="go${GOLANG_VERSION}.linux-${GOLANG_ARCH}.tar.gz"
curl -L --proto "=https" --tlsv1.2 -sSf "https://go.dev/dl/${GOLANG_TARBALL}" -o "$GOLANG_TARBALL"
echo "$GOLANG_SHA256  $GOLANG_TARBALL" | sha256sum -c -- || exit 1
tar -C /usr/local -zxf "$TMPDIR/$GOLANG_TARBALL"
su -l "$AI_USER" -c "/usr/local/go/bin/go version"
cd - > /dev/null

# ensure ~/.local/bin exists
if ! test -d "/home/$AI_USER/.local/bin" ; then
  echo -e "\nI: create ~/.local/bin"
  su -l "$AI_USER" -c "mkdir -p /home/$AI_USER/.local/bin"
fi

# adjust path for go and ~/.local/bin
echo -e "\nI: Adjust PATH for go and ~/.local/bin"
echo "export PATH=\"\$PATH:/usr/local/go/bin:\$HOME/go/bin:\$HOME/.local/bin\"" >> "/home/$AI_USER/.bashrc"

# update the git credential helper to honor GH_TOKEN with https://github.com/...
echo -e "\nI: Add git credential helper for GH_TOKEN and https://github.com/..."
cat > "/home/$AI_USER/.gitconfig" << 'EOF'
[credential "https://github.com"]
	helper = "!f() { echo \"username=x-access-token\"; echo \"password=${GH_TOKEN}\"; }; f"
EOF
chown "$AI_USER:$AI_USER" "/home/$AI_USER/.gitconfig"

# add resize_term function for terminal resize in sandy -c <container> sessions
echo -e "\nI: Add resize_term function"
cat >> "/home/$AI_USER/.bashrc" << 'EOF'

# Resize terminal by querying the terminal emulator directly
resize_term() {
    local old_settings=$(stty -g)
    stty raw -echo min 0 time 1
    printf '\e[18t'
    local response
    IFS=';' read -r -d 't' _ rows cols < /dev/tty
    stty "$old_settings"
    if [[ -n "$rows" && -n "$cols" ]]; then
        stty rows "$rows" cols "$cols"
    fi
    echo "Terminal size (rows x cols): $(stty size)"
}
EOF

# Install node
if [ ! -e "/home/$AI_USER/.nvm" ]; then
  echo -e "\nI: Install node"
  cd "$TMPDIR"
  curl -o install.sh https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh
  echo "2d8359a64a3cb07c02389ad88ceecd43f2fa469c06104f92f98df5b6f315275f  install.sh" sha256sum --check -- || exit 1
  su -l "$AI_USER" -c "bash $TMPDIR/install.sh"
  echo -e "\nI: Install node 24"
  su -l "$AI_USER" -c ". \"/home/$AI_USER/.nvm/nvm.sh\" && nvm install 24"
  echo -e "\nI: Install node 22"
  su -l "$AI_USER" -c ". \"/home/$AI_USER/.nvm/nvm.sh\" && nvm install 22"
  echo -e "\nI: Default to node 22"
  su -l "$AI_USER" -c ". \"/home/$AI_USER/.nvm/nvm.sh\" && nvm alias default \"$AI_NODEJS_VERSION\""
fi

#
# Helpful additional tools
#
for tool in semver yarn pnpm typescript typescript-language-server ts-morph tree-sitter-cli; do
  echo -e "\nI: Install $tool (node)"
  # this installs to ~/.nvm/versions/node/<nodever>/bin which is in the user's
  # PATH as part of nvm install
  su -l "$AI_USER" -c ". \"/home/$AI_USER/.nvm/nvm.sh\" && npm install -g '$tool'"
done

for tool in "github.com/mikefarah/yq/v4@v4.47.2" "golang.org/x/vuln/cmd/govulncheck@latest" "golang.org/x/tools/gopls@latest" "golang.org/x/tools/cmd/callgraph@latest" ; do
    echo -e "\nI: Install $tool (go)"
  # this installs to ~/go/bin which is in the user's PATH as part of rustup
  su -l "$AI_USER" -c "/usr/local/go/bin/go install '$tool'"
done

# shellcheck disable=SC2043
for tool in cargo-audit ; do
    echo -e "\nI: Install $tool (cargo)"
  # this installs to ~/.cargo/bin which is in the user's PATH as part of rustup
  su -l "$AI_USER" -c "/home/$AI_USER/.cargo/bin/cargo install '$tool'"
done

#
# AI tools
#
ai_tools=()

# Install claude code - native install
if [ ! -e "/home/$AI_USER/.local/bin/claude" ]; then
  echo -e "\nI: Install claude"
  cd "$TMPDIR"
  curl -fsSL -o claude-install.sh https://claude.ai/install.sh
  echo "a27f0c75029d86eab7313ce4d5a2464e4e68dcce76905a1462a76ab4f19937de  claude-install.sh" --check -- || exit 1
  su -l "$AI_USER" -c "bash $TMPDIR/claude-install.sh"
  ai_tools+=("claude (https://github.com/anthropics/claude-code):")
  ai_tools+=("- newline: ctrl+j or shift+enter")
  ai_tools+=("- verbose: launch with 'claude --verbose' or use '/config' to toggle")

  # disable auto-updates (don't work in ephemeral container; verify with native install)
  echo '{"autoUpdates": false}' > "/home/$AI_USER/.claude.json"
  chown "$AI_USER:$AI_USER" "/home/$AI_USER/.claude.json"
  chmod 600 "/home/$AI_USER/.claude.json"

  # install plugins (lsp improves efficiency (doesn't need compiler))
  echo -e "\nI: claude plugin marketplace add anthropics/claude-plugins-official"
  su -l "$AI_USER" -c "claude plugin marketplace add anthropics/claude-plugins-official"
  for plugin in gopls-lsp pyright-lsp rust-analyzer-lsp typescript-lsp plugin-dev ; do
    echo -e "\nI: claude plugin install $plugin@claude-plugins-official"
    su -l "$AI_USER" -c "claude plugin install $plugin@claude-plugins-official"
  done

  # install influxdb-docs mcp - https://docs.influxdata.com/kapacitor/v1/reference/mcp-server/
  echo -e "\nI: claude mcp add --transport http influxdb-docs https://influxdb-docs.mcp.kapa.ai"
  su -l "$AI_USER" -c "claude mcp add --transport http influxdb-docs https://influxdb-docs.mcp.kapa.ai"
fi

# Install openai codex
if ! test -e "/home/$AI_USER"/.nvm/versions/node/*/bin/codex ; then
  echo -e "\nI: Install openai/codex"
  # this installs to ~/.nvm/versions/node/<nodever>/bin which is in the user's
  # PATH as part of nvm install
  su -l "$AI_USER" -c ". \"/home/$AI_USER/.nvm/nvm.sh\" && npm install -g @openai/codex"
  ai_tools+=("codex (https://github.com/openai/codex; newline: ctrl+j or alt+enter)")

  # raise the subagent thread limit
  mkdir -p "/home/$AI_USER/.codex"
  chown "$AI_USER:$AI_USER" "/home/$AI_USER/.codex"
  chmod 700 "/home/$AI_USER/.codex"
  echo -e '[agents]\nmax_threads = 10\n' >> "/home/$AI_USER/.codex/config.toml"
  chown "$AI_USER:$AI_USER" "/home/$AI_USER/.codex/config.toml"
  chmod 600 "/home/$AI_USER/.codex/config.toml"
fi

# Install copilot cli
if ! test -e "/home/$AI_USER"/.nvm/versions/node/*/bin/copilot ; then
  echo -e "\nI: Install copilot-cli"
  su -l "$AI_USER" -c ". \"/home/$AI_USER/.nvm/nvm.sh\" && npm install -g @github/copilot"
  ai_tools+=("copilot (https://github.com/github/copilot-cli; ctrl+enter or shift+enter)")
fi

# Install gemini-cli
if ! test -e "/home/$AI_USER"/.nvm/versions/node/*/bin/gemini ; then
  echo -e "\nI: Install gemini-cli"
  # this installs to ~/.nvm/versions/node/<nodever>/bin which is in the user's
  # PATH as part of nvm install
  su -l "$AI_USER" -c ". \"/home/$AI_USER/.nvm/nvm.sh\" && npm install -g @google/gemini-cli"
  ai_tools+=("gemini (https://github.com/google-gemini/gemini-cli; newline: ctrl+j or alt+enter)")

  # adjust path for go and ~/.local/bin
  echo -e "\nI: Add gemini alias for NO_BROWSER=true"
  echo "alias gemini='NO_BROWSER=true gemini'" >> "/home/$AI_USER/.bashrc"
fi

# install mcp-grafana
if ! test -e "/home/$AI_USER"/go/bin/mcp-grafana ; then
  echo -e "\nI: Install mcp-grafana"
  su -l "$AI_USER" -c "/usr/local/go/bin/go install github.com/grafana/mcp-grafana/cmd/mcp-grafana@v0.7.8"
  ai_tools+=("mcp-grafana (https://github.com/grafana/mcp-grafana)")
fi

# install influxdb3_mcp_server
if ! test -e "/home/$AI_USER"/.nvm/versions/node/*/bin/influxdb-mcp-server ; then
  echo -e "\nI: Install influxdb-mcp-server"
  # this installs to ~/.nvm/versions/node/<nodever>/bin which is in the user's
  # PATH as part of nvm install
  su -l "$AI_USER" -c ". \"/home/$AI_USER/.nvm/nvm.sh\" && git clone https://github.com/influxdata/influxdb3_mcp_server.git .influxdb3_mcp_server && cd ./.influxdb3_mcp_server && npm install && npm run build && npm link"
  ai_tools+=("influxdb-mcp-server (https://github.com/influxdata/influxdb3_mcp_server)")
fi

# do this last so all the tools are listed
if ! grep -q "AI tools:" "/home/$AI_USER/.bashrc" ; then
  {
    echo ""
    echo 'cat <<EOM'
    echo
    echo "AI Tools:"
    printf -- '- %s\n' "${ai_tools[@]}"
    echo 'EOM'
  } >> "/home/$AI_USER/.bashrc"
fi

#
# end AI tools
#

echo -e "\nI: Cleaning up $TMPDIR"
rm -rf "${TMPDIR:?}"/*

echo -e "\nI: Cleaning up cache files, etc"
rm -rf "/home/$AI_USER"/.cache/*
rm -rf "/home/$AI_USER"/.cargo/git
rm -rf "/home/$AI_USER"/.cargo/registry
rm -rf "/home/$AI_USER"/go/pkg/*
su -l "$AI_USER" -c ". \"/home/$AI_USER/.nvm/nvm.sh\" && npm cache clean --force"
# this is 1.4G, but it removes the default toolchain, so we shouldn't do it
# if we need a usable cargo
#rm -rf "/home/$AI_USER"/.rustup   # rustup still in ~/.cargo/bin

echo "Done!!"
