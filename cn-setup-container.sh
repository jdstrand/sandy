#!/bin/bash
set -e

AI_USER="%%MACHINE_USER%%"
AI_LOCALE="en_US.UTF-8"
AI_NODEJS_VERSION="22"
RUSTUP_VERSION="1.28.2"
RUSTUP_SHA256="17247e4bcacf6027ec2e11c79a72c494c9af69ac8d1abcc1b271fa4375a106c2"
GOLANG_VERSION="1.25.1"
GOLANG_ARCH="amd64"
GOLANG_SHA256="7716a0d940a0f6ae8e1f3b3f4f36299dc53e31b16840dbd171254312c41ca12e"
ARCH=$(uname -m)
if [ "$ARCH" = "aarch64" ]; then
    GOLANG_SHA256="65a3e34fb2126f55b34e1edfc709121660e1be2dee6bdf405fc399a63a95a87d"
    GOLANG_ARCH="arm64"
fi

export DEBIAN_FRONTEND=noninteractive

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

echo -e "\nI: Generate locale for $AI_LOCALE"
echo "$AI_LOCALE UTF-8" > /etc/locale.gen
locale-gen "$AI_LOCALE"
update-locale LANG="$AI_LOCALE"

echo -e "\nI: Install handy tools"
apt-get install -y \
  bash-completion \
  bind9-host \
  command-not-found \
  less \
  lsb-base \
  neovim \
  netcat-openbsd \
  procps
apt-get update  # for command-not-found

echo -e "\nI: Install tools for AI"
apt-get install -y \
  ca-certificates \
  curl \
  file \
  git \
  iputils-ping \
  jq \
  manpages-dev \
  patch \
  ripgrep \
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

# Install rust
echo -e "\nI: Install rust"
cd /tmp
curl -L --proto "=https" --tlsv1.2 -sSf "https://raw.githubusercontent.com/rust-lang/rustup/${RUSTUP_VERSION}/rustup-init.sh" -o ./rustup-init.sh
echo "$RUSTUP_SHA256  rustup-init.sh" | sha256sum -c -- || exit 1
mv /tmp/rustup-init.sh /usr/local/bin
chmod 755 /usr/local/bin/rustup-init.sh
su -l "$AI_USER" -c "rustup-init.sh -y"
su -l "$AI_USER" -c "rustc --version"
cd - > /dev/null

# Install golang
echo -e "\nI: Install golang"
cd /tmp
GOLANG_TARBALL="go${GOLANG_VERSION}.linux-${GOLANG_ARCH}.tar.gz"
curl -L --proto "=https" --tlsv1.2 -sSf "https://go.dev/dl/${GOLANG_TARBALL}" -o "$GOLANG_TARBALL"
echo "$GOLANG_SHA256  $GOLANG_TARBALL" | sha256sum -c -- || exit 1
tar -C /usr/local -zxf "/tmp/$GOLANG_TARBALL"
su -l "$AI_USER" -c "/usr/local/go/bin/go version"
cd - > /dev/null

# install yq
echo -e "\nI: Install yq"
su -l "$AI_USER" -c "/usr/local/go/bin/go install github.com/mikefarah/yq/v4@v4.47.2"

# adjust path for go
echo -e "\nI: Adjust PATH for go"
echo "export PATH=\"\$PATH:/usr/local/go/bin:\$HOME/go/bin\"" >> "/home/$AI_USER/.bashrc"

# Install node
if [ ! -e "/home/$AI_USER/.nvm" ]; then
  echo -e "\nI: Install node"
  cd /tmp
  curl -o install.sh https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh
  echo "2d8359a64a3cb07c02389ad88ceecd43f2fa469c06104f92f98df5b6f315275f  install.sh" sha256sum --check -- || exit 1
  su -l "$AI_USER" -c "bash /tmp/install.sh"
  su -l "$AI_USER" -c ". \"/home/$AI_USER/.nvm/nvm.sh\" && nvm install \"$AI_NODEJS_VERSION\""
fi

# Install claude code
if ! test -e "/home/$AI_USER"/.nvm/versions/node/*/bin/claude ; then
  echo -e "\nI: Install claude"
  # this installs to ~/.nvm/versions/node/<nodever>/bin which is in the user's
  # PATH as part of nvm install
  su -l "$AI_USER" -c ". \"/home/$AI_USER/.nvm/nvm.sh\" && npm install -g @anthropic-ai/claude-code"
  # disable auto-updates (don't work in ephemeral container
  echo '{"autoUpdates": false}' > "/home/$AI_USER/.claude.json"
  chown "$AI_USER:$AI_USER" "/home/$AI_USER/.claude.json"
  chmod 600 "/home/$AI_USER/.claude.json"
  echo "I: run with 'claude' (https://www.claude.com/product/claude-code)"
fi

# Install copilot cli
if ! test -e "/home/$AI_USER"/.nvm/versions/node/*/bin/copilot ; then
  echo -e "\nI: Install copilot-cli"
  su -l "$AI_USER" -c ". \"/home/$AI_USER/.nvm/nvm.sh\" && npm install -g @github/copilot"
  echo "I: run with 'copilot' (https://github.com/github/copilot-cli)"
fi

# Install gemini-cli
if ! test -e "/home/$AI_USER"/.nvm/versions/node/*/bin/gemini ; then
  echo -e "\nI: Install gemini-cli"
  # this installs to ~/.nvm/versions/node/<nodever>/bin which is in the user's
  # PATH as part of nvm install
  su -l "$AI_USER" -c ". \"/home/$AI_USER/.nvm/nvm.sh\" && npm install -g @google/gemini-cli"
  echo "I: run with 'gemini' (https://github.com/google-gemini/gemini-cli)"
fi

# Install openai codex
if ! test -e "/home/$AI_USER"/.nvm/versions/node/*/bin/codex ; then
  echo -e "\nI: Install openai/codex"
  # this installs to ~/.nvm/versions/node/<nodever>/bin which is in the user's
  # PATH as part of nvm install
  su -l "$AI_USER" -c ". \"/home/$AI_USER/.nvm/nvm.sh\" && npm install -g @openai/codex"
  echo "I: run with 'codex' (https://github.com/openai/codex)"
fi

echo -e "\nI: Cleaning up /tmp"
rm -f /tmp/*

echo "Done!!"
