#!/bin/bash

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() { printf "${BLUE}[INFO]${NC} %s\n" "$1" >&2; }
print_success() { printf "${GREEN}[SUCCESS]${NC} %s\n" "$1" >&2; }
print_warning() { printf "${YELLOW}[WARNING]${NC} %s\n" "$1" >&2; }
print_error() { printf "${RED}[ERROR]${NC} %s\n" "$1" >&2; }

# Detect platform and architecture
detect_platform() {
    local os arch uname_s uname_m
    
    uname_s="$(uname -s)"
    uname_m="$(uname -m)"
    
    print_info "System info: OS='${uname_s}', Arch='${uname_m}'"
    
    case "${uname_s}" in
        Linux*)
            os="linux"
            ;;
        Darwin*)
            os="macos"
            ;;
        *)
            print_error "Unsupported operating system: ${uname_s}"
            print_info "Please download manually from: https://github.com/chriswessels/bashtion/releases/latest"
            exit 1
            ;;
    esac
    
    case "${uname_m}" in
        x86_64|amd64)
            arch="x86_64"
            ;;
        aarch64|arm64)
            arch="aarch64"
            ;;
        *)
            print_error "Unsupported architecture: ${uname_m}"
            print_info "Please download manually from: https://github.com/chriswessels/bashtion/releases/latest"
            exit 1
            ;;
    esac
    
    print_info "Mapped to: OS='${os}', Arch='${arch}'"
    echo "${os}-${arch}"
}

# Main installation function
install_bashtion() {
    local platform target_file download_url temp_dir
    
    platform=$(detect_platform)
    target_file="bashtion-${platform}.tar.gz"
    local repo="${BASHTION_INSTALL_REPO:-chriswessels/bashtion}"
    download_url="https://github.com/${repo}/releases/latest/download/${target_file}"
    temp_dir=$(mktemp -d)
    
    print_info "Final platform string: '${platform}'"
    print_info "Target file: '${target_file}'"
    print_info "Download URL: '${download_url}'"
    print_info "Temp directory: '${temp_dir}'"
    
    # Download archive
    if ! curl -fsSL -o "${temp_dir}/${target_file}" "${download_url}"; then
        print_error "Failed to download bashtion release artifact"
        print_info "Set BASHTION_INSTALL_REPO=owner/name if using a fork"
        exit 1
    fi
    # Extract
    if ! tar -xzf "${temp_dir}/${target_file}" -C "${temp_dir}"; then
        print_error "Failed to extract bashtion archive"
        exit 1
    fi
    
    # Check if binary exists
    if [[ ! -f "${temp_dir}/bashtion" ]]; then
        print_error "Downloaded archive does not contain bashtion binary"
        exit 1
    fi
    
    # Make binary executable
    chmod +x "${temp_dir}/bashtion"
    
    # Install to system
    local install_dir="${BASHTION_INSTALL_DIR:-/usr/local/bin}"
    
    if [[ -w "${install_dir}" ]]; then
        mv "${temp_dir}/bashtion" "${install_dir}/bashtion"
        print_success "Installed bashtion to ${install_dir}/bashtion"
    else
        print_info "Installing to ${install_dir} (requires sudo)"
        sudo mv "${temp_dir}/bashtion" "${install_dir}/bashtion"
        print_success "Installed bashtion to ${install_dir}/bashtion"
    fi
    
    # Cleanup
    rm -rf "${temp_dir}"
    
    # Verify installation
    if command -v bashtion > /dev/null 2>&1; then
        print_success "Installation completed successfully!"
        print_info "Version: $(bashtion --version || echo 'unknown')"
        print_info "Pipe installers through 'bashtion' to review them before execution"
    else
        print_warning "Installation completed, but 'bashtion' is not in PATH"
        print_info "You may need to restart your shell or add ${install_dir} to your PATH"
    fi
}

# Show banner
printf "${BLUE}"
cat << 'EOF'
  _   _                   _   _                 
 | \ | | ___  _ __ ___   | \ | | ___  _ __ ___  
 |  \| |/ _ \| '_ ` _ \  |  \| |/ _ \| '_ ` _ \ 
 | |\  | (_) | | | | | | | |\  | (_) | | | | | |
 |_| \_|\___/|_| |_| |_| |_| \_|\___/|_| |_| |_|
                                               
EOF
printf "${NC}"
print_info "Bashtion installer - interactive shell script guardian"
echo

# Check dependencies
if ! command -v curl > /dev/null 2>&1; then
    print_error "curl is required but not installed"
    exit 1
fi

if ! command -v tar > /dev/null 2>&1; then
    print_error "tar is required but not installed"
    exit 1
fi

# Run installation
install_bashtion
