#!/bin/bash

# Script to install mypy (Python static type checker)
# Handles apt lock situations automatically

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if apt is locked
check_apt_lock() {
    if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
        return 0  # Lock exists
    else
        return 1  # No lock
    fi
}

# Function to wait for apt lock to be released
wait_for_apt_lock() {
    local max_wait=300  # Maximum wait time in seconds (5 minutes)
    local wait_time=0
    local check_interval=5

    print_status "Checking for apt lock..."
    
    while check_apt_lock; do
        if [ $wait_time -ge $max_wait ]; then
            print_error "Timeout waiting for apt lock to be released after $max_wait seconds."
            print_status "You can manually check running processes with: ps aux | grep -E 'apt|dpkg'"
            print_status "Or force remove locks (risky): sudo rm /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock"
            exit 1
        fi
        
        print_warning "apt is locked by another process. Waiting... ($wait_time/$max_wait seconds)"
        sleep $check_interval
        wait_time=$((wait_time + check_interval))
    done
    
    print_success "apt lock is available!"
}

# Function to kill hanging apt processes (with user confirmation)
kill_apt_processes() {
    # Get PIDs as an array, filter to only numbers
    local apt_pids=($(pgrep -f "apt|dpkg" 2>/dev/null | grep -E '^[0-9]+$' || true))
    
    if [ ${#apt_pids[@]} -gt 0 ]; then
        print_warning "Found running apt/dpkg processes:"
        # Convert array to comma-separated string for ps command
        local pid_list=$(IFS=','; echo "${apt_pids[*]}")
        ps -p "$pid_list" -o pid,cmd --no-headers 2>/dev/null || true
        
        read -p "Do you want to kill these processes? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_status "Killing apt/dpkg processes..."
            # Kill each PID individually to avoid command line issues
            for pid in "${apt_pids[@]}"; do
                sudo kill -9 "$pid" 2>/dev/null || true
            done
            sleep 2
            
            # Clean up any remaining locks
            print_status "Cleaning up lock files..."
            sudo rm -f /var/lib/dpkg/lock-frontend
            sudo rm -f /var/lib/dpkg/lock
            sudo dpkg --configure -a
            
            print_success "Processes killed and locks cleaned up."
        else
            print_status "Exiting. Please wait for the processes to finish naturally."
            exit 1
        fi
    else
        print_status "No running apt/dpkg processes found."
    fi
}

# Main installation function
install_mypy() {
    print_status "Starting mypy installation..."
    
    # Wait for apt lock or offer to kill processes
    if check_apt_lock; then
        print_warning "apt is currently locked by another process."
        
        # Show what processes are using apt
        print_status "Processes using apt/dpkg:"
        ps aux | grep -E 'apt|dpkg' | grep -v grep || echo "No visible apt/dpkg processes"
        
        echo
        echo "Options:"
        echo "1) Wait for the process to finish (recommended)"
        echo "2) Kill the processes and continue (risky)"
        echo "3) Exit and try again later"
        
        read -p "Choose an option (1/2/3): " -n 1 -r
        echo
        
        case $REPLY in
            1)
                wait_for_apt_lock
                ;;
            2)
                kill_apt_processes
                ;;
            3)
                print_status "Exiting. Try running the script again later."
                exit 0
                ;;
            *)
                print_error "Invalid option. Exiting."
                exit 1
                ;;
        esac
    fi
    
    print_status "Updating package list..."
    sudo apt-get update
    
    print_status "Installing mypy via system package manager..."
    sudo apt-get install -y python3-mypy
    
    # If system package not available, try alternative methods
    if ! command -v mypy >/dev/null 2>&1; then
        print_status "System package not found, trying pipx..."
        
        # Install pipx if not available
        if ! command -v pipx >/dev/null 2>&1; then
            print_status "Installing pipx..."
            sudo apt-get install -y pipx
        fi
        
        print_status "Installing mypy via pipx..."
        pipx install mypy
        
        # If pipx fails, try pip with --break-system-packages as last resort
        if ! command -v mypy >/dev/null 2>&1; then
            print_warning "pipx installation failed, trying pip with --break-system-packages (not recommended)..."
            read -p "Do you want to proceed with --break-system-packages? (y/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                print_status "Installing pip for Python 3 (if not already installed)..."
                sudo apt-get install -y python3-pip
                
                print_status "Installing mypy with --break-system-packages..."
                pip3 install --user --upgrade mypy --break-system-packages
            else
                print_error "Installation cancelled. Consider using a virtual environment."
                exit 1
            fi
        fi
    fi
    
    print_success "mypy installation complete!"
    
    # Check if mypy is in PATH
    if command -v mypy >/dev/null 2>&1; then
        print_success "mypy is available in PATH"
        mypy --version
    else
        print_warning "mypy is installed but not in PATH"
        print_status "Possible solutions:"
        print_status "1. For pip --user installations: export PATH=\$PATH:~/.local/bin"
        print_status "2. For pipx installations: pipx ensurepath (then restart shell)"
        print_status "3. Add the appropriate path to your ~/.bashrc for permanent access"
        
        # Try to find mypy location
        if [ -f ~/.local/bin/mypy ]; then
            print_status "Found mypy at ~/.local/bin/mypy"
        elif [ -f ~/.local/share/pipx/venvs/mypy/bin/mypy ]; then
            print_status "Found mypy installed via pipx"
        fi
    fi
}

# Run the installation
install_mypy