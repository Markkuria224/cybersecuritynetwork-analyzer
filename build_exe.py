#!/usr/bin/env python3
"""
Build script for creating a standalone EXE of the Network Analyzer.
This creates a single-file executable that others can run without Python installed.

Usage:
    python build_exe.py

Requirements:
    pip install pyinstaller
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def main():
    print("🔨 Building Network Analyzer EXE...")
    
    # Check if PyInstaller is installed
    try:
        import PyInstaller
        print(f"✓ PyInstaller {PyInstaller.__version__} found")
    except ImportError:
        print("❌ PyInstaller not found. Installing...")
        subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"], check=True)
        print("✓ PyInstaller installed")
    
    # Clean previous builds
    build_dirs = ["build", "dist"]
    for dir_name in build_dirs:
        if os.path.exists(dir_name):
            print(f"🧹 Cleaning {dir_name}/")
            shutil.rmtree(dir_name)
    
    # Build the EXE
    print("🚀 Building EXE with PyInstaller...")
    
    cmd = [
        "pyinstaller",
        "--onefile",                    # Single EXE file
        "--windowed",                   # No console window
        "--name=NetworkAnalyzer",       # EXE name
        "--icon=icon.ico",             # Icon (if exists)
        "--add-data=config.json;.",    # Include config file
        "--hidden-import=scapy",       # Ensure Scapy is included
        "--hidden-import=matplotlib",  # Ensure Matplotlib is included
        "--hidden-import=tkinter",     # Ensure Tkinter is included
        "--clean",                      # Clean cache
        "network_analyzer.py"
    ]
    
    # Remove icon flag if icon doesn't exist
    if not os.path.exists("icon.ico"):
        cmd.remove("--icon=icon.ico")
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print("✓ Build completed successfully!")
        
        # Check if EXE was created
        exe_path = Path("dist/NetworkAnalyzer.exe")
        if exe_path.exists():
            size_mb = exe_path.stat().st_size / (1024 * 1024)
            print(f"📁 EXE created: {exe_path}")
            print(f"📏 Size: {size_mb:.1f} MB")
            print(f"📍 Location: {exe_path.absolute()}")
            
            # Create a simple README for the EXE
            readme_path = Path("dist/README.txt")
            readme_content = """Network Analyzer - Standalone EXE

This is a standalone executable that doesn't require Python installation.

REQUIREMENTS:
- Windows 10/11
- Npcap (install with "WinPcap API-compatible mode" enabled)
  Download from: https://nmap.org/npcap/

USAGE:
1. Double-click NetworkAnalyzer.exe
2. Select your network interface
3. Click "Start" to begin packet capture
4. If no packets appear, run as Administrator

FEATURES:
- Real-time network packet capture
- Protocol filtering (TCP/UDP/ICMP/ARP)
- Search and filter capabilities
- Security threat detection
- Live packet rate visualization
- Export to CSV/TXT/PCAP formats

SECURITY:
- For educational and authorized network analysis only
- Use responsibly and in accordance with applicable laws
- May require Administrator privileges for packet capture

TROUBLESHOOTING:
- If capture shows no packets: Run as Administrator
- Ensure Npcap is installed with WinPcap compatibility
- Allow through Windows Firewall if prompted
"""
            readme_path.write_text(readme_content, encoding='utf-8')
            print(f"📝 Created README.txt in dist/ folder")
            
        else:
            print("❌ EXE not found in dist/ folder")
            print("Build output:")
            print(result.stdout)
            if result.stderr:
                print("Errors:")
                print(result.stderr)
                
    except subprocess.CalledProcessError as e:
        print(f"❌ Build failed with exit code {e.returncode}")
        print("Build output:")
        print(e.stdout)
        if e.stderr:
            print("Errors:")
            print(e.stderr)
        return 1
    
    print("\n🎉 Build complete! Share the EXE and README.txt with others.")
    print("They only need to install Npcap to run it.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
