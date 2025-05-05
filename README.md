
# CyberRecon (Test Build)

**CyberRecon** is a lightweight network vulnerability scanner built with Python and `nmap`, featuring a simple GUI using Tkinter.  
This is a **test version** with major improvements in performance, flexibility, and user experience.

## New in This Version:
- **Improved scanning speed** by limiting port range (default: 1-1024) and using `-T4` timing.
- **Custom port range input**: users can define specific ports (e.g., `80-443`).
- **Threaded scanning**: prevents app freezing during long scans.
- **New tabbed interface** using `ttk.Notebook`:
  - **Vulnerability Scanner**
  - **Data Leak Checker** *(integrating with Have I Been Pwned)* â€“ *in progress*.
- **Scan status updates**: shows "Scanning..." and "Scan Complete" messages.

## Features:
- Detect open ports, service states, and server types.
- Export detailed scan reports in `.txt` format.
- User-friendly GUI with clean layout and color styling.

## Usage:
1. Install dependencies:  
   ```bash
   pip install python-nmap
   ```
2. Clone the repo and run:
   ```bash
   git clone https://github.com/OmarHany-sudo/CyberRecon.git
   cd CyberRecon
   python3 CyberRecon.py
   ```
3. Enter a target (IP or domain), optionally set a port range, then click **Start Scan**.

## Developer:
- **Facebook**: [Omar Hany](https://facebook.com/Omar.Hany.850)  
- **Instagram**: [Omar Hany](https://instagram.com/omar.hany.850/)