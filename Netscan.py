import subprocess

def get_target_ip():
    """Prompt user for target IPv4 address."""
    return input("Enter target IPv4 address: ")

def get_ports():
    """Prompt user for port numbers, allowing range selection."""
    ports = input("Enter ports (comma-separated or range 0-65535, or type 'all'): ")
    return "0-65535" if ports == "all" else ports

def choose_scan():
    """Display available scan types and prompt user to choose one."""
    scan_options = {
        "1": ("TCP Connect Scan", ["-sT"]),
        "2": ("Stealth SYN Scan", ["-sS"]),
        "3": ("UDP Scan", ["-sU"]),
        "4": ("NULL Scan", ["-sN"]),
        "5": ("FIN Scan", ["-sF"]),
        "6": ("XMAS Scan", ["-sX"]),
        "7": ("OS Fingerprinting", ["-O"]),
        "8": ("Version Detection Scan", ["-sV"]),
        "9": ("Ping Scan", ["-sn"]),
        "10": ("Check if System is Up", ["-Pn"]),
        "11": ("Firewall Bypass Scan", ["-f"]),
        "12": ("IDS/IPS Evasion Scan", ["--mtu", "16", "-D", "RND:10", "--data-length", "100"]),
        "13": ("Host Discovery", ["-sn", "-PE", "-PP", "-PM"])
    }
    
    for key, (name, _) in scan_options.items():
        print(f"{key}. {name}")
    
    choice = input("Enter the number of the scan type: ")
    return scan_options.get(choice, (None, None))

def run_scan(scan_type, target, extra_args):
    """Execute the selected Nmap scan and display results."""
    if not scan_type:
        print("Invalid selection. Please choose a valid scan type.")
        return
    
    try:
        print(f"\n[+] Running {scan_type} on {target}...")
        result = subprocess.run(["nmap", "-4"] + extra_args + [target], capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"Error performing {scan_type}: {e}")

def main():
    target = get_target_ip()
    scan_type, args = choose_scan()
    
    if scan_type == "TCP Connect Scan":
        ports = get_ports()
        args += ["-p", ports]
    
    run_scan(scan_type, target, args)

if __name__ == "__main__":
    main()

