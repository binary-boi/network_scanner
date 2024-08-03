# network_scanner
## Network Scanner Script

This repository contains a Python script for scanning a network and gathering information about discovered hosts. 

### Features:

* **Host Discovery:** Identifies active hosts within a specified IP range using Nmap's ping sweep functionality.
* **Whois Lookup:** Retrieves information about the registrant of a domain name associated with the discovered host.
* **Subdomain Discovery (Basic):** Attempts to discover subdomains for the identified host using the `sublist3r` tool.
* **Port Scanning:** Scans open ports on discovered hosts using Nmap's TCP SYN scan.
* **Banner Grabbing (Basic):** Attempts to retrieve the service banner information from open ports.
* **DNS Analysis:** Performs a basic DNS lookup for the discovered host, retrieving A records, NS records, and MX records.
* **HTTP Header Analysis:** Retrieves HTTP headers for the discovered host (requires internet access).
* **Screenshot Capturing (Optional):** Captures screenshots of discovered hosts (requires a web browser and Selenium).

**Note:** This script is for educational purposes only. Please obtain permission before scanning any network that you do not own or control. 

### Usage:

1. Install required libraries:
    * `nmap`
    * `ipaddress`
    * `socket`
    * `whois`
    * `subprocess`
    * `dns.resolver`
    * `requests`
    * `selenium`
    * `webdriver_manager` (for Chrome driver)
2. Clone or download this repository.
3. Run the script from the command line:

    ```bash
    python network_scanner.py
    ```

4. Enter the IP range you want to scan in the format `start_IP-end_IP` (e.g., `192.168.1.1-192.168.1.254`).
    
**Optional:**
    
* Install a web browser (e.g., Chrome) for screenshot capturing functionality.

The script will display information about discovered hosts and potential vulnerabilities.


### Disclaimer

This script is provided for educational purposes only. The authors are not responsible for any misuse of this script. 
