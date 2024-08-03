from tqdm import tqdm
import nmap
import ipaddress
import socket
import whois
import subprocess
import dns.resolver
import requests
from selenium import webdriver
from webdriver_manager.chrome import ChromeDriverManager

def scan_network(ip_range):
    try:
        ipaddress.ip_network(ip_range)

        # Host discovery
        scanner = nmap.PortScanner()

        # Use tqdm to show progress bar for hosts
        for host in tqdm(scanner.scan(hosts=ip_range, arguments='-sP')['scan'].keys()):
            if scanner[host].state() == 'up':
                print(f"{host} is up")

                # Whois lookup
                try:
                    w = whois.whois(socket.gethostbyname(host))
                    print(f"Whois information for {host}:")
                    print(w)
                except Exception as e:
                    print(f"Error getting Whois information for {host}: {e}")

                # Subdomain discovery (basic)
                try:
                    subdomains = subprocess.check_output(["sublist3r", "-d", host]).decode('utf-8').splitlines()
                    print(f"Subdomains for {host}:")
                    for subdomain in subdomains:
                        print(subdomain)
                except Exception as e:
                    print(f"Error getting subdomains for {host}: {e}")

                # Port scanning
                scanner.scan(host, arguments='-sT -p1-1024')  # Adjust port range as needed
                for proto in scanner[host].all_protocols():
                    print(f"Open ports on {host} ({proto}): ")
                    for port in scanner[host][proto].keys():
                        print(f"\t{port}/{proto}: {scanner[host][proto][port]['state']}")

                # Banner grabbing (basic)
                for proto in scanner[host].all_protocols():
                    for port in scanner[host][proto].keys():
                        if scanner[host][proto][port]['state'] == 'open':
                            try:
                                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                sock.connect((host, port))
                                banner = sock.recv(1024).decode('utf-8').strip()
                                print(f"\tBanner for {host}:{port}: {banner}")
                                sock.close()
                            except Exception as e:
                                print(f"\tError getting banner for {host}:{port}: {e}")

                # DNS analysis
                analyze_dns(socket.gethostbyname(host))

                # HTTP header analysis
                try:
                    analyze_http_headers(f"http://{host}")
                except Exception as e:
                    pass  # Handle errors gracefully

                # Screenshot capturing
                try:
                    driver = webdriver.Chrome(ChromeDriverManager().install())
                    driver.get(f"http://{host}")
                    driver.save_screenshot(f"screenshot_{host}.png")
                    driver.quit()
                except Exception as e:
                    print(f"Error capturing screenshot for {host}: {e}")

    except ValueError:
        print("Invalid IP range format. Please enter a valid IP range (e.g., 192.168.1.1-192.168.1.254)")


def analyze_dns(domain):
    try:
        answers = dns.resolver.query(domain, 'A')
        for rdata in answers:
            print(f"A record: {rdata.address}")

        answers = dns.resolver.query(domain, 'NS')
        for rdata in answers:
            print(f"NS record: {rdata.to_text()}")

        answers = dns.resolver.query(domain, 'MX')
        for rdata in answers:
            print(f"MX record: {rdata.preference} {rdata.exchange}")
    except Exception as e:
        print(f"Error analyzing DNS records for {domain}: {e}")


def analyze_http_headers(url):
    try:
        response = requests.get(url)
        print(f"HTTP headers for {url}:")
        print(response.headers)
    except Exception as e:
        print(f"Error analyzing HTTP headers for {url}: {e}")

if __name__ == "__main__":
    ip_range = input("Enter the IP range to scan (e.g., 192.168.1.1-192.168.1.254): \n ")
    scan_network(ip_range)
