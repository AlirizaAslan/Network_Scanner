import argparse
import socket
from scapy.all import ARP, Ether, srp, conf, get_if_list, get_if_addr
import psutil


def get_active_interfaces():
    """
    Tüm aktif arayüzleri ve IP adreslerini döner.
    """
    interfaces = []
    for nic, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family.name == "AF_INET" and not addr.address.startswith("169.254"):
                interfaces.append((nic, addr.address))
    return interfaces


def get_default_interface():
    """
    Varsayılan aktif ağ arayüzünü döner.
    """
    active_interfaces = get_active_interfaces()
    if active_interfaces:
        return active_interfaces[0]  # İlk aktif arayüzü döner
    return None

# IP'ye karşılık gelen cihaz adı almak için DNS sorgusu
def get_device_name(ip):
    """Verilen IP adresine karşılık gelen cihaz adını döndürür."""
    try:
        hostname = socket.gethostbyaddr(ip)
        return hostname[0]
    except socket.herror:
        return None


def scan_network(interface, target_ip, timeout):
    """
    Ağdaki cihazları tarar.
    """
    print(f"[INFO] Scanning on interface: {interface} ({get_if_addr(interface)})")
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    answered, unanswered = srp(packet, timeout=timeout, iface=interface, verbose=False)

    print("\n[INFO] Found Devices:")
    for sent, received in answered:
        hostname = get_device_name(received.psrc)
        if hostname:
            print(f"- IP: {received.psrc}, MAC: {received.hwsrc}, Hostname: {hostname}")
        else:
            print(f"- IP: {received.psrc}, MAC: {received.hwsrc}, Hostname: Unknown")


def list_interfaces():
    """
    Aktif ağ arayüzlerini ve IP adreslerini listeler.
    """
    interfaces = get_active_interfaces()
    if not interfaces:
        print("[INFO] No active interfaces found.")
        return

    print("[INFO] Active Network Interfaces:")
    for idx, (nic, ip) in enumerate(interfaces, 1):
        print(f"{idx}. Interface: {nic}, IP Address: {ip}")


def main():
    parser = argparse.ArgumentParser(description="Network Scanner Tool")
    parser.add_argument("-i", "--interface", type=str, help="Network interface to use")
    parser.add_argument("-t", "--target", type=str, help="Target IP range (e.g., 192.168.1.0/24)")
    parser.add_argument("--timeout", type=int, default=3, help="Timeout for responses (default: 3s)")
    parser.add_argument("-l", "--list-interfaces", action="store_true", help="List all active network interfaces")
    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        return

    if not args.target:
        print("[ERROR] Target IP range is required. Use -t to specify the target.")
        return

    interface = args.interface
    if not interface:
        default_interface = get_default_interface()
        if default_interface:
            interface = default_interface[0]
            print(f"[INFO] No interface provided. Using default: {interface}")
        else:
            print("[ERROR] No active network interface found.")
            return

    scan_network(interface, args.target, args.timeout)


if __name__ == "__main__":
    main()
