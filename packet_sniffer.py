from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime
import os


# --------------------------------------------------
#   Network Packet Analyzer
#   This tool captures live network packets and
#   shows useful information like source and
#   destination IP addresses, protocol type,
#   port numbers, and payload data.
#
#   DISCLAIMER: Only use on networks you own
#   or have explicit permission to monitor.
#   Unauthorized packet sniffing is illegal.
# --------------------------------------------------


LOG_FILE = "packet_log.txt"
packet_count = 0


def write_to_log(content):
    # Save the packet details to our log file
    with open(LOG_FILE, "a") as f:
        f.write(content + "\n")


def guess_service(port):
    # Most common network services and their port numbers
    # This helps us understand what kind of traffic we see
    services = {
        80:   "HTTP - regular web browsing",
        443:  "HTTPS - secure web browsing",
        21:   "FTP - file transfer",
        22:   "SSH - secure remote access",
        23:   "Telnet - remote access",
        25:   "SMTP - sending emails",
        53:   "DNS - domain name lookup",
        110:  "POP3 - receiving emails",
        143:  "IMAP - email access",
        3306: "MySQL - database",
        3389: "RDP - remote desktop",
        8080: "HTTP alternate port",
    }
    return services.get(port, None)


def analyze_packet(packet):
    # This function runs automatically every time
    # a new packet is captured from the network
    global packet_count
    packet_count += 1

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n" + "=" * 60)
    print(f"   Packet number  : {packet_count}")
    print(f"   Captured at    : {timestamp}")
    print("=" * 60)

    if IP in packet:
        # Get source and destination IP addresses
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        print(f"   Source IP      : {src_ip}")
        print(f"   Destination IP : {dst_ip}")

        # Figure out which protocol this packet uses
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"   Protocol       : TCP (Transmission Control Protocol)")
            print(f"   Source port    : {src_port}")
            print(f"   Dest port      : {dst_port}")

            # Tell the user what service this port belongs to
            service = guess_service(dst_port)
            if service:
                print(f"   Likely service : {service}")

        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"   Protocol       : UDP (User Datagram Protocol)")
            print(f"   Source port    : {src_port}")
            print(f"   Dest port      : {dst_port}")

        elif ICMP in packet:
            print(f"   Protocol       : ICMP (used for ping and diagnostics)")
            print(f"   ICMP type      : {packet[ICMP].type}")

        else:
            print(f"   Protocol       : Other (number {packet[IP].proto})")

        # Show a preview of the data inside the packet
        if Raw in packet:
            raw_data = packet[Raw].load
            try:
                decoded = raw_data.decode('utf-8', errors='ignore')
                if decoded.strip():
                    preview = decoded.strip()[:100]
                    print(f"   Data preview   : {preview}")
            except Exception:
                print(f"   Data preview   : Binary data (not readable as text)")

        # Save this packet info to the log file
        log_entry = (
            f"[{timestamp}] Packet {packet_count} | "
            f"{src_ip} -> {dst_ip} | "
            f"Protocol: {packet[IP].proto}"
        )
        write_to_log(log_entry)

    else:
        print("   Type           : Non-IP packet (ARP or Ethernet level)")

    print("=" * 60)


def start_sniffing(packet_limit, interface=None):
    print("\nStarting packet capture...")
    print(f"Will capture {packet_limit} packets total.")
    print("Press Ctrl+C at any time to stop early.\n")

    try:
        if interface:
            sniff(
                iface=interface,
                prn=analyze_packet,
                count=packet_limit,
                store=False
            )
        else:
            sniff(
                prn=analyze_packet,
                count=packet_limit,
                store=False
            )

    except PermissionError:
        print("\nPermission denied!")
        print("Please run this program as Administrator.")
        print("Right-click Command Prompt and choose Run as Administrator.")

    except Exception as e:
        print(f"\nSomething went wrong: {e}")


def main():
    print("=" * 60)
    print("         NETWORK PACKET ANALYZER")
    print("   Capture and Analyze Live Network Traffic")
    print("=" * 60)
    print("\nDISCLAIMER: For educational purposes only.")
    print("Only use on networks you own or have permission")
    print("to monitor. Unauthorized sniffing is illegal.")

    while True:
        print("\n" + "-" * 60)
        print("What would you like to do?")
        print("  1. Start capturing packets")
        print("  2. View the packet log file")
        print("  3. Clear the log file")
        print("  4. Exit")
        print("-" * 60)

        choice = input("Your choice (1/2/3/4): ").strip()

        if choice == '4':
            print("\nThank you for using Network Packet Analyzer.")
            print("Stay ethical and legal. Goodbye!")
            break

        elif choice == '1':
            print("\nHow many packets do you want to capture?")
            print("Tip: Start with 10 or 20 to test it out.")

            while True:
                try:
                    limit = int(input("Number of packets: "))
                    if limit > 0:
                        break
                    else:
                        print("Please enter a number greater than 0.")
                except ValueError:
                    print("That is not a valid number. Please try again.")

            print("\nEnter your network interface name.")
            print("Examples: Wi-Fi, Ethernet, eth0, wlan0")
            print("Just press Enter to use the default interface.")
            interface = input("Interface: ").strip()

            if interface == "":
                interface = None

            start_sniffing(limit, interface)

            print(f"\nDone! Captured {packet_count} packets in total.")
            print(f"Log file saved at: {os.path.abspath(LOG_FILE)}")

        elif choice == '2':
            if os.path.exists(LOG_FILE):
                print(f"\nContents of {LOG_FILE}:")
                print("-" * 60)
                with open(LOG_FILE, "r") as f:
                    content = f.read()
                    print(content if content else "The log file is empty.")
            else:
                print("\nNo log file found yet. Capture some packets first.")

        elif choice == '3':
            if os.path.exists(LOG_FILE):
                os.remove(LOG_FILE)
                print("\nLog file cleared successfully.")
            else:
                print("\nNo log file to clear.")

        else:
            print("\nThat is not a valid choice. Please enter 1, 2, 3, or 4.")


if __name__ == "__main__":
    main()