import socket
import struct
import csv
import time
import threading

# Global flag to control sniffing
sniffing = False
lock = threading.Lock()

def sniff_packets():
    global sniffing
    sniffing = True
    try:
        # Create a raw socket
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

        while sniffing:
            # Capture a packet
            raw_packet, addr = s.recvfrom(65535)

            # Unpack Ethernet header (14 bytes)
            eth_length = 14
            eth_header = raw_packet[:eth_length]
            eth = struct.unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])

            # Parse IP packets, IP Protocol number = 8
            if eth_protocol == 8:
                # Parse IP header
                ip_header = raw_packet[eth_length:20+eth_length]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                version_ihl = iph[0]
                version = version_ihl >> 4
                ihl = version_ihl & 0xF
                iph_length = ihl * 4
                ttl = iph[5]
                protocol = iph[6]
                s_addr = socket.inet_ntoa(iph[8])
                d_addr = socket.inet_ntoa(iph[9])

                # Parse TCP packets, TCP protocol number = 6
                if protocol == 6:
                    t = iph_length + eth_length
                    tcp_header = raw_packet[t:t+20]
                    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                    source_port = tcph[0]
                    dest_port = tcph[1]
                    payload = raw_packet[t+20:].decode('utf-8', errors='ignore')
                    proto = 'TCP'

                # Parse UDP Packets, UDP protocol number = 17
                elif protocol == 17:
                    u = iph_length + eth_length
                    udph_length = 8
                    udp_header = raw_packet[u:u+udph_length]
                    udph = struct.unpack('!HHHH', udp_header)
                    source_port = udph[0]
                    dest_port = udph[1]
                    payload = raw_packet[u+udph_length:].decode('utf-8', errors='ignore')
                    proto = 'UDP'
                else:
                    source_port = ''
                    dest_port = ''
                    payload = ''
                    proto = 'Other'

                # Write packet data to CSV
                with lock:
                    with open('packets.csv', 'a', newline='') as csvfile:
                        packet_writer = csv.writer(csvfile)
                        packet_writer.writerow([time.time(), s_addr, d_addr, proto, payload])

            time.sleep(0.001)  # Small delay to reduce CPU usage

    except socket.error as msg:
        print('Socket error: ' + str(msg))
    except Exception as e:
        print('Error in sniff_packets: ' + str(e))
    finally:
        s.close()

def stop_sniffing():
    global sniffing
    sniffing = False
