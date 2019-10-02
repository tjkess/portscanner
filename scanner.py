import argparse
from scapy.all import *


def print_info(port, state):
    print("%s | %s" % (port, state))


def tcp(t, p):
    print("starting tcp scan on target %s on ports %s" %(t, p))
    source = RandShort()
    info = ""
    for target in t:
        for port in p:
            packet = sr1(IP(dst=target)/TCP(sport=source, dport=port, flags="FPU"), timeout=1)
            if packet != None:
                if packet.haslayer(TCP):
                    if packet[TCP].flags == 20:
                        print_info(port, "Closed")
                    else:
                        print_info(port, "tcp flags %s " % packet[TCP].flag)
                elif packet.haslayer(ICMP):
                    print_info(port, "icmp filtered")
                else:
                    print_info(port, "idk")
                info += packet.summary() + '\n'
    return info


def udp(t, p):
    print("start udp scan on ports %s" % p)
    info = ""
    for target in t:
        for port in p:
            packet = sr1(IP(dst=target)/UDP(sport=port, dport=port), timeout=2)
            if packet == None:
                print_info(port, "open or filtered")
            else:
                if packet.haslayer(ICMP):
                    print_info(port, "closed")
                elif packet.haslayer(UDP):
                    print_info(port, "open or filtered")
                else:
                    print_info(port, "idk")
                info += packet.summary()
    return info


parser = argparse.ArgumentParser("Welcome to the port scanner")
parser.add_argument("-t", "--target", help="specify the ip address of your target", required=True, nargs="+")
parser.add_argument("-p", "--ports", help="specify the ports to be scanned", nargs="+", type=int)
parser.add_argument("-f", "--file", help="include a txt file with targets separated by commas")
parser.add_argument("-s", "--scan", help="specify the type of scan eg(tcp, udp, icmp)", required=True)

inputs = parser.parse_args()

if inputs.file:
    target = []
    f = open(inputs.file, "r")
    file_content = f.read()
    ip = ""
    for letter in file_content:
        if letter == ',':
            target.append(ip)
            ip = ""
            continue
        ip += letter
else:
    target = inputs.target
if inputs.ports:
    ports = inputs.ports
else:
    ports = range(1, 1024)
scan = inputs.scan.lower()
if scan == 'udp':
    udp(target, ports)
elif scan == 'tcp':
    print (tcp(target, ports))


