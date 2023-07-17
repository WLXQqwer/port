# -*- coding: UTF-8 -*-
import argparse
from scapy.all import *


# 打印端⼝状态
def print_ports(port, state):
    print("%s | %s" % (port, state))


def tcpScan(target, ports):
    pass


def synScan(target, ports):
    pass

    def ackScan(target, ports):
        pass

    def windowScan(target, ports):
        pass

    def nullScan(target, ports):
        pass

    def finScan(target, ports):
        pass

    def xmaxScan(target, ports):
        pass

    def udpScan(target, ports):
        pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser("")
    parser.add_argument("-t", "--target", help="目标ip", required=True)
    parser.add_argument("-p", "--ports", type=str, help=1-254)
    parser.add_argument("-s", "--scantype", help="""
     "T":全连接扫描
     "S":syn扫描
     "A":ack扫描
     "W":TCPwindow扫描
     "N":NULL扫描
     "F":FIN扫描
     "X":Xmas扫描
     "U":UDP扫描
     """, required=True)
    args = parser.parse_args()
    target = args.target
    scantype = args.scantype
    if args.ports:
        start, end = map(int, args.ports.split('-'))
        ports = range(start, end + 1)
    else:
        ports = range(1, 65535)
    # 扫码⽅式
    if scantype == "T":  # 全连接扫描
        pass
    elif scantype == "S":  # syn扫描
        pass
    elif scantype == "A":  # ack扫描
        pass
    elif scantype == "W":  # TCPwindow扫描
        pass
    elif scantype == "N":  # NULL扫描
        pass
    elif scantype == "F":  # FIN扫描
        pass
    elif scantype == "X":  # Xmas扫描
        pass
    elif scantype == "U":  # UDP扫描
        pass
    else:
        print("不⽀持当前模式")


def tcpScan(target, ports):
    print("tcp全连接扫描 %s with ports %s" % (target, ports))
    for port in ports:
        send = sr1(IP(dst=target) / TCP(dport=port, flags="S"), timeout=2, verbose=0)
        if (send is None):
            print_ports(port, "closed")
        elif send.haslayer("TCP"):

            if send["TCP"].flags == "SA":
                send_1 = sr1(IP(dst=target) / TCP(dport=port, flags="AR"), timeout=2, verbose=0)
                print_ports(port, "open")
            elif send["TCP"].flags == "RA":
                print_ports(port, "close")


def synScan(target, ports):
    print("tcp全连接扫描 %s with ports %s" % (target, ports))
    for port in ports:
        send = sr1(IP(dst=target) / TCP(dport=port, flags="S"), timeout=2, verbose=0)
        if (send is None):
            print_ports(port, "closed")
        elif send.haslayer("TCP"):
            print(send["TCP"].flags)
            if send["TCP"].flags == "SA":
                send_1 = sr1(IP(dst=target) / TCP(dport=port, flags="R"), timeout=2,
                             verbose=0)  # 只修改这⾥
                print_ports(port, "opend")
            elif send["TCP"].flags == "RA":
                print_ports(port, "closed")


def ackScan(target, ports):
    print("tcp ack扫描 %s with ports %s" % (target, ports))


for port in ports:
    send = sr1(IP(dst=target) / TCP(dport=port, flags="A"), timeout=5)
    print(str(type(send)))
    if (str(type(send)) == "<class 'NoneType'>"):
        print_ports(port, "filtered")
    elif (send.haslayer(TCP)):
        if (send.getlayer(TCP).flags == "R"):
            print_ports(port, "unfiltered")
        elif (send.haslayer(ICMP)):
            if (int(send.getlayer(ICMP).type) == 3 and int(send.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                print_ports(port, "filtered")
            else:
                print_ports(port, "filtered")


def windowScan(target, ports):
    print("tcp window扫描 %s with ports %s" % (target, ports))
    for port in ports:
        window_scan_resp = sr1(IP(dst=target) / TCP(dport=port, flags="A"), timeout=5)
        print(str(type(window_scan_resp)))
    if (str(type(window_scan_resp)) == "<class 'NoneType'>"):
        print_ports(port, "close")
    elif (window_scan_resp.haslayer(TCP)):
        if (window_scan_resp.getlayer(TCP).window == 0):
            print_ports(port, "close")
        elif (window_scan_resp.getlayer(TCP).window > 0):
            print_ports(port, "open")
    else:
        print_ports(port, "close")


def nullScan(target, ports):
    print("tcp NULL 扫描 %s with ports %s" % (target, ports))
    for port in ports:
        null_scan_resp = sr1(IP(dst=target) / TCP(dport=port, flags=""), timeout=5)
        if (str(type(null_scan_resp)) == "<class 'NoneType'>"):
            print_ports(port, "Open|Filtered")
        elif (null_scan_resp.haslayer(TCP)):
            if (null_scan_resp.getlayer(TCP).flags == "R" or
                    null_scan_resp.getlayer(TCP).flags == "A"):
                print_ports(port, "Closed")
        elif (null_scan_resp.haslayer(ICMP)):
            if (int(null_scan_resp.getlayer(ICMP).type) == 3 and
                    int(null_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                print_ports(port, "Filtered")


def finScan(target, ports):
    print("tcp FIN 扫描 %s with ports %s" % (target, ports))
    for port in ports:
        fin_scan_resp = sr1(IP(dst=target) / TCP(dport=port, flags="F"), timeout=5)
        if (str(type(fin_scan_resp)) == "<class 'NoneType'>"):
            print_ports(port, "Open|Filtered")
        elif (fin_scan_resp.haslayer(TCP)):
            if (fin_scan_resp.getlayer(TCP).flags == 0x14):
                print_ports(port, "Closed")
        elif (fin_scan_resp.haslayer(ICMP)):
            if (int(fin_scan_resp.getlayer(ICMP).type) == 3 and
                    int(fin_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                print_ports(port, "Filtered")


def xmaxScan(target, ports):
    print("tcp xmax 扫描 %s with ports %s" % (target, ports))
    for port in ports:
        fin_scan_resp = sr1(IP(dst=target) / TCP(dport=port, flags="FPU"), timeout=5)
        if (str(type(fin_scan_resp)) == "<class 'NoneType'>"):
            print_ports(port, "Open|Filtered")
        elif (fin_scan_resp.haslayer(TCP)):
            if (fin_scan_resp.getlayer(TCP).flags == "R"):
                print_ports(port, "Closed")

        elif (fin_scan_resp.haslayer(ICMP)):
            if (int(fin_scan_resp.getlayer(ICMP).type) == 3 and
                    int(fin_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                print_ports(port, "Filtered")


def udpScan(target, ports):
    print("UDP 扫描 %s with ports %s" % (target, ports))
    for port in ports:
        udp_scan_resp = sr1(IP(dst=target) / UDP(dport=port), timeout=5)
        if (str(type(udp_scan_resp)) == "<class 'NoneType'>"):
            print_ports(port, "Open|Filtered")
        elif (udp_scan_resp.haslayer(UDP)):
            if (udp_scan_resp.getlayer(TCP).flags == "R"):
                print_ports(port, "Open")
        elif (udp_scan_resp.haslayer(ICMP)):
            if (int(udp_scan_resp.getlayer(ICMP).type) == 3 and
                    int(udp_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                print_ports(port, "Filtered")

####    用于端口扫描
####    命令运行： python3 <脚本文件名> -t <目标IP> -s <扫描类型> [-p <端口列表>]

