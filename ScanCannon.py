#!/usr/bin/env python3

"""ScanCannon.py - Runs masscan, follows up with Nmap for more detailed service info.

This should finish much faster than nmap alone."""

__author__ = "Steve Campbell (@lpha3ch0)"
__license__ = "MIT"
__version__ = "1.0"
__maintainer__ = "Steve Campbell"
__email__ = "sdcampbell68@live.com"

import argparse, os, sys, time
from subprocess import Popen, list2cmdline
from multiprocessing import cpu_count
import nmap

nmap_results = []
top_ports = "21,22,23,25,53,80,81,110,111,123,137-139,161,389,443,445,500,512,513,548,623-624,1099,1241,1433-1434,1521,2049,2375,2376,2483-2484,3306,3389,4333,4786,4848,5432,5800,5900,5901,6000,6001,7001,8000,8080,8181,8443,10000,16992-16993,27017,32764"
all_ports = "1-65535"

def exec_commands(cmds):
    ''' Exec commands in parallel in multiple process
    (as much as we have CPU)
    '''
    if not cmds: return # empty list

    def done(p):
        return p.poll() is not None
    def success(p):
        return p.returncode == 0
    def fail():
        sys.exit(1)

    max_task = 12 # Tweaked for the PTK's. Adjust as needed.
    processes = []
    while True:
        while cmds and len(processes) < max_task:
            task = cmds.pop()
            print(list2cmdline(task))
            processes.append(Popen(task))

        for p in processes:
            if done(p):
                if success(p):
                    processes.remove(p)
                else:
                    fail()

        if not processes and not cmds:
            break
        else:
            time.sleep(0.05)

def do_masscan(scope_file, ports, excludefile):
    masscan_path = os.popen("which masscan").read().rstrip()
    if not masscan_path:
        print("\n[!] Masscan was not found! Please install Masscan and rerun.\n")
        sys.exit(1)
    if excludefile:
        masscan_args = " -p {0} --open --excludefile {1} -oG masscan.gnmap -iL {2} --source-port 61000 --rate=10000".format(ports, excludefile, scope_file)
    else:
        masscan_args = " -p {0} --open -oG masscan.gnmap -iL {1} --source-port 61000 --rate=10000".format(ports, scope_file)
    print("\n[+] Running masscan, please be patient...")
    os.system(masscan_path + masscan_args)
    # Wait for masscan to complete
    print("\n[+] Masscan complete!\n")

def grep_gnmap_hosts(gnmapfile, port, proto):
    """
    Greps gnmap (grepable) output from Nmap or Masscan for hosts with the specified port and writes hosts to a file.
    Accepts three arguments: "/path/to/gnmapfile", "port", proto (tcp | udp)
    """
    lines = [line.rstrip('\n') for line in open(gnmapfile)]
    hosts = []
    search = port + "/open/" + proto
    for line in lines:
        if search in line:
            hosts.append(line.split()[1])
    if hosts:
        filename = port + "." + proto + ".txt"
        with open(filename,'w') as f:
            f.write('\n'.join(hosts))
            print("{} hosts written to file : {}".format(len(hosts), filename))
    else:
        print("No hosts found with port {} open.".format(port))

def smb_signing():
    """
    Tests host for SMB signing and writes affected hosts to a file.
    """
    hosts = [line.rstrip('\n') for line in open('445.tcp.txt')]
    nm = nmap.PortScanner()
    vuln_hosts = []
    for target in hosts:
        nm.scan(hosts=target, ports='445', arguments='-sS --script=smb2-security-mode')
        for host in nm._scan_result['scan'].keys():
            try:
                if "Message signing enabled but not required" in str(nm._scan_result['scan'][host]['hostscript']):
                    print("[+]{} : Message signing not required".format(host))
                    vuln_hosts.append(host)
            except:
                continue
    if vuln_hosts:
        filename = "smb-message-signing.txt"
        print("Writing vulnerable hosts to file: {}".format(filename))
        with open(filename,'w') as f:
            for host in vuln_hosts:
                f.write(host+'\n')

def smb_vulns():
    """
    Scans the specified host async for SMB vulns and calls the function callback_result_smb_vulns.
    Accepts one argument: host
    """
    hosts = [line.rstrip('\n') for line in open('445.tcp.txt')]
    nm = nmap.PortScanner()
    vuln_hosts = []
    for target in hosts:
        nm.scan(hosts=target, ports='445', arguments='-sS --script=smb-vuln-ms17-010.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse')
        for host in nm._scan_result['scan'].keys():
            try:
                for x in nm._scan_result['scan'][host]['hostscript']:
                    if "State: VULNERABLE" in str(x):
                        print("[+]" + host + " : VULNERABLE! " + x['id'])
                        vuln_hosts.append("{} : {}".format(host, x['id']))
            except:
                continue
    if vuln_hosts:
        filename = "SMB-VULNS.txt"
        print("Writing vulnerable hosts to file: {}".format(filename))
        with open(filename,'a') as f:
            for host in vuln_hosts:
                f.write(host+'\n')


def main():
    if not os.geteuid() == 0:
        print("ScanCannon must be run as root/sudo!")
        sys.exit()
    # Setup arguments:
    parser = argparse.ArgumentParser(description='ScanCannon.py - Runs masscan, follows up with Nmap for more detailed service info.')
    parser.add_argument("scope_file", help="Path to the file which contains hosts/networks in scope.")
    parser.add_argument("output_file", help="Base name/path to the output file. Output will be in gnmap format.")
    parser.add_argument("--all-ports", dest="all_ports", action="store_true", help="Scan all 65536 TCP ports.")
    parser.add_argument("--limited-ports", dest="limited_ports", action="store_true", help="Scan a limited number of common vulnerable ports.")
    parser.add_argument("-e", "--excludefile", dest="excludefile", action="store_true", help="Path to a file containing hosts to exclude from the scan.")
    args = parser.parse_args()

    # Run Masscan
    # iptables - Add rule to prevent the kernel from sendint a RST and killing the connection.
    os.system("iptables -A INPUT -p tcp --dport 61000 -j DROP")
    if args.limited_ports:
        do_masscan(args.scope_file, top_ports, args.excludefile)
    else:
        do_masscan(args.scope_file, all_ports, args.excludefile)

    # Remove iptables rule
    os.system("iptables -D INPUT -p tcp --dport 61000 -j DROP")

    # Define commands, which will be run in parallel.
    commands = []

    # Run Nmap
    host_ports = dict() # Dictionary with hosts as keys and a list of ports as values.
    lines = [line.rstrip('\n') for line in open('masscan.gnmap')]
    for line in lines:
        if "Host" in line:
            words = line.split()
            host = words[1]
            port = words[-1].split('/')[0]
            if host in host_ports:
                # If host is already in host_ports dictionary, append the port to the host.
                host_ports[host].append(port)
            else:
                # Host is not already in host_ports dictionary, add the host and port.
                host_ports[host] = [port]
    for host,ports in host_ports.items():
        ports = ",".join(str(x) for x in ports)
        commands.append(['nmap', '-Pn', '-sS', '-sV', '-p', ports, '-oG', args.output_file, '--append-output', host])

    print("\n[+] Starting nmap, please be patient...\n")
    exec_commands(commands)
    print("\n[+] Finished running nmap.\n")

    print("\nStarting SMB tests...")
    print("\nChecking for hosts with port 445/tcp open...")
    grep_gnmap_hosts("{}.gnmap".format(args.output_file), '445', 'tcp')
    print("\nChecking hosts for SMB signing...")
    smb_signing()
    print("\nChecking hosts for SMB vulnerabilities...")
    smb_vulns()

    print("If the terminal is jacked up, enter the 'reset' command to fix it.\nSorry, but I don't know why this sometimes happens.")

if __name__ == "__main__":
    main()
