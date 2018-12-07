#!/usr/bin/env python

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

start = time.time()

nmap_results = []
top_ports = "21,22,23,25,53,80,81,110,111,123,137-139,161,389,443,445,500,512,513,548,623-624,1099,1241,1433-1434,1521,2049,2483-2484,3306,3389,4333,4786,4848,5432,5800,5900,5901,6000,6001,7001,8000,8080,8181,8443,10000,16992-16993,27017,32764"
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

    max_task = cpu_count() * 3
    processes = []
    while True:
        while cmds and len(processes) < max_task:
            task = cmds.pop()
            print list2cmdline(task)
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

def do_masscan(scope_file, ports):
    masscan_path = os.popen("which masscan").read().rstrip()
    masscan_args = " -p {0} --open -oG masscan.gnmap -iL {1} --rate=10000".format(ports, scope_file)
    print("\n[+] Running masscan, please be patient...")
    os.system(masscan_path + masscan_args)
    # Wait for masscan to complete
    print("\n[+] Masscan complete!\n")

def main():
    # Setup arguments:
    parser = argparse.ArgumentParser(description='ScanCannon.py - Runs masscan, follows up with Nmap for more detailed service info.')
    parser.add_argument("scope_file", help="Path to the file which contains hosts/networks in scope.")
    parser.add_argument("output_file", help="Base name/path to the output file. Leave off the extension, which will be added by nmap.")
    parser.add_argument("--all-ports", dest="all_ports", action="store_true", help="Scan all 65536 TCP ports.")
    parser.add_argument("--limited-ports", dest="limited_ports", action="store_true", help="Scan a limited number of top ports.")
    args = parser.parse_args()

    # Run Masscan
    if args.limited_ports:
        do_masscan(args.scope_file, top_ports)
    else:
        do_masscan(args.scope_file, all_ports)

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
    for host,ports in host_ports.iteritems():
        ports = ",".join(str(x) for x in ports)
        commands.append(['nmap', '-Pn', '-sS', '-sV', '-p', ports, '-oA', args.output_file, '--append-output', host])

    print("\n[+] Starting nmap, please be patient...\n")
    exec_commands(commands)
    print("\n[+] Finished running nmap.\n")

    end = time.time()
    print("Run time: " + str(end-start))

if __name__ == "__main__":
    main()
