# ScanCannon

Runs Masscan, followed up by Nmap for service version info.
This should finish scans much faster than Nmap alone while providing service version info that Masscan doesn't provide.

During testing, a scan using nmap alone against all 65535 ports on 16 hosts took more than two hours just to reach 70 percent. Using ScanCannon, the same nmap scan parameters finished in 7 minutes.

## Installation and requirements

* Requires masscan to be in your path.
* Requires root privileges.
* No installation required. ScanCannon uses only standard libraries and should run on Python 2.7+. Not tested on Python 3+ but it *should* work.
* Your scope_file must contain IP or network addresses only. Masscan doesn't resolve hostnames.

## Usage

usage: ScanCannon.py [-h] [--all-ports] [--limited-ports]
                     scope_file output_file

ScanCannon.py - Runs masscan, follows up with Nmap for more detailed service
info.

positional arguments:
  scope_file       Path to the file which contains hosts/networks in scope.
  output_file      Base name/path to the output file. Leave off the extension,
                   which will be added by nmap.

optional arguments:
  -h, --help       show this help message and exit
  --all-ports      Scan all 65536 TCP ports.
  --limited-ports  Scan a limited number of top ports.

## License and warranty

MIT License. No warranty is provided. Use at your own risk and only use it to scan systems that you own or have permission to scan.
