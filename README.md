# ScanCannon

Masscan alone is fast but doesn't provide service version info. Nmap alone is too slow when scanning all 65535 TCP ports. ScanCannon first runs Masscan, the follows up with parallel Nmap scans of only those hosts/ports that Masscan discovers open.

usage: ScanCannon.py scope_file output_file [--all-ports] [--limited-ports]

positional arguments:
  scope_file       Path to the file which contains hosts/networks in scope.
  output_file      Base name/path to the output file. Leave off the extension,
                   which will be added by nmap.

optional arguments:
  -h, --help       show this help message and exit
  --all-ports      Scan all 65536 TCP ports.
  --limited-ports  Scan a limited number of common vulnerable ports.
