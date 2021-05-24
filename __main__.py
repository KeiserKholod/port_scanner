import re
from argparse import ArgumentParser
import scanner as sc
import errors


def parse_args():
    parser = ArgumentParser(description='TCP and UDP port scanner')
    parser.add_argument('-t', '--tcp_only', help='Scan only TCP',
                        action='store_true')
    parser.add_argument('-p', '--ports', nargs=2, default=['1', '65535'],
                        metavar='PORT', help='Port range')
    parser.add_argument('host', help='Remote host')
    return parser.parse_args().__dict__


def verify_user_input(port_range):
    port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
    port_range_valid = port_range_pattern.search(port_range.replace(" ", ""))
    if not port_range_valid:
        raise errors.WrongPortRangeError(port_range)
    try:
        port_start = int(port_range_valid.group(1))
        port_end = int(port_range_valid.group(2))
    except ValueError:
        raise errors.WrongPortRangeError(port_range)
    return port_start, port_end


def scan(tcp_only, ports, host):
    port_start, port_end = verify_user_input("-".join(ports))
    scanner = sc.Scanner(host, port_start, port_end)
    scanner.start_scan(tcp_only)
    scanner.start_scan(tcp_only)


if __name__ == '__main__':
    try:
        args = parse_args()
        scan(**args)
    except errors.PortScannerError as err:
        print(err.message)
        exit(1)
    except KeyboardInterrupt:
        print('\nStopped')
