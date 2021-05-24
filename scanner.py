import socket
from threading import Lock, Thread
from queue import Queue


class Scanner:
    def __init__(self, host, port_start, port_end):
        self.host = host
        self.port_range = range(port_start, port_end + 1)
        self.ports_queue = Queue()
        self.print_lock = Lock()
        self.timeout = 0.1

    def thread_scan(self, scan_func):
        port = self.ports_queue.get()
        scan_func(port)
        self.ports_queue.task_done()

    def start_scan(self, tcp_only):
        threads = []
        for port in self.port_range:
            if tcp_only:
                self.ports_queue.put(port)
                t = Thread(target=self.thread_scan, args=(self.scan_tcp_port,))
                threads.append(t)
        for thread in threads:
            thread.start()
        self.ports_queue.join()

    def scan_tcp_port(self, port: int):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((self.host, port))
            protocol_name = self.get_protocol(port, 'tcp')
            with self.print_lock:
                print(f'TCP {port} {protocol_name}')
        except (socket.timeout, OSError, ConnectionRefusedError):
            pass
        except PermissionError:
            with self.print_lock:
                print(f'TCP {port}: Not enough rights')

    @staticmethod
    def get_protocol(port, transport):
        try:
            return socket.getservbyport(port, transport).upper()
        except OSError:
            return 'OSError'
