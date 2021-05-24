class PortScannerError(Exception):
    message: str


class WrongPortRangeError(PortScannerError):
    def __init__(self, port_range):
        self.message = f'Wrong port range: {port_range}'
