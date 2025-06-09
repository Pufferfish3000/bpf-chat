import socket


class Networking:
    def __init__(self, dip: str, dport: int, sport: int):
        self.dip = dip
        self.dport = dport
        self.sport = sport
        self.sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("", self.sport))

    def send_msg(self, msg: str):
        self.sock.sendto(msg.encode("utf-8"), (self.dip, self.dport))

    def recv_msg(self) -> str:
        data, _ = self.sock.recvfrom(1024)
        return data.decode("utf-8")

    def close(self):
        self.sock.close()
