import argparse
from client.view import ClientView
import logging


class Client:
    def __init__(self, args: argparse.Namespace, log_level: int = logging.INFO):
        self.args = args
        self.view = ClientView(log_level=log_level, logfile=args.log_file)

    def client_loop(self):
        pass
