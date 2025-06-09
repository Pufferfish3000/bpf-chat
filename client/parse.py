import argparse
import sys
from client.view import ClientView
from typing import Optional, NoReturn, Any


def get_command_args() -> argparse.Namespace:
    """Return parsed client command line arguments

    Returns:
        argparse.Namespace: Client command line arguments
    """
    parser = argparse.ArgumentParser(
        description="BPF Exec Client", prog="python3 -m client"
    )
    parser.add_argument(
        "-p", "--log-file", default="Client.log", help="Path to the log file"
    )
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode")
    parser.add_argument(
        "-I",
        "--dip",
        required=True,
        help="Destination IP Address of the machine you want the packet routed to",
    )

    parser.add_argument(
        "-D", "--demo", action="store_true", help="Run client in demo mode"
    )

    return parser.parse_args()
