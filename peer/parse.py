import argparse
import sys
from peer.view import PeerView
from typing import Optional, NoReturn, Any


def get_command_args() -> argparse.Namespace:
    """Return parsed peer command line arguments

    Returns:
        argparse.Namespace: Peer command line arguments
    """
    parser = argparse.ArgumentParser(
        description="BPF Exec Peer", prog="python3 -m peer"
    )
    parser.add_argument(
        "-L", "--log-file", default="Peer.log", help="Path to the log file"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument(
        "-I",
        "--dip",
        required=True,
        help="Destination IP Address of the machine you want the packet routed to",
    )

    parser.add_argument(
        "-d",
        "--dport",
        required=True,
    )
    parser.add_argument(
        "-s",
        "--sport",
        required=True,
    )

    parser.add_argument(
        "-D", "--demo", action="store_true", help="Run peer in demo mode"
    )

    return parser.parse_args()
