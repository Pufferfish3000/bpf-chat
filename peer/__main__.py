import logging
from peer.view import PeerView
from peer.parse import get_command_args
from peer.peer import Peer


def start_peer() -> None:
    args = get_command_args()
    if args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    peer = Peer(args, log_level)

    intro = PeerView.colored_text(
        "BPF Chat Peer, type a message to send to another peer\n\n\n",
        "05A8AA",
    )

    # Print the intro message without logging
    print(intro)
    peer.view.print_debug("Starting Peer in debug mode")
    try:
        peer.peer_loop()
    except KeyboardInterrupt:
        peer.view.print_msg("Goodbye")


if __name__ == "__main__":
    start_peer()
