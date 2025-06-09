import logging
from client.view import ClientView
from client.parse import get_command_args
from client.client import Client


def start_client() -> None:
    args = get_command_args()
    if args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    client = Client(args, log_level)

    intro = ClientView.colored_text(
        "BPF Chat Client, type a message to send to another client\n\n\n",
        "05A8AA",
    )

    # Print the intro message without logging
    print(intro)
    client.view.print_debug("Starting Client in debug mode")
    try:
        client.client_loop()
    except KeyboardInterrupt:
        client.view.print_msg("Goodbye")

if __name__ == "__main__":
    start_client()
