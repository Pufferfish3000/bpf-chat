import argparse
from peer.networking import Networking
from peer.view import PeerView
import random
import logging
import time


class Peer:
    def __init__(self, args: argparse.Namespace, log_level: int = logging.INFO):
        self.args = args
        self.view = PeerView(log_level=log_level, logfile=args.log_file)
        self.network = Networking(args.dip, int(args.dport), int(args.sport))

    def peer_loop(self):
        prompt = PeerView.colored_text("BPF CHAT> ", "C9C9EE")

        while True:
            if self.args.demo:
                msg = Peer._random_sentence()
            else:
                msg = Peer._prompt_user()

            self.view.print_msg(f"Sending: {msg}")
            self.network.send_msg(msg)
            recv_msg = self.network.recv_msg()
            self.view.print_success(f"Recv msg: {recv_msg}")

    @staticmethod
    def _random_sentence():
        time.sleep(2)
        nouns = [
            "puppy",
            "car",
            "rabbit",
            "doll",
            "monkey",
            "cat",
            "fish",
            "doctor",
            "hacker",
        ]
        verbs = [
            "runs",
            "hits",
            "jumps",
            "drives",
            "walks",
            "throws",
            "kicks",
            "punches",
            "pulls",
            "pushes",
            "lifts",
            "drops",
            "catches",
            "climbs",
            "swings",
            "rolls",
            "slides",
            "dives",
            "shoots",
            "stomps",
            "grabs",
            "chases",
            "tackles",
            "slaps",
        ]
        adv = [
            "well.",
            "fast.",
            "straight.",
            "hard.",
            "loudly.",
            "proudly.",
            "suspiciously.",
            "strangely.",
            "kindly.",
            "easily.",
            "rudely.",
            "neatly.",
            "quickly.",
            "generously.",
            "eagerly.",
            "accidentally.",
            "rapidly.",
            "hungrily.",
            "foolishly.",
            "cheerfully.",
        ]
        return (
            nouns[random.randrange(0, len(nouns) - 1)]
            + " "
            + verbs[random.randrange(0, len(verbs) - 1)]
            + " "
            + adv[random.randrange(0, len(adv) - 1)]
        )

    @staticmethod
    def _prompt_user():
        prompt = PeerView.colored_text("BPF CHAT> ", "C9C9EE")
        return input(prompt)
