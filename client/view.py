import logging


class ClientView:
    """ClientView is a class that provides methods to log messages with different severity levels"""

    def __init__(
        self,
        log_name: str = "Client",
        log_level: int = logging.DEBUG,
        logfile: str = "Client.log",
    ) -> None:
        self.logger = logging.getLogger(log_name)
        self.logger.setLevel(log_level)

        # No steam handler as the escape codes look bad in a text editor
        file_h = logging.FileHandler(logfile, mode="a+")
        file_h.setLevel(logging.NOTSET)
        file_formatter = logging.Formatter("%(asctime)s: %(message)s")
        file_h.setFormatter(file_formatter)
        self.logger.addHandler(file_h)

    @staticmethod
    def _hex_to_rgb(hex_color: str) -> tuple[int, ...]:
        """Converts a hex color string to an RGB tuple.

        Args:
            hex_color (str): Hexadecimal color string (e.g., "FFFFFF").

        Returns:
            tuple[int, int, int]: RGB values as a tuple of integers.
        """
        try:
            return tuple(int(hex_color[i : i + 2], 16) for i in (0, 2, 4))
        except ValueError:
            logging.error(f"Invalid hex color: {hex_color}. Defaulting to white.")
            return (255, 255, 255)

    @staticmethod
    def colored_text(text: str, hex_color: str) -> str:
        """Formats text with ANSI escape codes for color.

        Args:
            text (str): Text to format.
            hex_color (str): Hexadecimal color string (e.g., "FFFFFF").

        Returns:
            str: Formatted text with ANSI escape codes.
        """
        r, g, b = ClientView._hex_to_rgb(hex_color)
        return f"\033[38;2;{r};{g};{b}m{text}\033[0m"

    def write(self, msg: str) -> None:
        """write method for cmd.Cmd class to print messages

        Args:
            msg (str): message to print
        """
        self.print_msg(msg)

    def print_msg(self, msg: str, text_code: str = "FFFFFF") -> None:
        """prints error message in format [INFO] <msg>

        Args:
            msg (str): message to print
            text_code (int, optional): ansi code for message. Defaults to FFFFFF (white).
        """
        info_msg = "[*] "
        colored_info_msg = self.colored_text(info_msg, "E55381")
        for line in msg.split("\n"):
            new_msg = self.colored_text(line, text_code)
            self.logger.info(f"{info_msg}{msg}")
            print(f"{colored_info_msg}{new_msg}")

    def print_success(self, msg: str, text_code: str = "FFFFFF") -> None:
        """prints success message in format [PASS] <msg>
        Args:
            msg (str): message to print
            text_code (int, optional): ansi code for message. Defaults to FFFFFF (white).
        """
        success_msg = "[+] "
        colored_success_msg = self.colored_text(success_msg, "05A8AA")
        for line in msg.split("\n"):
            new_msg = self.colored_text(line, text_code)
            self.logger.info(f"{success_msg}{msg}")
            print(f"{colored_success_msg}{new_msg}")

    def print_error(self, msg: str, text_code: str = "FFFFFF") -> None:
        """prints error message in format [FAIL] <msg>
        Args:
            msg (str): message to print
            text_code (int, optional): ansi code for message. Defaults to FFFFFF (white).
        """
        error_msg = "[-] "
        colored_error_msg = self.colored_text(error_msg, "FF3A20")
        for line in msg.split("\n"):
            new_msg = self.colored_text(line, text_code)
            self.logger.error(f"{error_msg}{msg}")
            print(f"{colored_error_msg}{new_msg}")

    def print_warning(self, msg: str, text_code: str = "FFFFFF") -> None:
        """prints warning message in format [WARN] <msg>
        Args:
            msg (str): message to print
            text_code (int, optional): ansi code for message. Defaults to FFFFFF (white).
        """
        warn_msg = "[!] "
        colored_warning_msg = self.colored_text(warn_msg, "FFC759")
        for line in msg.split("\n"):
            new_msg = self.colored_text(line, text_code)
            self.logger.warning(f"{warn_msg}{msg}")
            print(f"{colored_warning_msg}{new_msg}")

    def print_debug(self, msg: str, text_code: str = "FFFFFF") -> None:
        """prints debug message in format [DBUG] <msg>
        Args:
            msg (str): message to print
            text_code (int, optional): ansi code for message. Defaults to FFFFFF (white).
        """
        debug_msg = "[D] "
        colored_debug_msg = self.colored_text(debug_msg, "2667FF")
        for line in msg.split("\n"):
            new_msg = self.colored_text(line, text_code)
            self.logger.debug(f"{debug_msg}{msg}")
            if self.logger.level != logging.DEBUG:
                continue
            print(f"{colored_debug_msg}{new_msg}")
