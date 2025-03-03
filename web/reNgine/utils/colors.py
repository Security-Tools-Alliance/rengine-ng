class Colors:
    """ ANSI color codes """
    # System
    RED = "\033[0;31m"
    BLUE = "\033[0;34m"
    YELLOW = "\x1b[33m"

    # Custom
    BLACK = "\033[0;30m"
    BROWN = "\033[0;33m"
    CYAN = "\033[0;36m"
    GRAY = "\x1b[38;20m"
    GREEN = "\033[0;32m"
    MAGENTA = "\x1b[35;20m"
    ORANGE = "\x1b[38;5;214m"
    PURPLE = "\033[0;35m"
    WHITE = "\x1b[37;20m"
    BOLD_RED = "\x1b[31;1m"

    # Light/Dark
    LIGHT_GRAY = "\033[0;37m"
    LIGHT_ORANGE = "\x1b[38;5;215m"
    LIGHT_RED = "\033[1;31m"
    LIGHT_GREEN = "\033[1;32m"
    LIGHT_BLUE = "\033[1;34m"
    LIGHT_PURPLE = "\033[1;35m"
    LIGHT_CYAN = "\033[1;36m"
    LIGHT_WHITE = "\033[1;37m"
    DARK_GRAY = "\033[1;30m"

    # Formatting
    BOLD = "\033[1m"
    FAINT = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    NEGATIVE = "\033[7m"
    CROSSED = "\033[9m"
    END = "\033[0m"
    RESET = "\x1b[0m"

    # cancel SGR codes if we don't write to a terminal
    if not __import__("sys").stdout.isatty():
        for _ in dir():
            if isinstance(_, str) and _[0] != "_":
                locals()[_] = ""
    elif __import__("platform").system() == "Windows":
        kernel32 = __import__("ctypes").windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        del kernel32



if __name__ == '__main__':
    for i in dir(Colors):
        if i[:1] != "_" and i != "END":
            print("{:>16} {}".format(i, getattr(Colors, i) + i + Colors.END))