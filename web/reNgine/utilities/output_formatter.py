"""
Output formatter utilities - Leaf layer.
Pure text formatting functions with no Django dependencies.
Handles JSON formatting, ANSI code conversion to HTML, and unicode handling.
"""

from html import escape
import json
import re
from typing import Dict, Tuple


def format_json_output(text: str) -> Tuple[bool, str]:
    """
    Attempt to parse and format JSON text.

    Args:
        text: Text that might be JSON

    Returns:
        tuple: (is_json, formatted_text)
    """
    if not text or not text.strip():
        return False, text

    try:
        # Try to parse as JSON
        parsed = json.loads(text)
        # Format with indentation
        formatted = json.dumps(parsed, indent=2, ensure_ascii=False)
        return True, formatted
    except (json.JSONDecodeError, ValueError, TypeError):
        return False, text


def convert_ansi_to_html(text: str) -> str:
    """
    Convert ANSI escape sequences to HTML with CSS classes.

    Handles:
    - Basic colors (30-37 for foreground, 40-47 for background)
    - Bright colors (90-97, 100-107)
    - Styles (bold=1, underline=4, italic=3, dim=2, etc.)
    - Reset codes (0, 22, 24, etc.)
    - 256 colors (38;5;n and 48;5;n) - simplified to closest basic color

    Args:
        text: Text containing ANSI escape sequences

    Returns:
        str: HTML with span tags and CSS classes, with ANSI codes removed
    """
    if not text:
        return ""

    # Escape HTML first to prevent XSS
    text = escape(text)

    # ANSI escape sequence pattern: \u001b[...m or \x1b[...m or ESC[...m
    ansi_pattern = re.compile(r"\u001b\[([0-9;]*)m|\x1b\[([0-9;]*)m|ESC\[([0-9;]*)m")

    result = []
    last_pos = 0
    current_classes = []

    for match in ansi_pattern.finditer(text):
        # Add text before the ANSI code
        if match.start() > last_pos:
            text_segment = text[last_pos : match.start()]
            if text_segment:
                if current_classes:
                    result.append(f'<span class="{" ".join(current_classes)}">{text_segment}</span>')
                else:
                    result.append(text_segment)

        # Process ANSI code
        code_str = match.group(1) or match.group(2) or match.group(3) or ""
        codes = [int(c) for c in code_str.split(";") if c.isdigit()]

        # Reset all styles
        if 0 in codes:
            current_classes = []
        else:
            for code in codes:
                if code == 1:  # Bold
                    if "ansi-bold" not in current_classes:
                        current_classes.append("ansi-bold")
                elif code == 2:  # Dim
                    if "ansi-dim" not in current_classes:
                        current_classes.append("ansi-dim")
                elif code == 3:  # Italic
                    if "ansi-italic" not in current_classes:
                        current_classes.append("ansi-italic")
                elif code == 4:  # Underline
                    if "ansi-underline" not in current_classes:
                        current_classes.append("ansi-underline")
                elif code == 22:  # Reset bold/dim
                    current_classes = [c for c in current_classes if c not in ["ansi-bold", "ansi-dim"]]
                elif code == 23:  # Reset italic
                    current_classes = [c for c in current_classes if c not in ["ansi-italic"]]
                elif code == 24:  # Reset underline
                    current_classes = [c for c in current_classes if c not in ["ansi-underline"]]
                elif 30 <= code <= 37:
                    # Remove existing foreground colors
                    current_classes = [
                        c
                        for c in current_classes
                        if not c.startswith("ansi-") or c in ["ansi-bold", "ansi-dim", "ansi-italic", "ansi-underline"]
                    ]
                    color_map = {
                        30: "ansi-black",
                        31: "ansi-red",
                        32: "ansi-green",
                        33: "ansi-yellow",
                        34: "ansi-blue",
                        35: "ansi-magenta",
                        36: "ansi-cyan",
                        37: "ansi-white",
                    }
                    current_classes.append(color_map[code])
                elif 40 <= code <= 47:
                    # Remove existing background colors
                    current_classes = [c for c in current_classes if not c.startswith("ansi-bg-")]
                    bg_color_map = {
                        40: "ansi-bg-black",
                        41: "ansi-bg-red",
                        42: "ansi-bg-green",
                        43: "ansi-bg-yellow",
                        44: "ansi-bg-blue",
                        45: "ansi-bg-magenta",
                        46: "ansi-bg-cyan",
                        47: "ansi-bg-white",
                    }
                    current_classes.append(bg_color_map[code])
                elif 90 <= code <= 97:
                    # Remove existing foreground colors, but preserve style classes and background colors
                    current_classes = [
                        c
                        for c in current_classes
                        if not c.startswith("ansi-")
                        or c in ["ansi-bold", "ansi-dim", "ansi-italic", "ansi-underline"]
                        or c.startswith("ansi-bg-")
                    ]
                    bright_color_map = {
                        90: "ansi-bright-black",
                        91: "ansi-bright-red",
                        92: "ansi-bright-green",
                        93: "ansi-bright-yellow",
                        94: "ansi-bright-blue",
                        95: "ansi-bright-magenta",
                        96: "ansi-bright-cyan",
                        97: "ansi-bright-white",
                    }
                    current_classes.append(bright_color_map[code])
                elif 100 <= code <= 107:
                    # Remove existing background colors
                    current_classes = [c for c in current_classes if not c.startswith("ansi-bg-")]
                    bright_bg_color_map = {
                        100: "ansi-bg-bright-black",
                        101: "ansi-bg-bright-red",
                        102: "ansi-bg-bright-green",
                        103: "ansi-bg-bright-yellow",
                        104: "ansi-bg-bright-blue",
                        105: "ansi-bg-bright-magenta",
                        106: "ansi-bg-bright-cyan",
                        107: "ansi-bg-bright-white",
                    }
                    current_classes.append(bright_bg_color_map[code])
        last_pos = match.end()

    # Add remaining text
    if last_pos < len(text):
        if text_segment := text[last_pos:]:
            if current_classes:
                result.append(f'<span class="{" ".join(current_classes)}">{text_segment}</span>')
            else:
                result.append(text_segment)

    return "".join(result)


def format_output(output: str) -> Dict[str, any]:
    """
    Main function to analyze and format output text.

    Detects JSON and formats it, converts ANSI codes to HTML, handles unicode.

    Args:
        output: Raw output text

    Returns:
        dict: Dictionary with formatted output and metadata:
            - formatted: str - Formatted output (HTML for ANSI, formatted JSON for JSON)
            - is_json: bool - Whether the output was JSON
            - has_ansi: bool - Whether the output contained ANSI codes
            - raw: str - Original output
    """
    if not output:
        return {
            "formatted": "",
            "is_json": False,
            "has_ansi": False,
            "raw": "",
        }

    # Check for ANSI codes first
    has_ansi = bool(re.search(r"\u001b\[|\\x1b\[|ESC\[", output))

    # Try to parse as JSON
    is_json, json_formatted = format_json_output(output)

    if is_json:
        # For JSON, return formatted JSON (no ANSI conversion needed)
        return {
            "formatted": json_formatted,
            "is_json": True,
            "has_ansi": has_ansi,
            "raw": output,
        }

    # Not JSON, convert ANSI to HTML if present
    formatted = convert_ansi_to_html(output) if has_ansi else escape(output)
    return {
        "formatted": formatted,
        "is_json": False,
        "has_ansi": has_ansi,
        "raw": output,
    }
