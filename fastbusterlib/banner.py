from __future__ import annotations

from textwrap import dedent

FASTBUSTER_BANNER = dedent(
    r"""
    ______         _   ____              _
   |  ____|       | | |  _ \            | |
   | |__ __ _  ___| |_| |_) |_   _  ___ | |_ ___ _ __
   |  __/ _` |/ __| __|  _ <| | | |/ __|| __/ _ \ '__|
   | | | (_| |\__ \ |_| |_) | |_| |\__ \| ||  __/ |     >>>
   |_|  \__,_||___/\__|____/ \__,_||___/ \__\___|_|    >>>>>
                                                        >>>
   """
).strip("\n")

STARTER_PARAMETERS = [
    ("url", "http://10.10.10.10:8080"),
    ("wordlist", "wordlist.txt"),
    ("concurrency", "40"),
    ("timeout", "6.0s"),
    ("method", "GET"),
    ("status-allow", "200,204,301-308,401,403"),
    ("output-format", "text"),
]


def render_startup_screen() -> str:
    lines = [FASTBUSTER_BANNER, "", "Fast start parameters:"]
    for key, value in STARTER_PARAMETERS:
        lines.append(f"  - {key:<13} {value}")
    lines.extend(
        [
            "",
            "Example:",
            "  fastbuster --url http://10.10.10.10:8080 --wordlist wordlist.txt",
        ]
    )
    return "\n".join(lines)
