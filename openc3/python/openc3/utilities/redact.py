# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

"""Secret redaction for log messages. Python twin of OpenC3::Logger.redact (Ruby)."""

import json
import re


# Placeholder substituted for secret values
REDACTED = "[REDACTED]"
# Dict keys / setting names / form fields whose values must never be logged
SENSITIVE_KEY_PATTERN = re.compile(
    r"pass(word|wd|phrase)|secret|token|api_?key|credential|private_key|authorization|cookie|_key$",
    re.IGNORECASE,
)
# Inline "key: value", "key => value", "key=value" (JSON, repr, form-encoded)
SENSITIVE_PAIR_PATTERN = re.compile(
    r"([\"']?)(\w*(?:pass(?:word|wd|phrase)|secret|token|api_?key|credential|private_key|authorization|cookie)\w*)\1"
    r"(\s*(?:=>|=|:)\s*)([\"']?)((?:bearer\s+)?[^\"'&\s,}\]]*)\4",
    re.IGNORECASE,
)
BEARER_PATTERN = re.compile(r"(bearer\s+)[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE)


def sensitive_key(key) -> bool:
    """Whether values stored under this key are secrets"""
    return SENSITIVE_KEY_PATTERN.search(str(key)) is not None


def redact(value):
    """Return a copy of value that is safe to write to a log message.

    dict values stored under a sensitive key are replaced with REDACTED
    (recursively). str / bytes are parsed as JSON when possible and otherwise
    scrubbed of inline key/value pairs and bearer tokens. Everything else is
    returned unchanged.
    """
    if isinstance(value, dict):
        return {key: REDACTED if sensitive_key(key) else redact(val) for key, val in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(redact(val) for val in value)
    if isinstance(value, (bytes, bytearray)):
        return redact_string(value.decode("utf-8", errors="replace"))
    if isinstance(value, str):
        return redact_string(value)
    return value


def redact_string(string: str) -> str:
    stripped = string.strip()
    if stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, (dict, list)):
                return json.dumps(redact(parsed))
        except ValueError:
            pass  # Not JSON, fall through to pattern based redaction

    def _replace_pair(match):
        quote, key, sep, value_quote = match.group(1), match.group(2), match.group(3), match.group(4)
        return f"{quote}{key}{quote}{sep}{value_quote}{REDACTED}{value_quote}"

    redacted = SENSITIVE_PAIR_PATTERN.sub(_replace_pair, string)
    return BEARER_PATTERN.sub(lambda m: f"{m.group(1)}{REDACTED}", redacted)
