"""A single quote-aware lexer, including source spans and pipeline separators."""

from dataclasses import dataclass
from nvyr.errors import ParseError


@dataclass(frozen=True)
class Token:
    value: str
    start: int
    end: int
    pipe: bool = False
    complete: bool = True
    quoted: bool = False


def lex(text, *, partial=False):
    tokens, index = [], 0

    while index < len(text):
        if text[index].isspace():
            index += 1
            continue

        start = index

        if text[index] == "|":
            tokens.append(Token("|", index, index + 1, True))
            index += 1
            continue

        value, quote, unfinished_escape = "", None, False
        quoted = False

        while index < len(text):
            char = text[index]
            if quote is None and (char.isspace() or char == "|"):
                break

            if char in "\"'":
                quoted = True
                if quote is None:
                    quote = char
                elif quote == char:
                    quote = None
                else:
                    value += char
            elif char == "\\" and quote != "'":
                # Within double quotes only quote/backslash need escaping.
                # Preserve regex escapes such as \\. and \\d verbatim.
                if quote == '"' and index + 1 < len(text) and text[index + 1] not in '\\"':
                    value += char
                    index += 1
                    continue

                index += 1

                if index == len(text):
                    if not partial:
                        raise ParseError("The command ends with a backslash. Complete the escaped character or remove the backslash.", start=start)

                    unfinished_escape = True
                    break

                value += text[index]
            else:
                value += char

            index += 1

        if quote and not partial:
            raise ParseError("A quoted value is missing its closing quote.", start=start)

        tokens.append(Token(value, start, index, complete=not quote and not unfinished_escape, quoted=quoted))

    return tokens


def split_pipeline(text):
    stages = [[]]

    for token in lex(text):
        if token.pipe:
            if not stages[-1]:
                raise ParseError("A command is required before '|'.", start=token.start)

            stages.append([])
        else:
            stages[-1].append(token)

    if not stages[-1]:
        raise ParseError("Enter a command; after '|', specify an output modifier such as match or commands.")

    return stages


def quote(value):
    import shlex

    if isinstance(value, Token):
        rendered = shlex.quote(value.value)
        if value.quoted and rendered == value.value:
            return "'" + rendered + "'"
        return rendered

    return shlex.quote(str(value))


def load_arguments(words):
    """Shared load grammar; file access remains exclusively client-side."""
    words = list(words)
    replace = bool(words and words[0] == "replace")
    if replace:
        words.pop(0)

    set_format = bool(words and words[0] == "set")
    if set_format:
        words.pop(0)

    if len(words) != 1:
        raise ParseError("Expected load [replace] [set] <file>")

    return words[0], replace, set_format
