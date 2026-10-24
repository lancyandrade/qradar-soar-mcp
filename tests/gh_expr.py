"""A small evaluator for the GitHub Actions expression subset the workflows use.

Enough to evaluate the real ``if:`` and ``concurrency:`` expressions in
.github/workflows against synthetic event contexts: ``||``/``&&`` returning
operand values, ``!``, ``==``/``!=`` with GitHub's loose comparison, property
and index access (missing -> null), string/number/boolean/null literals and
``format()``. Anything else raises, so a test never silently evaluates an
expression it does not understand.
"""

from __future__ import annotations

import re
from typing import Any

_TOKEN = re.compile(
    r"\s*(?:(?P<num>-?\d+(?:\.\d+)?)|(?P<str>'(?:[^']|'')*')|(?P<op>\|\||&&|==|!=|!|\(|\)|\[|\]|\.|,)"
    r"|(?P<ident>[A-Za-z_][A-Za-z0-9_-]*))"
)


class ExprError(ValueError):
    pass


def _tokens(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    pos = 0
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise ExprError(f"cannot tokenise at {text[pos : pos + 20]!r}")
        kind = m.lastgroup
        assert kind is not None
        out.append((kind, m.group(kind)))
        pos = m.end()
        while pos < len(text) and text[pos].isspace():
            pos += 1
    return out


def truthy(value: Any) -> bool:
    if value is None or value is False:
        return False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value != 0
    return value != ""


def _num(value: Any) -> float:
    if value is None:
        return 0.0
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip()) if value.strip() else 0.0
        except ValueError:
            return float("nan")
    return float("nan")


def equal(a: Any, b: Any) -> bool:
    if type(a) is type(b) or (isinstance(a, (int, float)) and isinstance(b, (int, float))):
        if isinstance(a, str):
            return a.casefold() == b.casefold()
        return bool(a == b)
    if a is None or b is None:
        return False
    if isinstance(a, (dict, list)) or isinstance(b, (dict, list)):
        return False
    return _num(a) == _num(b)


def _show(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


class _Parser:
    def __init__(self, text: str, ctx: dict[str, Any]) -> None:
        self.toks = _tokens(text)
        self.i = 0
        self.ctx = ctx

    def peek(self) -> tuple[str, str] | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self, value: str | None = None) -> tuple[str, str]:
        tok = self.peek()
        if tok is None or (value is not None and tok[1] != value):
            raise ExprError(f"expected {value!r}, got {tok!r}")
        self.i += 1
        return tok

    def parse(self) -> Any:
        value = self.or_()
        if self.peek() is not None:
            raise ExprError(f"trailing tokens: {self.toks[self.i :]}")
        return value

    def or_(self) -> Any:
        value = self.and_()
        while self.peek() == ("op", "||"):
            self.take()
            right = self.and_()
            value = value if truthy(value) else right
        return value

    def and_(self) -> Any:
        value = self.not_()
        while self.peek() == ("op", "&&"):
            self.take()
            right = self.not_()
            value = right if truthy(value) else value
        return value

    def not_(self) -> Any:
        if self.peek() == ("op", "!"):
            self.take()
            return not truthy(self.not_())
        return self.cmp()

    def cmp(self) -> Any:
        left = self.primary()
        tok = self.peek()
        if tok in (("op", "=="), ("op", "!=")):
            self.take()
            right = self.primary()
            same = equal(left, right)
            return same if tok[1] == "==" else not same
        return left

    def primary(self) -> Any:
        kind, value = self.take()
        if kind == "num":
            return float(value) if "." in value else int(value)
        if kind == "str":
            return value[1:-1].replace("''", "'")
        if (kind, value) == ("op", "("):
            inner = self.or_()
            self.take(")")
            return inner
        if kind != "ident":
            raise ExprError(f"unexpected {value!r}")
        if value in ("true", "false"):
            return value == "true"
        if value == "null":
            return None
        if self.peek() == ("op", "("):
            return self.call(value)
        current: Any = self.ctx.get(value)
        while self.peek() in (("op", "."), ("op", "[")):
            _, op = self.take()
            if op == ".":
                _, name = self.take()
                current = current.get(name) if isinstance(current, dict) else None
            else:
                index = self.or_()
                self.take("]")
                if isinstance(current, list) and isinstance(index, int):
                    current = current[index] if 0 <= index < len(current) else None
                elif isinstance(current, dict) and isinstance(index, str):
                    current = current.get(index)
                else:
                    current = None
        return current

    def call(self, name: str) -> Any:
        self.take("(")
        args = []
        if self.peek() != ("op", ")"):
            args.append(self.or_())
            while self.peek() == ("op", ","):
                self.take()
                args.append(self.or_())
        self.take(")")
        if name == "format":
            fmt, rest = str(args[0]), args[1:]
            return re.sub(r"\{(\d+)\}", lambda m: _show(rest[int(m.group(1))]), fmt)
        raise ExprError(f"unsupported function {name}()")


def evaluate(expression: str, ctx: dict[str, Any]) -> Any:
    """Evaluate a bare expression (as in ``if:``), or one wrapped in ``${{ }}``."""
    text = expression.strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2]
    return _Parser(text, ctx).parse()


def render(template: str, ctx: dict[str, Any]) -> str:
    """Expand every ``${{ ... }}`` in a string such as a concurrency group."""
    out, pos = [], 0
    while (start := template.find("${{", pos)) != -1:
        end = template.find("}}", start)
        if end == -1:
            raise ExprError("unterminated ${{")
        out.append(template[pos:start])
        out.append(_show(evaluate(template[start + 3 : end], ctx)))
        pos = end + 2
    out.append(template[pos:])
    return "".join(out)
