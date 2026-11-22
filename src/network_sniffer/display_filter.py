import operator
import re
from collections.abc import Iterator
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Protocol

from .capture import Packet
from .dissect import PacketAnalysis


_PROTOCOLS = {
    name.lower(): name for name in (
        "Ethernet", "VLAN", "SLL", "SLL2", "ARP", "IPv4", "IPv6", "TCP", "UDP", "ICMP", "ICMPv6", "DNS",
    )
}
_PROTOCOLS.update(ip="IPv4", icmp6="ICMPv6")

_ADDRESS_FIELDS = {
    "src.ip": ("ipv4.src", "ipv6.src"),
    "dst.ip": ("ipv4.dst", "ipv6.dst"),
    "ipv4.src": ("ipv4.src",),
    "ipv4.dst": ("ipv4.dst",),
    "ipv6.src": ("ipv6.src",),
    "ipv6.dst": ("ipv6.dst",),
}
_NUMERIC_FIELDS = {
    "frame.len", "frame.caplen", "eth.type", "vlan.id", "arp.operation",
    "ipv4.protocol", "ipv4.ttl", "ipv4.fragment_offset", "ipv6.next_header", "ipv6.hop_limit",
    "tcp.src_port", "tcp.dst_port", "tcp.flags", "tcp.seq", "tcp.ack",
    "udp.src_port", "udp.dst_port", "udp.length", "icmp.type", "icmp.code", "icmpv6.type", "icmpv6.code",
    "dns.id", "dns.flags", "dns.response", "dns.rcode", "dns.questions", "dns.answers", "dns.qtype",
}
_NUMERIC_ALIASES = {
    "src.port": ("tcp.src_port", "udp.src_port"),
    "dst.port": ("tcp.dst_port", "udp.dst_port"),
    "tcp.port": ("tcp.src_port", "tcp.dst_port"),
    "udp.port": ("udp.src_port", "udp.dst_port"),
}
_OPERATORS = {
    "==": operator.eq, "!=": operator.ne, "<": operator.lt,
    "<=": operator.le, ">": operator.gt, ">=": operator.ge,
}
_TOKEN_PATTERN = re.compile(r"\s+|==|!=|<=|>=|[()<>]|[a-zA-Z0-9_.:-]+|[^\s]")
_INTEGER_PATTERN = re.compile(r"-?(?:0[xX][0-9a-fA-F]+|[0-9]+)")
_MAX_EXPRESSION_LENGTH = 4096
_MAX_GROUP_DEPTH = 32


class DisplayFilterError(ValueError):
    def __init__(self, message: str, column: int) -> None:
        self.column = column
        self.detail = message
        super().__init__(f"Column {column}: {message}")


# A missing field is unknown, including after negation. Only True selects a packet.
class _Expression(Protocol):
    def evaluate(self, packet: Packet, analysis: PacketAnalysis) -> bool | None: ...


@dataclass(frozen=True, slots=True)
class _ProtocolPredicate:
    name: str

    def evaluate(self, packet: Packet, analysis: PacketAnalysis) -> bool:
        return any(layer.name == self.name and layer.length > 0 for layer in analysis.layers)


_Comparable = int | IPv4Address | IPv6Address


@dataclass(frozen=True, slots=True)
class _Comparison:
    keys: tuple[str, ...]
    operation: str
    expected: _Comparable

    def _values(self, packet: Packet, analysis: PacketAnalysis) -> Iterator[_Comparable]:
        if self.keys == ("frame.len",):
            yield packet.original_length
        elif self.keys == ("frame.caplen",):
            yield packet.captured_length
        else:
            for layer in analysis.layers:
                for field in layer.fields:
                    if field.key in self.keys and isinstance(field.value, (int, IPv4Address, IPv6Address)):
                        yield field.value

    def evaluate(self, packet: Packet, analysis: PacketAnalysis) -> bool | None:
        compare = _OPERATORS[self.operation]
        # For repeated fields, equality and ordered comparisons match any value.
        # Inequality requires every value to differ.
        decisive = self.operation != "!="
        found = False
        for value in self._values(packet, analysis):
            found = True
            if compare(value, self.expected) is decisive:
                return decisive
        return not decisive if found else None


@dataclass(frozen=True, slots=True)
class _Negation:
    term: _Expression

    def evaluate(self, packet: Packet, analysis: PacketAnalysis) -> bool | None:
        value = self.term.evaluate(packet, analysis)
        return None if value is None else not value


@dataclass(frozen=True, slots=True)
class _LogicalGroup:
    terms: tuple[_Expression, ...]
    decisive: bool  # True for OR, False for AND.

    def evaluate(self, packet: Packet, analysis: PacketAnalysis) -> bool | None:
        unknown = False
        for term in self.terms:
            value = term.evaluate(packet, analysis)
            if value is self.decisive:
                return value
            if value is None:
                unknown = True
        return None if unknown else not self.decisive


@dataclass(frozen=True, slots=True)
class DisplayFilter:
    expression: str
    _root: _Expression

    def matches(self, packet: Packet, analysis: PacketAnalysis) -> bool:
        return self._root.evaluate(packet, analysis) is True


@dataclass(frozen=True, slots=True)
class _Token:
    text: str
    column: int


class _Parser:
    def __init__(self, expression: str) -> None:
        self.tokens = [
            _Token(match[0], match.start() + 1)
            for match in _TOKEN_PATTERN.finditer(expression) if not match[0].isspace()
        ]
        self.tokens.append(_Token("", len(expression) + 1))
        self.index = 0

    @property
    def current(self) -> _Token:
        return self.tokens[self.index]

    def _accept(self, text: str) -> bool:
        if self.current.text.lower() == text:
            self.index += 1
            return True
        return False

    def parse(self) -> _Expression:
        expression = self._or(0)
        if self.current.text:
            raise DisplayFilterError(f"Expected 'and' or 'or' before {self.current.text!r}", self.current.column)
        return expression

    def _or(self, depth: int) -> _Expression:
        terms = [self._and(depth)]
        while self._accept("or"):
            terms.append(self._and(depth))
        return terms[0] if len(terms) == 1 else _LogicalGroup(tuple(terms), True)

    def _and(self, depth: int) -> _Expression:
        terms = [self._unary(depth)]
        while self._accept("and"):
            terms.append(self._unary(depth))
        return terms[0] if len(terms) == 1 else _LogicalGroup(tuple(terms), False)

    def _unary(self, depth: int) -> _Expression:
        negate = False
        while self._accept("not"):
            negate = not negate

        if self.current.text == "(":
            if depth >= _MAX_GROUP_DEPTH:
                raise DisplayFilterError("Too many nested parentheses", self.current.column)
            self.index += 1
            expression = self._or(depth + 1)
            if not self._accept(")"):
                raise DisplayFilterError("Expected ')'", self.current.column)
        else:
            expression = self._predicate()
        return _Negation(expression) if negate else expression

    def _predicate(self) -> _Expression:
        token = self.current
        name = token.text.lower()
        protocol = _PROTOCOLS.get(name)
        if protocol is not None:
            self.index += 1
            return _ProtocolPredicate(protocol)

        address_keys = _ADDRESS_FIELDS.get(name)
        numeric_keys = _NUMERIC_ALIASES.get(name)
        if numeric_keys is None and name in _NUMERIC_FIELDS:
            numeric_keys = (name,)
        if address_keys is None and numeric_keys is None:
            message = "Expected a protocol or field" if not token.text else f"Unknown protocol or field {token.text!r}"
            raise DisplayFilterError(message, token.column)

        self.index += 1
        operation = self.current
        if operation.text not in _OPERATORS:
            raise DisplayFilterError(f"Expected a comparison after {token.text!r}", operation.column)

        self.index += 1
        literal = self.current
        if address_keys is not None:
            if operation.text not in ("==", "!="):
                raise DisplayFilterError("IP addresses support only '==' and '!='", operation.column)
            expected = self._address(literal, name)
            keys = address_keys
        else:
            if not _INTEGER_PATTERN.fullmatch(literal.text):
                raise DisplayFilterError("Expected an integer", literal.column)
            base = 16 if literal.text.lower().lstrip("-").startswith("0x") else 10
            try:
                expected = int(literal.text, base)
            except ValueError as error:
                raise DisplayFilterError("Integer literal is too large", literal.column) from error
            assert numeric_keys is not None
            keys = numeric_keys
        self.index += 1
        return _Comparison(keys, operation.text, expected)

    @staticmethod
    def _address(token: _Token, name: str) -> IPv4Address | IPv6Address:
        try:
            address = ip_address(token.text)
        except ValueError as error:
            raise DisplayFilterError("Expected an IP address", token.column) from error
        if name.startswith(("ipv4.", "ipv6.")) and not name.startswith(f"ipv{address.version}."):
            raise DisplayFilterError(f"Address family does not match {name!r}", token.column)
        return address


def compile_display_filter(expression: str) -> DisplayFilter:
    if len(expression) > _MAX_EXPRESSION_LENGTH:
        raise DisplayFilterError("Expression is too long", _MAX_EXPRESSION_LENGTH + 1)
    return DisplayFilter(expression.strip(), _Parser(expression).parse())
