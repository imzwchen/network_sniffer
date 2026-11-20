import re
import struct
from dataclasses import dataclass
from ipaddress import ip_address


_MAX_DNS_RECORDS = 128
_MAX_HTTP_HEADER = 16384
_MAX_MESSAGES = 16
_TLS_VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
_HTTP_TOKEN = rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+"
_HTTP_REQUEST = re.compile(rb"(" + _HTTP_TOKEN + rb") ([\x21-\x7e]+) (HTTP/1\.[01])")
_HTTP_RESPONSE = re.compile(rb"(HTTP/1\.[01]) ([1-5][0-9]{2})(?: (.*))?")
_HEADER_NAME = re.compile(_HTTP_TOKEN)
_DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT"}


@dataclass(frozen=True, slots=True)
class MessageField:
    key: str
    label: str
    value: int | str
    offset: int = 0
    length: int = 0
    display: str | None = None

    @property
    def text(self) -> str:
        return str(self.value) if self.display is None else self.display


@dataclass(frozen=True, slots=True)
class ApplicationMessage:
    protocol: str
    title: str
    fields: tuple[MessageField, ...] = ()
    note: str | None = None


class _DecodeError(ValueError):
    pass


def _wire_text(data: bytes, limit: int = 200) -> str:
    text = "".join(chr(byte) if 32 <= byte <= 126 and byte != 92 else f"\\x{byte:02x}" for byte in data[:limit])
    return text + ("..." if len(data) > limit else "")


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "big")


def _dns_name(data: bytes, start: int, bound: int) -> tuple[str, int]:
    position, expanded_length = start, 1
    consumed = None
    labels = []
    visited = set()
    while True:
        limit = bound if consumed is None else len(data)
        if position >= limit:
            raise _DecodeError("Incomplete DNS name")
        if position in visited or len(visited) >= 128:
            raise _DecodeError("Invalid DNS compression chain")
        visited.add(position)
        size = data[position]
        if not size:
            return ".".join(labels) or ".", position + 1 if consumed is None else consumed
        if size & 0xC0 == 0xC0:
            if position + 2 > limit:
                raise _DecodeError("Incomplete DNS compression pointer")
            target = _u16(data, position) & 0x3FFF
            if not 12 <= target < position:
                raise _DecodeError("Invalid DNS compression pointer")
            if consumed is None:
                consumed = position + 2
            position = target
            continue
        if size > 63:
            raise _DecodeError("Invalid DNS label length")
        end = position + 1 + size
        expanded_length += size + 1
        if expanded_length > 255 or end > limit:
            raise _DecodeError("Incomplete or overlong DNS name")
        labels.append(_wire_text(data[position + 1 : end]).replace(".", "\\."))
        position = end


def _dns_type(value: int) -> str:
    name = _DNS_TYPES.get(value)
    return f"{value} ({name})" if name else str(value)


def _dns_rdata(data: bytes, start: int, end: int, record_type: int) -> str:
    value = data[start:end]
    if (record_type, len(value)) in ((1, 4), (28, 16)):
        return str(ip_address(value))
    if record_type in (2, 5, 12) and value:
        name, consumed = _dns_name(data, start, end)
        if consumed != end:
            raise _DecodeError("Invalid DNS name record length")
        return name
    if record_type in (15, 33):
        prefix_size = 2 if record_type == 15 else 6
        if len(value) <= prefix_size:
            raise _DecodeError("Incomplete DNS MX or SRV record")
        name, consumed = _dns_name(data, start + prefix_size, end)
        if consumed != end:
            raise _DecodeError("Invalid DNS MX or SRV record length")
        numbers = " ".join(str(_u16(value, i)) for i in range(0, prefix_size, 2))
        return f"{numbers} {name}"
    if record_type == 16:
        parts = []
        position = 0
        while position < len(value) and len(parts) < 16:
            next_position = position + 1 + value[position]
            if next_position > len(value):
                raise _DecodeError("Incomplete DNS TXT value")
            parts.append(_wire_text(value[position + 1 : next_position]))
            position = next_position
        return " ".join(parts) + (" ..." if position < len(value) else "")
    return value[:32].hex(" ") + (" ..." if len(value) > 32 else "")


def parse_dns(data: bytes) -> ApplicationMessage | None:
    if len(data) < 12:
        return None
    identifier, flags, questions, answers, authorities, additional = struct.unpack_from("!6H", data)
    response = bool(flags & 0x8000)
    title = "DNS Response" if response else "DNS Query"
    fields = [
        MessageField("dns.id", "Transaction ID", identifier, 0, 2, f"{identifier:#06x}"),
        MessageField("dns.flags", "Flags", flags, 2, 2, f"{flags:#06x}"),
        MessageField("dns.response", "Message type", int(response), 2, 2, "Response" if response else "Query"),
        MessageField("dns.rcode", "Response code", flags & 15, 2, 2),
        MessageField("dns.questions", "Questions", questions, 4, 2),
        MessageField("dns.answers", "Answers", answers, 6, 2),
        MessageField("dns.authority", "Authority records", authorities, 8, 2),
        MessageField("dns.additional", "Additional records", additional, 10, 2),
    ]
    offset, entries = 12, 0
    note = None
    try:
        for section, count in (("Question", questions), ("Answer", answers), ("Authority", authorities), ("Additional", additional)):
            for _ in range(count):
                if entries >= _MAX_DNS_RECORDS:
                    return ApplicationMessage("DNS", title, tuple(fields), "DNS record display limit reached")
                entries += 1
                name_start = offset
                name, offset = _dns_name(data, offset, len(data))
                if section == "Question":
                    fields.append(MessageField("dns.qname", "Question name", name, name_start, offset - name_start))
                    if offset + 4 > len(data):
                        raise _DecodeError("Incomplete DNS question")
                    record_type, record_class = struct.unpack_from("!HH", data, offset)
                    fields.append(MessageField("dns.qtype", "Question type", record_type, offset, 2, _dns_type(record_type)))
                    fields.append(MessageField("dns.qclass", "Question class", record_class, offset + 2, 2))
                    offset += 4
                else:
                    fields.append(MessageField("dns.rr.name", f"{section} name", name, name_start, offset - name_start))
                    if offset + 10 > len(data):
                        raise _DecodeError("Incomplete DNS resource record")
                    record_type, record_class, ttl, size = struct.unpack_from("!HHIH", data, offset)
                    fields.append(MessageField("dns.rr.type", f"{section} type", record_type, offset, 2, _dns_type(record_type)))
                    fields.append(MessageField("dns.rr.class", f"{section} class", record_class, offset + 2, 2))
                    fields.append(MessageField("dns.rr.ttl", f"{section} TTL", ttl, offset + 4, 4))
                    start, end = offset + 10, offset + 10 + size
                    if end > len(data):
                        raise _DecodeError("Incomplete DNS resource data")
                    if size:
                        value = _dns_rdata(data, start, end, record_type)
                        fields.append(MessageField("dns.rr.data", f"{section} data", value, start, size))
                    offset = end
    except _DecodeError as error:
        note = str(error)
    return ApplicationMessage("DNS", title, tuple(fields), note)


def scan_tcp_dns(data: bytes) -> tuple[ApplicationMessage, ...]:
    offset = 0
    messages = []
    while offset < len(data) and len(messages) < _MAX_MESSAGES:
        if offset + 2 > len(data):
            messages.append(ApplicationMessage("DNS", "DNS over TCP", note="Incomplete DNS length prefix"))
            break
        size = _u16(data, offset)
        offset += 2
        if size < 12 or offset + size > len(data):
            note = "Incomplete DNS over TCP message" if size >= 12 else "Invalid DNS over TCP message length"
            messages.append(ApplicationMessage("DNS", "DNS over TCP", note=note))
            break
        message = parse_dns(data[offset : offset + size])
        if message is not None:
            messages.append(message)
        offset += size
    return tuple(messages)


def _chunk_end(data: bytes, offset: int) -> int | None:
    while offset < len(data):
        line_end = data.find(b"\r\n", offset, offset + 1024)
        if line_end < 0:
            return None
        digits = data[offset:line_end].split(b";", 1)[0]
        if not re.fullmatch(rb"[0-9a-fA-F]{1,8}", digits):
            return None
        size = int(digits, 16)
        offset = line_end + 2
        if not size:
            if data.startswith(b"\r\n", offset):
                return offset + 2
            trailers = data.find(b"\r\n\r\n", offset)
            return trailers + 4 if trailers >= 0 else None
        offset += size
        if not data.startswith(b"\r\n", offset):
            return None
        offset += 2
    return None


def scan_http(data: bytes) -> tuple[ApplicationMessage, ...]:
    messages = []
    offset = 0
    while offset < len(data) and len(messages) < _MAX_MESSAGES:
        line_end = data.find(b"\r\n", offset, offset + _MAX_HTTP_HEADER)
        if line_end < 0:
            break
        line = data[offset:line_end]
        request, response = _HTTP_REQUEST.fullmatch(line), _HTTP_RESPONSE.fullmatch(line)
        if request is None and response is None:
            break
        status = None
        if request is not None:
            method, target, version = (_wire_text(part) for part in request.groups())
            title = f"HTTP {method} {target}"
            fields = [MessageField("http.version", "Version", version)]
        else:
            assert response is not None
            version, status_text, reason = response.groups()
            status = int(status_text)
            title = f"HTTP {status} {_wire_text(reason or b'')}".rstrip()
            fields = [MessageField("http.version", "Version", _wire_text(version))]

        header_end = data.find(b"\r\n\r\n", line_end, offset + _MAX_HTTP_HEADER)
        if header_end < 0:
            messages.append(ApplicationMessage("HTTP", title, tuple(fields), "Incomplete HTTP headers or header limit reached"))
            break
        headers: dict[bytes, list[bytes]] = {}
        valid = True
        for entry in data[line_end + 2 : header_end].split(b"\r\n") if header_end > line_end else ():
            key, separator, value = entry.partition(b":")
            if not separator or not _HEADER_NAME.fullmatch(key):
                valid = False
                break
            headers.setdefault(key.lower(), []).append(value.strip(b" \t"))
        for key, label in ((b"host", "Host"), (b"content-type", "Content-Type"), (b"content-length", "Content-Length"),
                           (b"transfer-encoding", "Transfer-Encoding")):
            if key in headers:
                fields.append(MessageField(f"http.{key.decode()}", label, _wire_text(headers[key][0])))

        offset = header_end + 4
        note = None
        if not valid:
            note = "Invalid HTTP header line"
        elif status == 101:
            messages.append(ApplicationMessage("HTTP", title, tuple(fields)))
            break
        elif status is not None and (status < 200 or status in (204, 304)):
            pass  # The response has no body.
        elif transfers := headers.get(b"transfer-encoding"):
            codings = b",".join(transfers).lower().split(b",")
            if codings[-1].strip() == b"chunked":
                next_offset = _chunk_end(data, offset)
                if next_offset is None:
                    note = "Incomplete or invalid HTTP chunked body"
                else:
                    offset = next_offset
            else:
                messages.append(ApplicationMessage("HTTP", title, tuple(fields)))
                break
        elif lengths := headers.get(b"content-length"):
            if len(set(lengths)) != 1 or not re.fullmatch(rb"[0-9]{1,10}", lengths[0]):
                note = "Invalid or conflicting HTTP Content-Length"
            else:
                offset += int(lengths[0])
                if offset > len(data):
                    note = "Incomplete HTTP body"
        elif status is not None:
            messages.append(ApplicationMessage("HTTP", title, tuple(fields)))
            break  # A close-delimited response fills this direction's remaining bytes.

        messages.append(ApplicationMessage("HTTP", title, tuple(fields), note))
        if note is not None:
            break
    return tuple(messages)


class _TlsReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def take(self, size: int) -> bytes:
        end = self.offset + size
        if end > len(self.data):
            raise _DecodeError("Incomplete TLS hello field")
        result = self.data[self.offset:end]
        self.offset = end
        return result

    def number(self, width: int) -> int:
        return int.from_bytes(self.take(width), "big")

    def vector(self, width: int) -> bytes:
        return self.take(self.number(width))

    @property
    def remaining(self) -> int:
        return len(self.data) - self.offset


def _tls_version(value: int) -> str:
    return _TLS_VERSIONS.get(value, f"{value:#06x}")


def _tls_extension(kind: int, data: bytes, client: bool) -> MessageField | None:
    reader = _TlsReader(data)
    if kind == 43:
        versions = reader.vector(1) if client else reader.take(2)
        if reader.remaining or not versions or len(versions) % 2:
            raise _DecodeError("Invalid TLS supported versions")
        display = ", ".join(_tls_version(_u16(versions, offset)) for offset in range(0, len(versions), 2))
        return MessageField("tls.versions", "Offered versions" if client else "Selected version", display)
    if kind == 0 and client:
        names = _TlsReader(reader.vector(2))
        while names.remaining:
            name_type = names.number(1)
            name = names.vector(2)
            if name_type == 0 and name:
                return MessageField("tls.sni", "Visible server name", _wire_text(name))
    if kind == 16:
        protocols = _TlsReader(reader.vector(2))
        names = []
        while protocols.remaining and len(names) < 16:
            names.append(_wire_text(protocols.vector(1)))
        return MessageField("tls.alpn", "ALPN", ", ".join(names))
    return None


def _tls_hello(body: bytes, client: bool) -> ApplicationMessage:
    title = "TLS ClientHello" if client else "TLS ServerHello"
    reader = _TlsReader(body)
    fields = []
    note = None
    try:
        version = reader.number(2)
        fields.append(MessageField("tls.legacy_version", "Legacy hello version", _tls_version(version)))
        reader.take(32)
        reader.vector(1)  # Session ID
        if client:
            suites = reader.vector(2)
            if not suites or len(suites) % 2:
                raise _DecodeError("Invalid TLS cipher suite list")
            fields.append(MessageField("tls.cipher_count", "Offered cipher suites", len(suites) // 2))
            reader.vector(1)  # Compression methods
        else:
            fields.append(MessageField("tls.cipher", "Selected cipher suite", f"{reader.number(2):#06x}"))
            reader.take(1)
        if reader.remaining:
            extensions = _TlsReader(reader.vector(2))
            while extensions.remaining:
                kind = extensions.number(2)
                field = _tls_extension(kind, extensions.vector(2), client)
                if field is not None:
                    fields.append(field)
        if not client and not any(field.key == "tls.versions" for field in fields):
            fields.append(MessageField("tls.versions", "Selected version", _tls_version(version)))
    except _DecodeError as error:
        note = str(error)
    return ApplicationMessage("TLS", title, tuple(fields), note)


def scan_tls(data: bytes) -> tuple[ApplicationMessage, ...]:
    if len(data) < 3 or data[0] != 22 or data[1] != 3 or data[2] > 4:
        return ()
    messages = []
    pending = bytearray()
    offset = 0
    while offset + 5 <= len(data) and len(messages) < _MAX_MESSAGES:
        record_type, major, minor = data[offset : offset + 3]
        size = _u16(data, offset + 3)
        if major != 3 or minor > 4 or size > 16384 or record_type not in (20, 22):
            break
        end = offset + 5 + size
        if end > len(data):
            break
        if record_type == 22:
            pending.extend(data[offset + 5 : end])
            used = 0
            while used + 4 <= len(pending) and len(messages) < _MAX_MESSAGES:
                kind = pending[used]
                length = int.from_bytes(pending[used + 1 : used + 4], "big")
                last = used + 4 + length
                if last > len(pending):
                    break
                if kind in (1, 2):
                    messages.append(_tls_hello(bytes(pending[used + 4 : last]), kind == 1))
                used = last
            del pending[:used]
        offset = end
    if not messages:
        messages.append(ApplicationMessage("TLS", "TLS handshake", note="Complete ClientHello or ServerHello not observed"))
    return tuple(messages)
