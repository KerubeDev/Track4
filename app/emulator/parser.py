import re
from dataclasses import dataclass
from datetime import datetime

_LINE_RE = re.compile(
    r"^(?P<ts>\d{2}-[A-Z][a-z]{2}-\d{4} \d{2}:\d{2}:\d{2}\.\d{3}) "
    r"queries: info: client @0x[0-9a-f]+ "
    r"(?P<client_ip>\d{1,3}(?:\.\d{1,3}){3})#(?P<client_port>\d+) "
    r"\(.*?\): query: (?P<qname>[^ ]+) (?P<qclass>[A-Z]+) (?P<qtype>[A-Z0-9]+)"
    r".*\((?P<resolver>\d{1,3}(?:\.\d{1,3}){3})\)$"
)

_TS_FMT = "%d-%b-%Y %H:%M:%S.%f"

_UNESCAPE = [(r"\(", "("), (r"\)", ")"), (r"\\", "\\")]


class ParseError(ValueError):
    pass


@dataclass(frozen=True)
class QueryRecord:
    timestamp: datetime
    client_ip: str
    client_port: int
    qname: str
    qtype: str
    resolver_ip: str
    source_file: str


def parse_timestamp(value: str) -> datetime:
    return datetime.strptime(value, _TS_FMT)


def parse_line(line: str, source_file: str) -> QueryRecord:
    line = line.rstrip("\n")
    m = _LINE_RE.match(line)
    if not m:
        raise ParseError(f"unparsable line: {line!r}")
    qname = m.group("qname")
    for escaped, plain in _UNESCAPE:
        qname = qname.replace(escaped, plain)
    return QueryRecord(
        timestamp=parse_timestamp(m.group("ts")),
        client_ip=m.group("client_ip"),
        client_port=int(m.group("client_port")),
        qname=qname.lower(),
        qtype=m.group("qtype"),
        resolver_ip=m.group("resolver"),
        source_file=source_file,
    )


def iter_file(path: str, source_file: str | None = None):
    source = source_file or path
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                continue
            yield parse_line(line, source)


def load_dataset(paths):
    for path in paths:
        yield from iter_file(path)