"""Contratos DNS independientes de la presentación."""

from dataclasses import dataclass, field


@dataclass
class DNSRecords:
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)
    zone_transfer: str = 'Not tested'

    def to_dict(self) -> dict[str, object]:
        return {
            'A': self.a,
            'AAAA': self.aaaa,
            'MX': self.mx,
            'NS': self.ns,
            'TXT': self.txt,
            'zone_transfer': self.zone_transfer,
        }
