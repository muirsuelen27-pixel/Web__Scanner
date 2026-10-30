"""Estados TLS no ambiguos."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ProtocolProbe:
    protocol: str
    remote: str
    local_probe: str

    def label(self) -> str:
        return f'{self.protocol}: Remote: {self.remote} | Local probe: {self.local_probe}'


def unavailable_protocol(protocol: str) -> ProtocolProbe:
    return ProtocolProbe(protocol, 'Not tested', 'unavailable')
