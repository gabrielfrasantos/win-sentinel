"""Packet capture with a raw socket (stdlib, no Wireshark/Npcap): which internet hosts
this PC sends traffic to and which names it looks up, during a short window.

Windows lets an administrator put a raw IPv4 socket in promiscuous receive mode
(SIO_RCVALL) on one local address. Outgoing packets are counted by destination;
DNS questions (UDP port 53) are decoded for the names. Each capture is also saved
as a .pcap (raw IP link type) in captures/ for 14 days, so Wireshark can open it.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import logging
import socket
import struct
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from winsentinel import paths, winapi
from winsentinel.report import Context

logger = logging.getLogger(__name__)

RETENTION = dt.timedelta(days=14)
MAX_PCAP_BYTES = 50 * 1024 * 1024
LINKTYPE_RAW = 101
TCP, UDP = 6, 17


@dataclass
class CaptureSummary:
    seconds: int
    file: str = ""
    packets: int = 0
    destinations: list[tuple[str, int, int]] = field(default_factory=list)
    dns: list[tuple[str, int]] = field(default_factory=list)
    error: str = ""


@dataclass(frozen=True)
class Packet:
    src: str
    dst: str
    protocol: int
    src_port: int
    dst_port: int
    payload: bytes


def parse_ipv4(data: bytes) -> Packet | None:
    """The addresses, ports and payload of an IPv4 TCP/UDP packet; None otherwise."""
    if len(data) < 20 or data[0] >> 4 != 4:
        return None
    header = (data[0] & 0x0F) * 4
    protocol = data[9]
    src = socket.inet_ntoa(data[12:16])
    dst = socket.inet_ntoa(data[16:20])
    body = data[header:]
    if protocol == TCP and len(body) >= 20:
        sport, dport = struct.unpack("!HH", body[:4])
        offset = (body[12] >> 4) * 4
        return Packet(src, dst, protocol, sport, dport, body[offset:])
    if protocol == UDP and len(body) >= 8:
        sport, dport = struct.unpack("!HH", body[:4])
        return Packet(src, dst, protocol, sport, dport, body[8:])
    return Packet(src, dst, protocol, 0, 0, b"")


def dns_questions(payload: bytes) -> list[str]:
    """Names asked for in a DNS query message (responses are ignored)."""
    if len(payload) < 12:
        return []
    flags, count = struct.unpack("!HH", payload[2:6])
    if flags & 0x8000:
        return []
    names: list[str] = []
    pos = 12
    for _ in range(min(count, 8)):
        labels: list[str] = []
        while pos < len(payload):
            length = payload[pos]
            if length == 0:
                pos += 1
                break
            if length & 0xC0:
                return names
            labels.append(payload[pos + 1 : pos + 1 + length].decode("ascii", "replace"))
            pos += 1 + length
        else:
            return names
        pos += 4
        if labels:
            names.append(".".join(labels).lower())
    return names


def is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global and not addr.is_multicast


class Tally:
    """Counts outgoing destinations and DNS names from a stream of raw packets."""

    def __init__(self, local_ip: str) -> None:
        self.local_ip = local_ip
        self.packets = 0
        self.destinations: Counter[tuple[str, int]] = Counter()
        self.names: Counter[str] = Counter()

    def add(self, data: bytes) -> None:
        packet = parse_ipv4(data)
        if packet is None:
            return
        self.packets += 1
        if packet.src != self.local_ip:
            return
        if is_public(packet.dst):
            self.destinations[(packet.dst, packet.dst_port)] += 1
        if packet.protocol == UDP and packet.dst_port == 53:
            for name in dns_questions(packet.payload):
                self.names[name] += 1

    def summary(self, seconds: int) -> CaptureSummary:
        return CaptureSummary(
            seconds,
            packets=self.packets,
            destinations=[(ip, port, n) for (ip, port), n in self.destinations.most_common()],
            dns=self.names.most_common(),
        )


def pcap_header() -> bytes:
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_RAW)


def pcap_record(data: bytes, when: float) -> bytes:
    seconds = int(when)
    micros = int((when - seconds) * 1_000_000)
    return struct.pack("<IIII", seconds, micros, len(data), len(data)) + data


def _prune(folder: Path) -> None:
    cutoff = time.time() - RETENTION.total_seconds()
    for old in folder.glob("capture-*.pcap"):
        try:
            if old.stat().st_mtime < cutoff:
                old.unlink()
        except OSError as e:
            logger.debug("Could not prune %s: %s", old, e)


def _open_socket(local_ip: str) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    try:
        s.bind((local_ip, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        s.settimeout(0.5)
    except OSError:
        s.close()
        raise
    return s


def _record(sock: socket.socket, seconds: int, tally: Tally, out: BinaryIO, ctx: Context) -> None:
    written = 0
    started = time.monotonic()
    last_report = 0.0
    while (elapsed := time.monotonic() - started) < seconds and not ctx.stopped:
        if elapsed - last_report >= 1:
            last_report = elapsed
            ctx.progress(
                f"Capturing network traffic ({elapsed:.0f}/{seconds} s)...", elapsed / seconds
            )
        try:
            data = sock.recv(65535)
        except TimeoutError:
            continue
        tally.add(data)
        if written < MAX_PCAP_BYTES:
            record = pcap_record(data, time.time())
            out.write(record)
            written += len(record)


def capture(seconds: int, local_ip: str, ctx: Context) -> CaptureSummary:
    """Capture ``seconds`` of traffic on the interface that owns ``local_ip``."""
    if not winapi.WINDOWS:
        return CaptureSummary(seconds, error="packet capture needs Windows")
    if not winapi.is_admin():
        return CaptureSummary(seconds, error="packet capture needs administrator")
    if not local_ip:
        return CaptureSummary(seconds, error="packet capture: no network connection")
    folder = paths.captures_dir()
    pcap = folder / f"capture-{dt.datetime.now():%Y%m%d-%H%M%S}.pcap"
    tally = Tally(local_ip)
    try:
        sock = _open_socket(local_ip)
    except OSError as e:
        return CaptureSummary(seconds, error=f"packet capture unavailable: {e}")
    ctx.progress(f"Capturing network traffic for {seconds} s...", 0.0)
    try:
        with pcap.open("wb") as out:
            out.write(pcap_header())
            _record(sock, seconds, tally, out, ctx)
    except OSError as e:
        return CaptureSummary(seconds, error=f"packet capture failed: {e}")
    finally:
        try:
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except OSError:
            pass
        sock.close()
    summary = tally.summary(seconds)
    summary.file = str(pcap)
    _prune(folder)
    logger.info(
        "Capture: %d packets, %d destinations, %d DNS names",
        summary.packets,
        len(summary.destinations),
        len(summary.dns),
    )
    return summary
