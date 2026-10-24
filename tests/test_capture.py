import socket
import struct

from winsentinel import capture


def ipv4(src, dst, protocol, payload):
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        0,
        0,
        64,
        protocol,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    return header + payload


def udp(sport, dport, payload=b""):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(sport, dport):
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, 0x02, 0, 0, 0)


def dns_query(*names):
    body = struct.pack("!HHHHHH", 0x1234, 0x0100, len(names), 0, 0, 0)
    for name in names:
        for label in name.split("."):
            body += bytes([len(label)]) + label.encode()
        body += b"\x00" + struct.pack("!HH", 1, 1)
    return body


def test_parse_packets():
    p = capture.parse_ipv4(ipv4("192.168.1.10", "8.8.8.8", 17, udp(5353, 53, b"hi")))
    assert (p.src, p.dst, p.protocol, p.src_port, p.dst_port, p.payload) == (
        "192.168.1.10",
        "8.8.8.8",
        17,
        5353,
        53,
        b"hi",
    )
    t = capture.parse_ipv4(ipv4("192.168.1.10", "1.2.3.4", 6, tcp(50000, 3333)))
    assert t.dst_port == 3333
    assert capture.parse_ipv4(b"\x60" + b"\x00" * 39) is None


def test_dns_questions():
    assert capture.dns_questions(dns_query("pool.supportxmr.com", "example.org")) == [
        "pool.supportxmr.com",
        "example.org",
    ]
    response = bytearray(dns_query("example.org"))
    response[2] |= 0x80
    assert capture.dns_questions(bytes(response)) == []
    assert capture.dns_questions(b"\x00") == []


def test_tally_counts_outgoing_public_traffic_and_names():
    tally = capture.Tally("192.168.1.10")
    tally.add(ipv4("192.168.1.10", "1.2.3.4", 6, tcp(50000, 3333)))
    tally.add(ipv4("192.168.1.10", "1.2.3.4", 6, tcp(50000, 3333)))
    tally.add(ipv4("192.168.1.10", "192.168.1.1", 17, udp(5000, 53, dns_query("nanopool.org"))))
    tally.add(ipv4("1.2.3.4", "192.168.1.10", 6, tcp(3333, 50000)))
    summary = tally.summary(30)
    assert summary.packets == 4
    assert summary.destinations == [("1.2.3.4", 3333, 2)]
    assert summary.dns == [("nanopool.org", 1)]


def test_pcap_format():
    header = capture.pcap_header()
    assert struct.unpack("<IHHiIII", header)[0] == 0xA1B2C3D4
    assert struct.unpack("<IHHiIII", header)[-1] == capture.LINKTYPE_RAW
    record = capture.pcap_record(b"abc", 1.5)
    assert struct.unpack("<IIII", record[:16]) == (1, 500000, 3, 3)


def test_capture_off_windows_is_a_clear_error(monkeypatch):
    monkeypatch.setattr(capture.winapi, "WINDOWS", False)
    summary = capture.capture(5, "192.168.1.10", None)
    assert summary.error == "packet capture needs Windows"
