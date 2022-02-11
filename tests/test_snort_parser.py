import random
import socket

import dpkt
from scapy.all import raw
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

from require.libs.snort_parser import mac_address, ip_to_str, ip6_to_str, get_protocol_from_id, \
    get_ip_detail_from_ethernet_data, list_protocol


def test_mac_address():
    assert mac_address(b't\xc6;\xc9S_') == '74:c6:3b:c9:53:5f'


def test_ip_to_str():
    ipv4_address_str = '192.168.56.103'
    ipv4_address_bytes = socket.inet_pton(socket.AF_INET, ipv4_address_str)

    assert ip_to_str(ipv4_address_bytes) == ipv4_address_str


def test_ip6_to_str():
    ipv6_address_str = '2001:db8:3333:4444:5555:6666:7777:8888'
    ipv6_address_bytes = socket.inet_pton(socket.AF_INET6, ipv6_address_str)

    assert ip6_to_str(ipv6_address_bytes) == ipv6_address_str


def test_get_protocol_from_id_145_must_true():
    test_protocol_id = list_protocol[145]

    assert get_protocol_from_id(255) == test_protocol_id  # true


def test_get_protocol_from_id_145_must_false():
    test_protocol_id = list_protocol[145]

    assert get_protocol_from_id(250) != test_protocol_id  # false


def test_get_protocol_from_id_144_must_true():
    protocol_id = random.randint(253, 254)
    test_protocol_id = list_protocol[144]

    assert get_protocol_from_id(protocol_id) == test_protocol_id  # true


def test_get_protocol_from_id_144_must_false():
    protocol_id = random.randint(1, 200)
    test_protocol_id = list_protocol[144]

    assert get_protocol_from_id(protocol_id) != test_protocol_id  # false


def test_get_protocol_from_id_143_must_true():
    protocol_id = random.randint(143, 252)
    test_protocol_id = list_protocol[143]

    assert get_protocol_from_id(protocol_id) == test_protocol_id  # true


def test_get_protocol_from_id_143_must_false():
    protocol_id = random.randint(1, 142)
    test_protocol_id = list_protocol[143]

    assert get_protocol_from_id(protocol_id) != test_protocol_id  # false


def test_ipv4_get_ip_detail_from_ethernet_data():
    ip_type = 'IPv4'
    src_mac_address = '74:c6:3b:c9:53:5f'
    dst_mac_address = '74:c6:3b:c9:53:5f'
    port_src = random.randint(3000, 9000)
    port_dst = random.randint(20, 500)
    len_value = 64
    ttl_value = 64

    # Automatic value created when create the packet
    df_bool = False  # Using Non Fragmented Packet
    mf_bool = False  # Using Non Fragmented Packet
    offset_value = 0  # Using Non Fragmented Packet
    protocol_type = random.choice(['TCP', 'UDP'])

    # Create Non Fragmented Packet TCP protocol
    ip_src = '192.168.1.18'
    ip_dst = '192.168.1.16'
    ethernet = Ether(src=src_mac_address, dst=dst_mac_address)
    ip = IP(src=ip_src, dst=ip_dst, len=len_value, ttl=ttl_value)
    if protocol_type == 'TCP':
        protocol = TCP(sport=port_src, dport=port_dst)
    elif protocol_type == 'UDP':
        protocol = UDP(sport=port_src, dport=port_dst)
    else:
        protocol = TCP(sport=port_src, dport=port_dst)
        protocol_type = 'TCP'

    a = ethernet / ip / protocol
    packet_info = {'len': len_value, 'ttl': ttl_value, 'DF': df_bool, 'MF': mf_bool, 'offset': offset_value}

    b = raw(a)
    eth = dpkt.ethernet.Ethernet(b)

    expected_result = {
        "source": {
            "mac_address": src_mac_address,
            "ip_address": ip_src,
            "port": port_src,
        },
        "destination": {
            "mac_address": dst_mac_address,
            "ip_address": ip_dst,
            "port": port_dst,
        },
        "ip_type": ip_type,
        "packet_info": packet_info,
        "protocol": protocol_type
    }

    assert get_ip_detail_from_ethernet_data(eth) == expected_result


def test_ipv6_get_ip_detail_from_ethernet_data():
    ip_type = 'IPv6'
    src_mac_address = '74:c6:3b:c9:53:5f'
    dst_mac_address = '74:c6:3b:c9:53:5f'
    port_src = random.randint(3000, 9000)
    port_dst = random.randint(20, 500)
    len_value = 64

    # Automatic value created when create the packet
    hop_value = 64
    protocol_type = random.choice(['TCP', 'UDP'])

    # Create Non Fragmented Packet TCP protocol
    ip_src = '2001:db8:3333:4444:5555:6666:7777:8888'
    ip_dst = '2001:db8:3333:4444:5555:6666:7777:2222'
    ethernet = Ether(src=src_mac_address, dst=dst_mac_address)
    ip = IPv6(src=ip_src, dst=ip_dst, plen=len_value)
    if protocol_type == 'TCP':
        protocol = TCP(sport=port_src, dport=port_dst)
    elif protocol_type == 'UDP':
        protocol = UDP(sport=port_src, dport=port_dst)
    else:
        protocol = TCP(sport=port_src, dport=port_dst)
        protocol_type = 'TCP'

    a = ethernet / ip / protocol
    packet_info = {'len': len_value, 'hop_limit': hop_value}

    b = raw(a)
    eth = dpkt.ethernet.Ethernet(b)

    expected_result = {
        "source": {
            "mac_address": src_mac_address,
            "ip_address": ip_src,
            "port": port_src,
        },
        "destination": {
            "mac_address": dst_mac_address,
            "ip_address": ip_dst,
            "port": port_dst,
        },
        "ip_type": ip_type,
        "packet_info": packet_info,
        "protocol": protocol_type
    }

    assert get_ip_detail_from_ethernet_data(eth) == expected_result


def test_get_snort_message():
    pass
