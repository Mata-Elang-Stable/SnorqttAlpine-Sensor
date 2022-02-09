import random
import socket

from require.libs.snort_parser import mac_address, ip_to_str, ip6_to_str, get_protocol_from_id, \
    get_ip_detail_from_ethernet_data, get_snort_message, list_protocol


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


from scapy.all import Ether, IP, ICMP, raw, hexdump, TCP, IPv6
import dpkt
from dpkt.ethernet import Ethernet
import socket

def test_get_ip_detail_from_ethernet_data():
    ## Input Variable
    ip_type = 'IPv6'
    src_mac_addr = '74:c6:3b:c9:53:5f'
    dst_mac_addr = '74:c6:3b:c9:53:5f'
    port_src = 123
    port_dst = 80
    len_value = 64
    ttl_value = 64

    # Automatic value created when create the packet
    hop_value = 64 
    DF_bool = False # Using Non Fragmented Packet
    MF_bool = False # Using Non Fragmented Packet
    offset_value = 0 # Using Non Fragmented Packet
    protocol = 'TCP'

    # Cretae Non Fragmented Packet TCP protocol
    if(ip_type == 'IPv4'):
        ip_src = '192.168.1.18'
        ip_dst = '192.168.1.16'
        a = Ether(src=src_mac_addr, dst=dst_mac_addr)/IP(src=ip_src ,dst=ip_dst, len=len_value, ttl=ttl_value)/TCP(sport=port_src, dport=port_dst)
        packet_info = {'len': len_value, 'ttl': ttl_value, 'DF': DF_bool, 'MF': MF_bool, 'offset': offset_value}
    elif(ip_type == 'IPv6'):
        ip_src = '2001:db8:3333:4444:5555:6666:7777:8888'
        ip_dst = '2001:db8:3333:4444:5555:6666:7777:2222'
        a = Ether(src=src_mac_addr, dst=dst_mac_addr)/IPv6(src=ip_src, dst=ip_dst, plen=len_value)/TCP(sport=port_src, dport=port_dst)
        packet_info = {'len': len_value, 'hop_limit': hop_value}
        
    b = raw(a)
    eth = dpkt.ethernet.Ethernet(b)

    expected_result = {
        "source": {
            "mac_address": src_mac_addr,
            "ip_address": ip_src,
            "port": port_src,
        },
        "destination": {
            "mac_address": dst_mac_addr,
            "ip_address": ip_dst,
            "port": port_dst,
        },
        "ip_type": ip_type,
        "packet_info": packet_info,
        "protocol": protocol
    }
    
    assert get_ip_detail_from_ethernet_data(eth) == expected_result


def test_get_snort_message():
    company_name = 'mata elang'
    device_id = 'a001'

    
    pass
