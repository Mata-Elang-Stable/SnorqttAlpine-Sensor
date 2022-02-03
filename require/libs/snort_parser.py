from typing import Tuple
import dpkt
import socket
import paho.mqtt.client as mqtt
import json
import os
import time
from snortunsock import snort_listener
from dpkt.ethernet import Ethernet
from snortunsock.alert import AlertPkt

# MQTT = os.environ['ALERT_MQTT_SERVER']
# topic = os.environ['ALERT_MQTT_TOPIC']
# device_id = os.environ['DEVICE_ID']
# company = os.environ['COMPANY']

MQTT = "192.168.0.120"
topic = "snoqttv5"
device_id = "a456uq"
company = "Home"

snort_mqtt = mqtt.Client()
snort_mqtt.connect(str(MQTT))
snort_mqtt.loop_start()


def mac_addr(address):
    """Convert a MAC address to a readable/printable string
       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % ord(chr(x)) for x in address)


def test_mac_addr():
    # TODO: create unit test for mac_addr() function
    assert mac_addr(b't\xc6;\xc9S_') == '74:c6:3b:c9:53:5f'


def ip_to_str(address):
    """Print out an IP address given a string
    Args:
        address (inet struct): inet network address
    Returns:
        str: Printable/readable IP address
    """
    return socket.inet_ntop(socket.AF_INET, address)

def test_ip_to_str():
    # TODO: create unit test for ip_to_str() function
    ipv4_address_str = '192.168.0.41'
    ipv4_address_bytes = socket.inet_pton(socket.AF_INET, ipv4_address_str)

    assert ip_to_str(ipv4_address_bytes) == '192.168.0.42'

def ip6_to_str(address):
    """Print out an IPv6 address given a string
    Args:
        address (inet struct): inet network address
    Returns:
        str: Printable/readable IPv6 address
    """
    return socket.inet_ntop(socket.AF_INET6, address)

def test_ip6_to_str():
    # TODO: create unit test for ip6_to_str() function
    ipv6_address_str = '2001:db8:3333:4444:5555:6666:7777:8888'
    ipv6_address_bytes = socket.inet_pton(socket.AF_INET6, ipv6_address_str)
    
    assert ip6_to_str(ipv6_address_bytes) == ipv6_address_str


def get_protocol_from_id(protocol_id: int) -> str:
    """Get protocol name from protocol id
    Args:
        protocol_id (int): protocol id from snort
    Returns:
        str: Protocol name
    """
    # TODO: create get_protocol_from_id() function
    list_protocol = ["HOPOPT","ICMP","IGMP","GGP","IP-in-IP","ST","TCP","CBT","EGP","IGP","BBN-RCC-MON", "NVP-II","PUP","ARGUS","EMCON","EXNET","CHAOS","UDP","MUX","DCN-MEAS","HMP","PRM","XNS-IDP","TRUNK-1","TRUNK-2","LEAF-1","LEAF-2","RDP","IRTP","ISO-TP4","NETBLT","MFE-NSP","MERIT-INP","DCCP","3PC","IDPR","XTP","DDP","IDPR-CMTP","TP++","IL","IPv6","SDRP","IPv6-Route","IPv6-Frag","IDRP","RSVP","GREs","DSR","BNA","ESP","AH","I-NLSP","SWIPE","NARP","MOBILE","TLSP","SKIP","IPv6-ICMP","IPv6-NoNxt","IPv6-Opts","Host Internal Protocol","CFTP","Any Local Network","SAT-EXPAK","KRYPTOLAN","RVD","IPPC","Any Distributed File System","SAT-MON","VISA","IPCU","CPNX","CPHB","WSN","PVP","BR-SAT-MON","SUN-ND","WB-MON","WB-EXPAK","ISO-IP","VMTP","SECURE-VMTP","VINES","TTP/IPTMP","NSFNET-IGP","DGP","TCF","EIGRP","OSPF","Sprite-RPC","LARP","MTP","AX.25","OS","MICP","SCC-SP","ETHERIP","ENCAP","Any Private Encryption Scheme","GMTP","IFMP","PNNI","PIM","ARIS","SCPS","QNX","A/N","IPComp","SNP","Compaq-Peer","IPX-in-IP","VRRP","PGM","Any 0-hop Protocol","L2TP","DDX","IATP","STP","SRP","UTI","SMP","SM","PTP","IS-IS over IPv4","FIRE","CRTP","CRUDP","SSCOPMCE","IPLT","SPS","PIPE","SCTP","FC","RSVP-E2E-IGNORE","Mobility Header","UDPLite","MPLS-in-IP","manet","HIP","Shim6","WESP","ROHC","UNASSIGNED","EXPERIMENT","RESERVED"]

    if protocol_id == 255 :
        return list_protocol[145]
    
    if protocol_id <= 254 and protocol_id >= 253 :
        return list_protocol[144]
    
    if protocol_id <= 252 and protocol_id >= 143 :
        return list_protocol[143]
        
    return list_protocol[protocol_id]

def test_get_protocol_from_id():
    list_protocol = ["HOPOPT","ICMP","IGMP","GGP","IP-in-IP","ST","TCP","CBT","EGP","IGP","BBN-RCC-MON", "NVP-II","PUP","ARGUS","EMCON","EXNET","CHAOS","UDP","MUX","DCN-MEAS","HMP","PRM","XNS-IDP","TRUNK-1","TRUNK-2","LEAF-1","LEAF-2","RDP","IRTP","ISO-TP4","NETBLT","MFE-NSP","MERIT-INP","DCCP","3PC","IDPR","XTP","DDP","IDPR-CMTP","TP++","IL","IPv6","SDRP","IPv6-Route","IPv6-Frag","IDRP","RSVP","GREs","DSR","BNA","ESP","AH","I-NLSP","SWIPE","NARP","MOBILE","TLSP","SKIP","IPv6-ICMP","IPv6-NoNxt","IPv6-Opts","Host Internal Protocol","CFTP","Any Local Network","SAT-EXPAK","KRYPTOLAN","RVD","IPPC","Any Distributed File System","SAT-MON","VISA","IPCU","CPNX","CPHB","WSN","PVP","BR-SAT-MON","SUN-ND","WB-MON","WB-EXPAK","ISO-IP","VMTP","SECURE-VMTP","VINES","TTP/IPTMP","NSFNET-IGP","DGP","TCF","EIGRP","OSPF","Sprite-RPC","LARP","MTP","AX.25","OS","MICP","SCC-SP","ETHERIP","ENCAP","Any Private Encryption Scheme","GMTP","IFMP","PNNI","PIM","ARIS","SCPS","QNX","A/N","IPComp","SNP","Compaq-Peer","IPX-in-IP","VRRP","PGM","Any 0-hop Protocol","L2TP","DDX","IATP","STP","SRP","UTI","SMP","SM","PTP","IS-IS over IPv4","FIRE","CRTP","CRUDP","SSCOPMCE","IPLT","SPS","PIPE","SCTP","FC","RSVP-E2E-IGNORE","Mobility Header","UDPLite","MPLS-in-IP","manet","HIP","Shim6","WESP","ROHC","UNASSIGNED","EXPERIMENT","RESERVED"]
    i = 0
    protocol = ""
    while(i<256):
        if i == 255 :
            protocol = list_protocol[145]
        elif i <= 254 and protocol_id >= 253 :
            protocol = list_protocol[144]
        elif i <= 252 and protocol_id >= 143 :
            protocol = list_protocol[143]
        else:
            protocol = list_protocol[i]

        assert get_protocol_from_id(i) == protocol

def get_port_from_ethernet_data(eth: Ethernet) -> Tuple(int, int):
    """Get port value from Ethernet var, return 0 if throw an AttributeError exception
    Args:
        eth (Ethernet): Ethernet var
    Returns:
        int: Port
    """
    # TODO: create get_port_from_ethernet_data() function
    dst_port = 0
    src_port = 0

    try:
        eth.data.data.dport
    except AttributeError:
        dst_port = 0
    else:
        dst_port = eth.data.data.dport

    try:
        eth.data.data.sport
    except AttributeError:
        src_port = 0
    else:
        src_port = eth.data.data.sport

    return src_port, dst_port

def test_get_port_from_ethernet_data():
    # TODO: create unit test for test_get_port_from_ethernet_data() function
    pass


def get_packet_info_from_ethernet_data(eth: Ethernet) -> dict:
    """Get packet info from ethernet data
    Args:
        eth (Ethernet): Ethernet var
    Returns:
        dict: packet information
    """
    # TODO: create get_packet_info_from_ethernet_data() function
    ip = eth.data
    len = ip.len

    if eth.type == dpkt.ethernet.ETH_TYPE_IP6:
        hop_lim = ip.hlim
        return {"len": len, "hop_limit": hop_lim}

    elif eth.type == dpkt.ethernet.ETH_TYPE_IP:
        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        ttl = ip.ttl
        DF = do_not_fragment
        MF = more_fragments
        offset = fragment_offset
        return {"len": len, "ttl": ttl, "DF": DF, "MF": MF, "offset": offset}
    
    else:
        return {"not_supported_packet": "IP Packet unsupported"}

def test_get_packet_info_from_ethernet_data():
    # TODO: create unit test for get_packet_info_from_ethernet_data() function
    pass

def get_ip_detail_from_ethernet_data(eth: Ethernet) -> Tuple(str, str, str):
    """Get ip value from Ethernet var
    Args:
        eth (Ethernet): Ethernet var
    Returns:
        Tuple(str, str): ip, ip_type
    """
    # TODO: create get_ip_detail_from_ethernet_data() function
    pass

def test_get_ip_detail_from_ethernet_data():
    # TODO: create unit test for get_ip_detail_from_ethernet_data() function
    pass


def get_snort_message(message: AlertPkt) -> dict:
    """Get snort message object from snort socket file
    Args:
        message (AlertPkt): Snort unix socket from snort listener
    Returns:
        dict: Snort message
    """
    # TODO: create unit test for get_snort_message() function
    pass

def test_get_snort_message():
    # TODO: create unit test for get_snort_message() function
    pass

def main():
    snort_message = {}

    for msg in snort_listener.start_recv("/var/log/snort/snort_alert"):
        orig_msg = b'.'.join(msg.alertmsg)
        alert_message = (str(orig_msg, 'utf-8').replace("\u0000", "")).replace("'", "")
        buf = msg.pkt
        event = msg.event
        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        src_mac = mac_addr(eth.src)
        dest_mac = mac_addr(eth.dst)

        # Timestamp created when the rule generate alert
        snort_message["timestamp"] = str(time.time())
        snort_message["alert_msg"] = str(alert_message)
        snort_message["company"] = company
        snort_message["device_id"] = device_id
        snort_message["sig_gen"] = event.sig_generator
        snort_message["sig_id"] = event.sig_id
        snort_message["sig_rev"] = event.sig_rev
        snort_message["classification"] = event.classification
        snort_message["priority"] = event.priority
        snort_message["protocol"] = get_protocol_from_id(eth.data.p)
        snort_message["src_mac"] = src_mac
        snort_message["dest_mac"] = dest_mac

        try:
            eth.data.data.dport
        except AttributeError:
            snort_message["dst_port"] = 0
        else:
            snort_message["dst_port"] = eth.data.data.dport

        try:
            eth.data.data.sport
        except AttributeError:
            snort_message["src_port"] = 0
        else:
            snort_message["src_port"] = eth.data.data.sport

        print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)

        if eth.type == dpkt.ethernet.ETH_TYPE_IP6:

            ip_type = "IPv6"
            snort_message["ip_type"] = ip_type

            ip = eth.data
            src_ip = ip6_to_str(ip.src)
            dest_ip = ip6_to_str(ip.dst)
            len = ip.plen
            hop_lim = ip.hlim
            packet_info = {"len": len, "hop_limit": hop_lim}

            snort_message["src_ip"] = src_ip
            snort_message["dest_ip"] = dest_ip
            snort_message["packet_info"] = packet_info

            # Print out the info
            print('IP: %s -> %s   (len=%d hop_limit=%d)\n' % \
                  (ip6_to_str(ip.src), ip6_to_str(ip.dst), ip.plen, ip.hlim))


        # Now unpack the data within the Ethernet frame (the IP packet)
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        elif eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip_type = "IPv4"
            snort_message["ip_type"] = ip_type

            ip = eth.data

            # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
            do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
            more_fragments = bool(ip.off & dpkt.ip.IP_MF)
            fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

            src_ip = ip_to_str(ip.src)
            dest_ip = ip_to_str(ip.dst)
            len = ip.len
            ttl = ip.ttl
            DF = do_not_fragment
            MF = more_fragments
            offset = fragment_offset
            packet_info = {"len": len, "ttl": ttl, "DF": DF, "MF": MF, "offset": offset}

            snort_message["src_ip"] = src_ip
            snort_message["dest_ip"] = dest_ip
            snort_message["packet_info"] = packet_info

            # Print out the info
            #print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
            #      (ip_to_str(ip.src), ip_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments,
            #       fragment_offset))

        else:
            ip_type = "Unsupported"
            snort_message["ip_type"] = ip_type

            src_ip = "N/A"
            dest_ip = "N/A"
            packet_info = {"not_supported_packet": "IP Packet unsupported"}

            snort_message["src_ip"] = src_ip
            snort_message["dest_ip"] = dest_ip
            snort_message["packet_info"] = packet_info

            #print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)

        snort_mqtt.publish(topic, json.dumps(snort_message))


if __name__ == '__main__':
    main()
