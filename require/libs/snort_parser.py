import json
import logging
import os
import socket
import time
from datetime import datetime

import dpkt
import paho.mqtt.client as mqtt
from csv_logger import CsvLogger
from dpkt.ethernet import Ethernet
from snortunsock import snort_listener
from snortunsock.alert import AlertPkt

list_protocol = ["HOPOPT", "ICMP", "IGMP", "GGP", "IP-in-IP", "ST", "TCP", "CBT", "EGP", "IGP", "BBN-RCC-MON",
                 "NVP-II", "PUP", "ARGUS", "EMCON", "EXNET", "CHAOS", "UDP", "MUX", "DCN-MEAS", "HMP", "PRM",
                 "XNS-IDP", "TRUNK-1", "TRUNK-2", "LEAF-1", "LEAF-2", "RDP", "IRTP", "ISO-TP4", "NETBLT", "MFE-NSP",
                 "MERIT-INP", "DCCP", "3PC", "IDPR", "XTP", "DDP", "IDPR-CMTP", "TP++", "IL", "IPv6", "SDRP",
                 "IPv6-Route", "IPv6-Frag", "IDRP", "RSVP", "GREs", "DSR", "BNA", "ESP", "AH", "I-NLSP", "SWIPE",
                 "NARP", "MOBILE", "TLSP", "SKIP", "IPv6-ICMP", "IPv6-NoNxt", "IPv6-Opts", "Host Internal Protocol",
                 "CFTP", "Any Local Network", "SAT-EXPAK", "KRYPTOLAN", "RVD", "IPPC",
                 "Any Distributed File System", "SAT-MON", "VISA", "IPCU", "CPNX", "CPHB", "WSN", "PVP",
                 "BR-SAT-MON", "SUN-ND", "WB-MON", "WB-EXPAK", "ISO-IP", "VMTP", "SECURE-VMTP", "VINES",
                 "TTP/IPTMP", "NSFNET-IGP", "DGP", "TCF", "EIGRP", "OSPF", "Sprite-RPC", "LARP", "MTP", "AX.25",
                 "OS", "MICP", "SCC-SP", "ETHERIP", "ENCAP", "Any Private Encryption Scheme", "GMTP", "IFMP",
                 "PNNI", "PIM", "ARIS", "SCPS", "QNX", "A/N", "IPComp", "SNP", "Compaq-Peer", "IPX-in-IP", "VRRP",
                 "PGM", "Any 0-hop Protocol", "L2TP", "DDX", "IATP", "STP", "SRP", "UTI", "SMP", "SM", "PTP",
                 "IS-IS over IPv4", "FIRE", "CRTP", "CRUDP", "SSCOPMCE", "IPLT", "SPS", "PIPE", "SCTP", "FC",
                 "RSVP-E2E-IGNORE", "Mobility Header", "UDPLite", "MPLS-in-IP", "manet", "HIP", "Shim6", "WESP",
                 "ROHC", "UNASSIGNED", "EXPERIMENT", "RESERVED"]


def mac_address(address: bytes):
    """Convert a MAC address to a readable/printable string
       Args:
           address (bytes): a MAC address in hex form (e.g. b'\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % ord(chr(int(x))) for x in address)


def ip_to_str(address):
    """Print out an IP address given a string
    Args:
        address (inet struct): inet network address
    Returns:
        str: Printable/readable IP address
    """
    return socket.inet_ntop(socket.AF_INET, address)


def ip6_to_str(address):
    """Print out an IPv6 address given a string
    Args:
        address (inet struct): inet network address
    Returns:
        str: Printable/readable IPv6 address
    """
    return socket.inet_ntop(socket.AF_INET6, address)


def get_protocol_from_id(protocol_id: int) -> str:
    """Get protocol name from protocol id
    Args:
        protocol_id (int): protocol id from snort
    Returns:
        str: Protocol name
    """
    if protocol_id == 255:
        return list_protocol[145]

    if 254 >= protocol_id >= 253:
        return list_protocol[144]

    if 252 >= protocol_id >= 143:
        return list_protocol[143]

    return list_protocol[protocol_id]


def get_ip_detail_from_ethernet_data(eth: Ethernet) -> dict:
    """Get ip value from Ethernet var
    Args:
        eth (Ethernet): Ethernet var
    Returns:
        dict: source, destination, packet_info
    """
    ethernet_data = eth.data
    protocol = get_protocol_from_id(ethernet_data.p)

    source_mac_address = mac_address(eth.src)
    destination_mac_address = mac_address(eth.dst)

    if hasattr(ethernet_data.data, "sport"):
        source_port = ethernet_data.data.sport
    else:
        source_port = 0

    if hasattr(ethernet_data.data, "dport"):
        destination_port = ethernet_data.data.dport
    else:
        destination_port = 0

    if eth.type == dpkt.ethernet.ETH_TYPE_IP6:
        ip_type = "IPv6"
        packet_length = ethernet_data.plen
        source_ip = ip6_to_str(ethernet_data.src)
        destination_ip = ip6_to_str(ethernet_data.dst)

        hop_limit = ethernet_data.hlim
        packet_info = {"len": packet_length, "hop_limit": hop_limit}

    elif eth.type == dpkt.ethernet.ETH_TYPE_IP:
        ip_type = "IPv4"
        packet_length = ethernet_data.len
        source_ip = ip_to_str(ethernet_data.src)
        destination_ip = ip_to_str(ethernet_data.dst)
        do_not_fragment = bool(ethernet_data.off & dpkt.ip.IP_DF)
        more_fragments = bool(ethernet_data.off & dpkt.ip.IP_MF)
        fragment_offset = ethernet_data.off & dpkt.ip.IP_OFFMASK
        ttl = ethernet_data.ttl

        packet_info = {"len": packet_length, "ttl": ttl, "DF": do_not_fragment, "MF": more_fragments,
                       "offset": fragment_offset}

    else:
        ip_type = "Unsupported"
        source_ip = "N/A"
        destination_ip = "N/A"

        packet_info = {"not_supported_packet": "IP Packet unsupported"}

    return {
        "source": {
            "mac_address": source_mac_address,
            "ip_address": source_ip,
            "port": source_port,
        },
        "destination": {
            "mac_address": destination_mac_address,
            "ip_address": destination_ip,
            "port": destination_port,
        },
        "ip_type": ip_type,
        "packet_info": packet_info,
        "protocol": protocol
    }


def get_snort_message(message: AlertPkt, company_name: str, device_id: str) -> dict:
    """Get snort message object from snort socket file
    Args:
        message (AlertPkt): Snort unix socket from snort listener
        company_name (str): Company Name/ID
        device_id (str): Device ID
    Returns:
        dict: Snort message
    """
    alert_message = b'.'.join(message.alertmsg)
    alert_message = (str(alert_message, 'utf-8').replace("\u0000", "")).replace("'", "")
    packet = message.pkt
    event = message.event
    ethernet = dpkt.ethernet.Ethernet(packet)

    ip_detail = get_ip_detail_from_ethernet_data(ethernet)

    return {
        "timestamp": str(time.time()),
        "alert_msg": str(alert_message),
        "company": company_name,
        "device_id": device_id,
        "sig_gen": event.sig_generator,
        "sig_id": event.sig_id,
        "sig_rev": event.sig_rev,
        "classification": event.classification,
        "priority": event.priority,
        "protocol": ip_detail["protocol"],
        "ip_type": ip_detail["ip_type"],
        "packet_info": ip_detail["packet_info"],
        "src_mac": ip_detail["destination"]["mac_address"],
        "src_ip": ip_detail["source"]["ip_address"],
        "src_port": ip_detail["source"]["port"],
        "dest_mac": ip_detail["destination"]["mac_address"],
        "dest_ip": ip_detail["destination"]["ip_address"],
        "dst_port": ip_detail["destination"]["port"]
    }


if __name__ == '__main__':
    LOG_HEADER = ["timestamp", "sig_gen", "sig_id", "sig_rev", "alert_msg", "protocol", "src_ip", "src_port", "dest_ip",
                  "dst_port", "src_mac", "dest_mac"]
    FORMAT = '%(timestamp)s;%(sig_gen)s;%(sig_id)s;%(sig_rev)s;%(alert_msg)s;%(protocol)s;%(src_ip)s;%(src_port)s;' \
             '%(dest_ip)s;%(dst_port)s;%(src_mac)s;%(dest_mac)s'
    DATE_FORMAT = '%Y/%m/%d %H:%M:%S'
    # logging.basicConfig(format=FORMAT, level=logging.DEBUG)
    logger = logging.getLogger(__name__)

    log_path = os.getenv('LOG_PATH', "/var/log/mataelang-sensor/snort.csv")

    # Reference: http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node21.html#SECTION00364000000000000000
    log_csv_handler = CsvLogger(
        filename=log_path,
        fmt=FORMAT,
        level=logging.DEBUG,
        add_level_nums=None,
        max_size=(128 * 1024 * 1024),
        max_files=14,
        header=LOG_HEADER,
        datefmt=DATE_FORMAT
    )

    logger.addHandler(log_csv_handler)

    mqtt_broker_host = os.getenv('ALERT_MQTT_SERVER', None)
    mqtt_broker_port = os.getenv('ALERT_MQTT_PORT', 1883)
    mqtt_topic = os.getenv('ALERT_MQTT_TOPIC', 'snoqttv5')
    me_device_id = os.getenv('DEVICE_ID', None)
    me_company = os.getenv('COMPANY', None)

    snort_mqtt = mqtt.Client()
    snort_mqtt.connect(mqtt_broker_host, mqtt_broker_port)
    snort_mqtt.loop_start()

    for snort_alert_message in snort_listener.start_recv("/var/log/snort/snort_alert"):
        snort_message = get_snort_message(snort_alert_message, me_company, me_device_id)
        timestamp_h = datetime.fromtimestamp(float(snort_message["timestamp"])).strftime(DATE_FORMAT)
        logger.warning(f"{timestamp_h} Alert Message: {snort_message['alert_msg']}", extra=snort_message)

        snort_mqtt.publish(mqtt_topic, json.dumps(snort_message))
