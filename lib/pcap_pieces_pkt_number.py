from scapy.all import *
from lib.validator import validate_packet_number
from scapy.error import Scapy_Exception

def pcap_packet_number(input_file):
    try:
        packets = rdpcap(input_file)
        return int(len(packets))
    except Scapy_Exception as e:
        return f"Exception: {e}"


def split_pcap_by_range_of_interval(input_file, output_prefix, packet_range_size):
    try:
        if int(packet_range_size):
            if validate_packet_number(int(packet_range_size), pcap_packet_number(input_file)):
                packets = rdpcap(input_file)
                msg = []
                for start in range(0, len(packets), int(packet_range_size)):
                    end = min(start + int(packet_range_size), len(packets))
                    
                    selected_packets = packets[start:end]
                    
                    output_file = f"{output_prefix}_{start}-{end-1}.pcap"
                    
                    for i, selected_packet in zip(range(start, end), selected_packets):
                        selected_packet.time = packets[i].time
                    wrpcap(output_file, selected_packets)
                    msg.append(f"Packets {start}-{end-1} saved to {output_file}")
                return msg
            else:
                return f"{packet_range_size} is not valid as total packet in {input_file} is {pcap_packet_number(input_file)}"
    except TypeError as e:
        return f"TypeError: {e}"
    except IndexError as e:
        return f"IndexError: {e}"
    except FileNotFoundError as e:
        return f"FileNotFoundError:{e}"
    except ValueError as e:
        return f"ValueError:{e}"



def split_pcap_by_packet_number(input_file, output_file, packet_number):
    try:
        if int(packet_number):
            output_file = f"{output_file}.pcap"
            packets = rdpcap(input_file)
            selected_packet = packets[int(packet_number)]
            wrpcap(output_file, selected_packet)
            return f"Packet {packet_number} saved to {output_file}"
    except TypeError as e:
        return f"TypeError: {e}"
    except IndexError as e:
        return f"IndexError: {e} {packet_number}"
    except FileNotFoundError as e:
        return f"FileNotFoundError:{e}"
    except ValueError as e:
        return f"ValueError:{e}"
    except Scapy_Exception as e:
        return f"Exception: {e}"


def split_pcap_by_range_packet(input_file, output_file, packet_number):
    try:
        if(list(packet_number)):
            output_file = f"{output_file}.pcap"
            packets = rdpcap(input_file)
            list(packet_number)
            packet_number.sort()
            selected_packets = [packets[i] for i in range(packet_number[0], packet_number[1]+1)]
            wrpcap(output_file, selected_packets)
            return f"Packet {packet_number[0]} to {packet_number[1]} saved to {output_file}"
    except TypeError as e:
        return f"TypeError: {e}"
    except IndexError as e:
        return f"IndexError: {e}"
    except FileNotFoundError as e:
        return f"FileNotFoundError:{e}"



    


