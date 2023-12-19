from scapy.all import rdpcap, wrpcap

def read_pcap_bytes(input_file):
    packets = rdpcap(input_file)
    pcap_bytes_list = []
    for i in range(0,len(packets)):
        pcap_bytes_list.append(packets[i].len)
    return set(pcap_bytes_list)

def split_pcap_by_all_byte(input_file, output_prefix):
    try:
        packets = rdpcap(input_file)
        pcap_bytes_list = []
        msg = []

        for i in range(0,len(packets)):
            pcap_bytes_list.append(int(packets[i].len))
        

        for byte in list(set(pcap_bytes_list)):
            selected_packets =[]
            output_file = f"{output_prefix}_{byte}.pcap"
            for pkt in range(len(packets)):
                if packets[pkt].len == byte:
                    selected_packets.append(packets[pkt])
            wrpcap(output_file, selected_packets)
            msg.append(f"Packets of {byte} saved to {output_file}")
        return msg
    except TypeError as e:
        return f"TypeError: {e}"
    except FileNotFoundError as e:
        return f"FileNotFoundError:{e}"


def split_pcap_by_byte(input_file, output_prefix, byte_for_file):
    try:
        if int(byte_for_file):
            packets = rdpcap(input_file)
            selected_packets =[]
            output_file = f"{output_prefix}_{byte_for_file}.pcap"
            for pkt in range(len(packets)):
                if packets[pkt].len == int(byte_for_file):
                    selected_packets.append(packets[pkt])
            if selected_packets:
                wrpcap(output_file, selected_packets)
                return f"Packets of byte {byte_for_file} saved to {output_file}"
            else:
                return f"Input file do not contain {byte_for_file} byte"
    except TypeError as e:
        return f"TypeError: {e}"
    except IndexError as e:
        return f"IndexError: {e}"
    except FileNotFoundError as e:
        return f"FileNotFoundError:{e}"
    except ValueError as e:
        return f"ValueError:{e}"


def split_pcap_by_range_byte(input_file, output_prefix, byte_range):
    try:
        if list(byte_range):
            pcap_bytes = list(read_pcap_bytes(input_file))
            pcap_bytes.sort()
            byte_range.sort()
            range_index_start = int()
            range_index_end = int()

            for index, byte in enumerate(pcap_bytes):
                if byte == byte_range[0]:
                    range_index_start = index
                elif byte == byte_range[1]:
                    range_index_end = index+1

            range_byte = pcap_bytes[range_index_start: range_index_end]
            packets = rdpcap(input_file)

            selected_packets =[]
            output_file = f"{output_prefix}.pcap"

            for byte in range_byte:
                for pkt in range(len(packets)):
                    if packets[pkt].len == byte:
                        selected_packets.append(packets[pkt])
            if selected_packets:
                wrpcap(output_file, selected_packets)
                return f"Packets of byte between {byte_range[0]} to {byte_range[1]} saved to {output_file}"
            else:
                return f"There is No packet between this range"
        else:
            return f"{byte_range} should be integer"
    except TypeError as e:
        return f"TypeError: {e}"
    except IndexError as e:
        return f"IndexError: {e}"
    except FileNotFoundError as e:
        return f"FileNotFoundError:{e}"
    except ValueError as e:
        return f"ValueError:{e}"