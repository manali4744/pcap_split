from scapy.all import rdpcap, wrpcap
from scapy.utils import EDecimal
from datetime import datetime
 

def split_pcap_by_time(input_pcap, output_prefix):

    try:
 
        read_pcap_file = rdpcap(input_pcap)
        
        packets_by_minute = {}

        msg = []
        
        for i in range(len(read_pcap_file)):
            data = read_pcap_file[i].time
            packet_time = datetime.utcfromtimestamp(float(str(data))).replace(microsecond=0)

            minute_key = packet_time.strftime("%Y-%m-%d %H:%M")
        
            if minute_key not in packets_by_minute:
                packets_by_minute[minute_key] = []
        
            packets_by_minute[minute_key].append(read_pcap_file[i])
        
        for minute_key, packets in packets_by_minute.items():
            
            output_pcap_file = f"{output_prefix}{minute_key.replace(':', '').replace(' ', '').replace('-', '')}.pcap"
            wrpcap(output_pcap_file, packets)
            msg.append(f"Packets for minute {minute_key} saved to {output_pcap_file}")
        return msg
    except TypeError as e:
        return f"TypeError: {e}"
    except FileNotFoundError as e:
        return f"FileNotFoundError:{e}"
    
    