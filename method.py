from lib.pcap_pieces_pkt_number import split_pcap_by_range_of_interval, pcap_packet_number, split_pcap_by_packet_number, split_pcap_by_range_packet
from lib.pcap_pieces_size import split_pcap_by_all_byte, read_pcap_bytes, split_pcap_by_byte, split_pcap_by_range_byte
from lib.pcap_pieces_time import split_pcap_by_time
from lib.validator import validate_packet_number
from lib.decrypted_pcap import decrypt_file


class PcapSplitType:

    def total_pkt(self, input_file):
        try:
            input_file = self.is_pcap_encrypted(input_file)
            message = pcap_packet_number(input_file)
            print(message)
        except TypeError as e:
            print(f"TypeError: {e}")
            return f"TypeError: {e}"
    
    def get_total_pkt(self, input_file):
        try:
            input_file = self.is_pcap_encrypted(input_file)
            message = pcap_packet_number(input_file)
            return message
        except TypeError as e:
            print(f"TypeError: {e}")
            return f"TypeError: {e}"

    def one_pkt_number(self, input_file, output_pcap, packet_number):
        try:
            input_file = self.is_pcap_encrypted(input_file)
            message = split_pcap_by_packet_number(input_file, output_pcap, packet_number)
            print(message)
        except TypeError as e:
            print(f"TypeError: {e}")
            return f"TypeError: {e}"
        
    def pkt_range(self, input_file, output_pcap, pkt_range):
        try:
            input_file = self.is_pcap_encrypted(input_file)
            if validate_packet_number(pkt_range[0], pcap_packet_number(input_file)) and validate_packet_number(pkt_range[1], pcap_packet_number(input_file)):
                message = split_pcap_by_range_packet(input_file, output_pcap, pkt_range)
                print(message)
            else:
                print(f"list: {pkt_range} is not valid")
                print(f"{pkt_range} should be in {pcap_packet_number(input_file)}")
        except TypeError as e:
            print(f"TypeError: {e}")
            return f"TypeError: {e}"
        
    def pkt_interval(self, input_file, output_pcap, packet_range_size):
        try:
            input_file = self.is_pcap_encrypted(input_file)
            message = split_pcap_by_range_of_interval(input_file, output_pcap, packet_range_size)
            print(message)
        except TypeError as e:
            print(f"TypeError: {e}")
            return f"TypeError: {e}"
        
    def unique_byte(self, input_file):
        try:
            input_file = self.is_pcap_encrypted(input_file)
            message = list(read_pcap_bytes(input_file))
            print(message)
        except TypeError as e:
            print(f"TypeError: {e}")
            return f"TypeError: {e}"
    
    def get_unique_byte(self, input_file):
        try:
            input_file = self.is_pcap_encrypted(input_file)
            message = list(read_pcap_bytes(input_file))
            return message
        except TypeError as e:
            print(f"TypeError: {e}")
            return f"TypeError: {e}"

        
    def one_byte(self, input_file, output_prefix, byte):
        try:
            input_file = self.is_pcap_encrypted(input_file)
            message = split_pcap_by_byte(input_file, output_prefix, byte)
            print(message)
        except TypeError as e:
            print(f"TypeError: {e}")
            return f"TypeError: {e}"
        
    def range_byte(self, input_file, output_prefix, byte_range):
        try:
            input_file = self.is_pcap_encrypted(input_file)
            if byte_range[0] in list(read_pcap_bytes(input_file)) and byte_range[0] in list(read_pcap_bytes(input_file)):
                message = split_pcap_by_range_byte(input_file, output_prefix, byte_range)
                print(message)
            else:
                print(f"{byte_range} should be in {read_pcap_bytes(input_file)}")
        except TypeError as e:
            print(f"TypeError: {e}")
            return f"TypeError: {e}"
    
    def all_byte(self, input_file, output_prefix):
        try:
            input_file = self.is_pcap_encrypted(input_file)
            message = split_pcap_by_all_byte(input_file, output_prefix)
            print(message)
        except TypeError as e:
            print(f"TypeError: {e}")
            return f"TypeError: {e}"
        
    def time_minute(self, input_file, output_prefix):
        try:
            input_file = self.is_pcap_encrypted(input_file)
            message = split_pcap_by_time(input_file, output_prefix)
            print(message)
        except TypeError as e:
            print(f"TypeError: {e}")
            return f"TypeError: {e}"
    
    def decrypt(self, input_file, password):
        try:
            output_file = f"pcap_decrypted/{input_file.split('/')[-1]}_decrypt.pcap"
            message = decrypt_file(input_file, output_file, password)
            return message
        except TypeError as e:
            print(f"TypeError: {e}")
            return f"TypeError: {e}"
    
    def is_pcap_encrypted(self, input_file):
        try:
            is_encrypted = pcap_packet_number(input_file)
            if type(is_encrypted) == int:
                return input_file
            else:
                print("file is encrypted method (xor_encrypt_decrypt)\n")
                password = input("\nEnter password or key of input file:")
                data = self.decrypt(input_file, password)
                if data[-1]!= "Exception":
                    print(data[0])
                    return data[-1]
                elif data[-1] == "Exception":
                    print(data[0])
                    exit()
        except TypeError as e:
            print(f"TypeError: {e}")
            return f"TypeError: {e}"




        
        
