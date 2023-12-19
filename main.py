from method import PcapSplitType

class PCAPSPLIT:
    
    def __init__(self):
        self.type()

    def type(self):
        print(f"\n{'*'*10}MAIN MENU{'*'*10}\n")
        print("1. Split by number of packets")
        print("2. Split by bytes")
        print("3. Split by time")
        print("4. Exit")

        self.choice = input("\nEnter your choice for how to split the pcap file: ")

        if self.choice == '1':
            self.pkt_number()
        elif self.choice == '2':
            self.pkt_byte()
        elif self.choice == '3':
            self.pkt_time()
        elif self.choice == '4':
            exit()
        else:
            print("Invalid choice. Please enter a valid option.\n\n")
            self.type()

    def pkt_number(self):
        pcap_file = PcapSplitType()
        info = self.pkt_info()
        # input_pcap = "input_pcap_files/2017-12-05-Hancitor-malspam-traffic.pcap"
        input_pcap = "input_pcap_files/encrypted.pcap"
        input_pcap = pcap_file.is_pcap_encrypted(input_pcap)
        if info == 1:
            print(f"\n{'*'*10}USING ONLY ONE PACKET SPLIT METHOD{'*'*10}")
            pcap_file = PcapSplitType()
            print(f"\nInput file: {input_pcap}\nfile contains {pcap_file.get_total_pkt(input_pcap)} packet\n")
            pkt_number = int(input("\nEnter Desired Packet number: "))
            output_pcap = f"output_pcap_files/packet_number_one/pcap_{pkt_number}"
            pcap_file.one_pkt_number(input_pcap, output_pcap, pkt_number)
            self.type()

        elif info == 2:
            print(f"{'*'*10}USING CUSTOM RANGE PACKET SPLIT METHOD{'*'*10}")
            pkt_list = []
            pcap_file = PcapSplitType()
            print(f"\nInput file: {input_pcap}\nfile contains {pcap_file.get_total_pkt(input_pcap)} packet\n")
            start_one = int(input("\nEnter starting packet number:"))
            end_one = int(input("\nEnter ending packet number:"))
            pkt_list.append(start_one)
            pkt_list.append(end_one)
            output_pcap = f"output_pcap_files/packet_number_range/pcap_between_{start_one}_{end_one}"
            pcap_file.pkt_range(input_pcap, output_pcap, pkt_list)
            self.type()

        elif info == 3:
            pcap_file = PcapSplitType()
            print(f"{'*'*10}USING CUSTOM INTERVAL METHOD{'*'*10}")
            packet_range_size = int(input("\nEnter desired interval: "))
            pcap_file.total_pkt
            output_pcap = "output_pcap_files/packet_number_interval/pcap_range"
            pcap_file.pkt_interval(input_pcap, output_pcap, packet_range_size)
            self.type()
        else:
            print("\nInvalid choice. Please enter a valid option.\n")
            self.pkt_number()

    def pkt_info(self):
        print(f"\n{'*'*10}PACKET SPLIT USING PACKET NUMBER{'*'*10}\n")
        print("1. Pcap file with one desired packet")
        print("2. Pcap file with a range of packets")
        print("3. Pcap file with a desired interval")
        choice = input("\nEnter Choice: ")

        return int(choice)
    
    def pkt_byte(self):
        info = self.byte_info()
        pcap_file = PcapSplitType()
        input_pcap = "input_pcap_files/2017-12-05-Hancitor-malspam-traffic.pcap"
        input_pcap = pcap_file.is_pcap_encrypted(input_pcap)
        if info == 1:
            print(f"\n{'*'*10}CREATE PCAP FILE HAVING SAME BYTE FOR ALL PACKETS{'*'*10}\n")
            info = "\nInfo: Here is a list of all bytes which the pcap file contains. You can create a specific file for a specific byte or a custom range of bytes.\n"
            print(info)
            pcap_bytes = pcap_file.get_unique_byte(input_pcap)
            byte_info = f"Bytes in the pcap file:\n{pcap_bytes}\n"
            print(byte_info)
            byte_for_file = int(input("\nEnter byte: "))
            output_prefix = f"output_pcap_files/byte_one/pcap_of_{byte_for_file}"
            if byte_for_file in pcap_bytes:
                pcap_file.one_byte(input_pcap, output_prefix, byte_for_file)
                self.type()
            else:
                print("Sorry, inserted wrong byte")
                self.pkt_byte()

        elif info == 2:
            pcap_file = PcapSplitType()
            print(f"\n{'*'*10}CREATE PCAP FILE HAVING CUSTOM RANGE OF BYTES{'*'*10}\n")
            pcap_bytes = pcap_file.get_unique_byte(input_pcap)
            byte_info = f"Bytes in the pcap files:\n {pcap_bytes}\n"
            print(byte_info)
            byte_range = []
            byte_one = int(input("\nEnter Byte One: "))
            if byte_one in pcap_bytes:
                byte_range.append(byte_one)
                byte_two = int(input("\nEnter Byte Two: "))
                if byte_two in pcap_bytes:
                    byte_range.append(byte_two)
                    output_prefix = f"output_pcap_files/byte_range/pcap_between_{byte_one}_{byte_two}"
                    pcap_file.range_byte(input_pcap, output_prefix, byte_range)
                    self.type()
                else:
                    print(f"Error: File does not contain {byte_two} byte")
                    self.pkt_byte()
            else:
                print(f"Error: File does not contain {byte_one} byte")
                self.pkt_byte()

        elif info == 3:
            pcap_file = PcapSplitType()
            print(f"\n{'*'*10}CREATE PCAP FILES HAVING SAME BYTE FOR EACH PACKET{'*'*10}\n")
            output_prefix = "output_pcap_files/byte_all_file/pcap_byte"
            pcap_file.all_byte(input_pcap, output_prefix)
            self.type()

        else:
            print("\nInvalid choice. Please enter a valid option.\n")
            self.pkt_byte()

    def byte_info(self):
        print(f"\n{'*'*10}PACKET SPLIT USING BYTE SPLIT METHOD{'*'*10}\n")
        print("1. One file with many packets, but same byte")
        print("2. One file having a range of bytes (e.g., between 1 to 32)")
        print("3. Separate files using the same byte for every file")
        choice = input("\nEnter Choice: ")
        return int(choice)

    def pkt_time(self):
        print(f"\n{'*'*10}USER USING PACKET by TIME SPLIT METHOD{'*'*10}\n")
        pcap_file = PcapSplitType()
        input_pcap = "input_pcap_files/2017-10-02-Hancitor-malspam-traffic-example.pcap"
        input_pcap = pcap_file.is_pcap_encrypted(input_pcap)
        output_prefix = f"output_pcap_files/time_minute/{input_pcap.split('/')[-1].split('.')[0]}_"
        print(f"Creates Pcap files with the same minute packets information (will take the default file: {input_pcap})")
        pcap_file.time_minute(input_pcap, output_prefix)
        self.type()


get_user_input = PCAPSPLIT()