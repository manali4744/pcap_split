## Project Overview

This project focuses on the splitting of pcap (Packet Capture) files using Python 3.8. Ensure that you have Python 3.8 installed on your system before proceeding with this project.
Objective

The primary goal of this project is to split pcap files based on specified parameters such as the number of packets, packet length(size), and time intervals.
Features

## best practice to run code with python3.8 rather than using python3 

Packet Splitting:

    The script can split pcap files based on a single packet.
    It can also perform splitting within a specified range of packets.
    Additionally, the script supports splitting based on specific intervals of packets.

Byte-based Splitting:

    The script is equipped to split pcap files using a particular byte(length) value.
    It supports splitting based on a specific byte range.
    All files with the same byte values can be split using this functionality.

Time-based Splitting:

    Time-based splitting is available with a interval in minutes.

# Create a virtual environment
```bash
$ python3.8 -m venv env
```
or
```bash
$ pip install virtualenv
$ virtualenv -p python3.8 env 
```

# Activate the virtual environment
```bash
$ source env/bin/activate
```

# Install dependencies
```bash
pip install -r requirements.txt
```


# Project structure:

    main.py: Main script with an example.
    lib/: Folder containing common functions.
    method.py: File with a common class object (PcapSplitType).

# Run the main script
```bash
$ python3.8 main.py
```

## PcapSplitType Module

Introduction

The PcapSplitType module provides a set of functions for splitting and processing pcap (Packet Capture) files. This module is designed to work with encrypted pcap files as well, using a basic XOR encryption and decryption method. It supports various splitting methods based on packet numbers, byte ranges, time intervals, and more.

Usage:

    Importing the Module

python:

    from PcapSplitType import PcapSplitType

Class Initialization:

    pcap_splitter = PcapSplitType()

Methods:

1. total_pkt(input_file):

        Description: Retrieves and prints the total number of packets in the pcap file.
        Parameters:
            input_file: The path to the pcap file.

   Example:

       pcap_splitter.total_pkt("example.pcap")

2. get_total_pkt(input_file):

        Description: Retrieves the total number of packets in the pcap file.
        Parameters:
            input_file: The path to the pcap file.
        Returns: Total packet count as a integer.

    Example:
    
        total_packets = pcap_splitter.get_total_pkt("example.pcap")

3. one_pkt_number(input_file, output_pcap, packet_number):

        Description: Splits the pcap file into a new one containing only the specified packet number.
        Parameters:
            input_file: The path to the pcap file.
            output_pcap: The path to the new pcap file prefix.
            packet_number: The desired packet number.

   Example:
   
        pcap_splitter.one_pkt_number("example.pcap", "output_packet", 5)

4. pkt_range(input_file, output_pcap, pkt_range):

        Description: Splits the pcap file into a new one containing only the packets within the specified range.
        Parameters:
            input_file: The path to the pcap file.
            output_pcap: The path to the new pcap file prefix.
            pkt_range: A list representing the packet range [start, end].

     Example:
    
        pcap_splitter.pkt_range("example.pcap", "output_rangep", [10, 20])

5. pkt_interval(input_file, output_pcap, packet_range_size):

        Description: Splits the pcap file into new ones with intervals based on the specified packet range size.
        Parameters:
            input_file: The path to the pcap file.
            output_pcap: The path to the new pcap files.
            packet_range_size: The desired packet range size.
    
     Example:
    
        pcap_splitter.pkt_interval("example.pcap", "output_interval", 50)

6. unique_byte(input_file):

        Description: Retrieves and prints unique bytes from the pcap file.
        Parameters:
            input_file: The path to the pcap file.

   Example:
      
        pcap_splitter.unique_byte("example.pcap")

7. get_unique_byte(input_file):

        Description: Retrieves unique bytes from the pcap file.
        Parameters:
            input_file: The path to the pcap file.
        Returns: List of unique bytes.

    Example:

        unique_bytes = pcap_splitter.get_unique_byte("example.pcap")

8. one_byte(input_file, output_prefix, byte)

        Description: Splits the pcap file into a new one containing only packets with the specified byte.
        Parameters:
            input_file: The path to the pcap file.
            output_prefix: The prefix for the new pcap file.
            byte: The desired byte.

    Example:
    
        pcap_splitter.one_byte("example.pcap", "output_byte", 1410)

9. range_byte(input_file, output_prefix, byte_range):

        Description: Splits the pcap file into a new one containing only packets within the specified byte range.
        Parameters:
            input_file: The path to the pcap file.
            output_prefix: The prefix for the new pcap file prefix.
            byte_range: A list representing the byte range [start, end].

    Example:
    
        pcap_splitter.range_byte("example.pcap", "output_byte_range", [313, 1410])

10. all_byte(input_file, output_prefix):

        Description: Splits the pcap file into new ones, each containing packets with a unique byte.
        Parameters:
            input_file: The path to the pcap file.
            output_prefix: The prefix for the new pcap files.

    Example:
    
        pcap_splitter.all_byte("example.pcap", "output_all_byte")

11. time_minute(input_file, output_prefix):

        Description: Splits the pcap file into new ones based on time intervals in minutes.
        Parameters:
            input_file: The path to the pcap file.
            output_prefix: The prefix for the new pcap files.

    Example:
    
        pcap_splitter.time_minute("example.pcap", "time")

12. decrypt(input_file, password):

        Description: Decrypts the encrypted pcap file using the provided password.
        Parameters:
            input_file: The path to the encrypted pcap file.
            password: The password or key for decryption.
        Returns: Message indicating the success or failure of the decryption and decrypt_file_path.

    Example:
    
        decryption_message = pcap_splitter.decrypt("encrypted.pcap", "my_secret_key")

13. is_pcap_encrypted(input_file):

        Description: Checks if the pcap file is encrypted and decrypts it if necessary.
        Parameters:
            input_file: The path to the pcap file.
        Returns: The path to the decrypted pcap file.

    Example:
    
        decrypted_file_path = pcap_splitter.is_pcap_encrypted("encrypted.pcap")

Important Notes

    This module uses a basic XOR encryption and decryption method, and it is recommended to use stronger encryption methods for sensitive data.
    Ensure that the required dependencies are installed or imported before using the module.

Dependencies

    The module depends on external libraries for pcap file manipulation. Ensure that the following libraries are installed:
        lib.pcap_pieces_pkt_number
        lib.pcap_pieces_size
        lib.pcap_pieces_time
        lib.validator
        lib.decrypted_pcap


This structure provides a clean separation of concerns and makes it easy for others to understand and use your project. Ensure that you replace placeholder method names with actual method names from your implementation.
