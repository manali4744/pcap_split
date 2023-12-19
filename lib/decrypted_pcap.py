from scapy.all import rdpcap

def xor_encrypt_decrypt(data, key):
    # Repeat the key to match the length of the data
    repeated_key = (key * (len(data) // len(key) + 1))[:len(data)]
    
    # Perform XOR operation
    result = bytes([a ^ b for a, b in zip(data, repeated_key.encode('utf-8'))])
    
    return result

def decrypt_file(input_file, output_file, password):
    try:
        with open(input_file, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = xor_encrypt_decrypt(encrypted_data, password)

        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
        try:
            read_pcap_file = rdpcap(output_file)
            return f"{input_file} is decrypted and saved as {output_file}", output_file
        except Exception as e:
            return f"Sorry: {input_file} is Not decrypted, due to password incorrection", "Exception"
    except TypeError as e:
        return f"TypeError: {e}"

