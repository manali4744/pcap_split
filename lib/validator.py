def validate_packet_number(number, packet):
    try:
        if 0 <= number and packet>= number:
            return True
        else:
            return False
    except ValueError as e:
        print(e)
        