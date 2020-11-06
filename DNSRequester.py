import binascii
import socket



#Takes url and formats it for message
def countB4Dot(url):
    values = [] #holds counter in hex and letters in hex
    letters = [] #letters in hex
    counter = 0 #counts length of strings
    for element in url:
        
        if element == ".":
            values.append(hex(counter))
            values.extend(letters)
            counter = 0
            letters = []
        else:
            letters.append(hex(ord(element)))
            counter+=1
    #appends last section after exiting loop
    values.append(hex(counter))
    values.extend(letters)

    return values


def send_udp_message(message, address, port):

    message = message.replace(" ", "").replace("\n", "")
    server_address = (address, port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(binascii.unhexlify(message), server_address)
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return binascii.hexlify(data).decode("utf-8")


def format_hex(hex):
    """format_hex returns a pretty version of a hex string"""
    octets = [hex[i:i+2] for i in range(0, len(hex), 2)]
    pairs = [" ".join(octets[i:i+2]) for i in range(0, len(octets), 2)]
    return "\n".join(pairs)


message = "AA AA 01 00 00 01 00 00 00 00 00 00 " \
"07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01"
#######################################
#####domain that we are requesting#####


#MaryLand root DNS server 
response = send_udp_message(message, "8.8.8.8", 53)
print(format_hex(response))

#Writes the incoming message to a text file
f = open("hex.txt", "x")
f.write(format_hex(response))
f.close()