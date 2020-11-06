import binascii
import socket
import sys

#Usage: mydns.py arg_name arg_name
#Example: mydns.py google.com 199.7.91.13

urlGiven = sys.argv[1]
rootDNS = sys.argv[2]
#Takes url and formats it for message
def countB4Dot(url):
    values = [] #holds counter in hex and letters in hex
    letters = [] #letters in hex
    counter = 0 #counts length of strings before "."
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

#Reformats lists of hex values produced by countB4Dot(url) into a string
def reformatHex():
    urlWord = ""
    for element in countB4Dot(urlGiven):
        if len(str(element)) < 4:
            urlWord += ("0" + str(element)[2] + " ")
        else:
            urlWord += (str(element)[2] + str(element)[3] + " ")
    urlWord += "00 "
    return urlWord


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



url = reformatHex()


message = "AA AA 01 00 00 01 00 00 00 00 00 00 " \
+ url+ "00 01 00 01"


#message = "AA AA 01 00 00 01 00 00 00 00 00 00 " \
#"07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01"
########################################
######domain that we are requesting#####


#MaryLand root DNS server 
response = send_udp_message(message, rootDNS, 53)
print("\n***Server Reply Content***\n",response)
print("\n***IP for queried domain name***\n")
#Writes the incoming message to a text file
#f.write(format_hex(response))
#f.close()

#print (reformatHex())