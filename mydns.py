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

def parse_response(message):
	print('ID: ' + message[:4])
	
	message = message[4:]
	h = bin(int(message[:4], 16))
	rcode = h[-4:]	
	print('RCODE: ', rcode)
	
	message = message[8:]
	ancount = int(message[:4], 16)
	print('ANCOUNT: ', ancount)
	
	message = message[4:]
	nscount = int(message[:4], 16)
	print('NSCOUNT: ', nscount)
	
	message = message[4:]
	arcount = int(message[:4], 16)
	print('ARCOUNT: ', arcount)
	totalRR = arcount + ancount + nscount
	
	message = message[4:]
	while message[:2] != '00':
		#in QNAME
		message = message[1:]
	
	message = message[2:]
	qtype = int(message[:4], 16)
	print('QTYPE: ', qtype)
	
	message = message[4:]
	qclass = int(message[:4], 16)
	print('QCLASS: ', qclass)
	
	message = message[8:]
	rrtype = int(message[:4], 16)
	if rrtype == 1:
		print('TYPE: A')
	elif rrtype == 2:
		print('TYPE: NS')
	else:
		print('TYPE: ', rrtype)

	message = message[4:]
	rrclass = int(message[:4], 16)
	if rrclass == 1:
		print('CLASS: IN')
	else:
		print('CLASS: ', rrclass)
	
	message = message[4:]
	ttl = int(message[:8], 16)
	print('TTL: ', ttl, 'seconds')

	rdlength = int(message[:4], 16)
	print('RDLENGTH: ', rdlength)

	rdata = message[:rdlength*2]
	message = message[rdlength:]

	if (rrtype == 1): # get the IP from the RDATA if the TYPE is A			
		a = int(rdata, 16)		
		ip4 = a & 0xff
		a = a >> 8
		ip3 = a & 0xff
		a = a >> 8
		ip2 = a & 0xff
		a = a >> 8
		ip1 = a & 0xff
		print("IP: " + str(ip1) + "." + str(ip2) + ".

url = reformatHex()
message = "AA AA 01 00 00 01 00 00 00 00 00 00 " \
+ url+ "00 01 00 01"

response = send_udp_message(message, rootDNS, 53)
print("\n***Server Reply Content***\n")
parse_response(response)   
print("\n***IP for queried domain name***\n")
             
