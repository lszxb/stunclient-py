#!/usr/bin/env python3

import random
import socket
import sys

from bitstring import Bits

defaultPort = 3478
addressList = []
if len(sys.argv) < 2:
    exit(1)

for arg in sys.argv[1:]:
    if len(arg.split(':')) == 1:
        addressList.append((arg.split(':')[0], defaultPort))
    elif len(arg.split(':')) == 2:
        addressList.append((arg.split(':')[0], int(arg.split(':')[1])))
    else:
        exit(2)

bindingRequest = Bits(hex="0x0001")
messageLength = Bits(hex="0x0000")
magicCookie = Bits(hex="0x2112A442")
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def bin2hex(binary):
    return Bits(bin=binary).hex


def bin2int(binary):
    return Bits(bin=binary).uint


def xor_address_parse(value):
    return address_parse(((Bits(bin=value[0:16])) +
                          (Bits(bin=value[16:32]) ^ Bits(bin=magicCookie.bin[0:16])) +
                          (Bits(bin=value[32:64]) ^ magicCookie)).bin)


def address_parse(value):
    ip_address = {"port": bin2int(value[16:32]),
                  "ip": str(bin2int(value[32:40])) + "." + str(bin2int(value[40:48])) + "." + str(
                      bin2int(value[48:56])) + "." + str(bin2int(value[56:64]))}
    return ip_address


def software_parse(value):
    return Bits(bin=value).bytes.decode("utf-8").split("\x00")[0]


attributesTypes = {"0001": "MAPPED-ADDRESS", "0002": "RESPONSE-ADDRESS", "0003": "CHANGE-ADDRESS",
                   "0004": "SOURCE-ADDRESS", "0005": "CHANGED-ADDRESS", "0006": "USERNAME", "0007": "PASSWORD",
                   "0008": "MESSAGE-INTEGRITY", "0009": "ERROR-CODE", "000A": "UNKNOWN-ATTRIBUTES",
                   "000B": "REFLECTED-FROM", "0014": "REALM", "0015": "NONCE", "0020": "XOR-MAPPED-ADDRESS",
                   "8020": "XOR-MAPPED-ADDRESS", "8022": "SOFTWARE", "8023": "ALTERNATE-SERVER", "8028": "FINGERPRINT",
                   "802b": "RESPONSE-ORIGIN", "802c": "OTHER-ADDRESS"}
attributesTypesParse = {"MAPPED-ADDRESS": address_parse, "SOFTWARE": software_parse, "SOURCE-ADDRESS": address_parse,
                        "CHANGED-ADDRESS": address_parse, "XOR-MAPPED-ADDRESS": xor_address_parse,
                        "RESPONSE-ORIGIN": address_parse, "OTHER-ADDRESS": address_parse}


def attributes_parse(binary):
    i = 0
    length = len(binary)
    attributes = {}
    while i < length:
        if bin2hex(binary[i + 0:i + 16]) in attributesTypes:
            attribute_type = attributesTypes[bin2hex(binary[i + 0:i + 16])]
        else:
            attribute_type = bin2hex(binary[i + 0:i + 16])
        attribute_length = bin2int(binary[i + 16:i + 32]) * 8
        attribute_value = binary[i + 32:i + 32 + attribute_length]
        if attribute_type in attributesTypesParse:
            attributes[attribute_type] = attributesTypesParse[attribute_type](attribute_value)
        else:
            attributes[attribute_type] = bin2hex(attribute_value)
        i += 32 + attribute_length
    return attributes

def get_ip(address):
    transactionID = Bits(uint=random.randint(0, 2 ** 96 - 1), length=96)
    
    print("TransactionID: " + transactionID.hex)
    
    request = bindingRequest + messageLength + magicCookie + transactionID
    
    s.sendto(request.bytes, address)
    response = Bits(bytes=s.recv(1024))
    
    print(attributes_parse(response.bin[160:]))
    
for address in addressList:
    get_ip(address)
