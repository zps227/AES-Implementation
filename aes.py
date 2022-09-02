#!/usr/bin/env python3

import copy

# My AES program should be run from the command line without any parameters. The user will first be asked
# which mode to run the software in (encryption or decryption). The user will then be prompeted to choose 
# file mode or text mode. File mode allows the user to input a filename for the plaintext and key, while 
# text mode allows the user to input hexadecmical text directly. The user is also prompted to choose 
# between cbc mode and ecb mode through a text input prompt.

# My implementation will only accept key sizes of 16, 24, and 32 bytes
# and plaintexts that can be broken up into 16 byte chunks evenly.


# Bytes are represented as size 8 lists in python
# polyList[0] is the highest bit
AES_POLY = [1, 0, 0, 0, 1, 1, 0, 1, 1]
AES_POLY_8BIT = [0, 0, 0, 1, 1, 0, 1, 1]
KEY_ROUND_CONSTANTS = []
sbox = {
    0x00: 0x63, 0x01: 0x7C, 0x02: 0x77, 0x03: 0x7B, 0x04: 0xF2, 0x05: 0x6B, 0x06: 0x6F, 0x07: 0xC5, 0x08: 0x30, 0x09: 0x01, 0x0A: 0x67, 
    0x0B: 0x2B, 0x0C: 0xFE, 0x0D: 0xD7, 0x0E: 0xAB, 0x0F: 0x76, 0x10: 0xCA, 0x11: 0x82, 0x12: 0xC9, 0x13: 0x7D, 0x14: 0xFA, 0x15: 0x59, 
    0x16: 0x47, 0x17: 0xF0, 0x18: 0xAD, 0x19: 0xD4, 0x1A: 0xA2, 0x1B: 0xAF, 0x1C: 0x9C, 0x1D: 0xA4, 0x1E: 0x72, 0x1F: 0xC0, 0x20: 0xB7, 
    0x21: 0xFD, 0x22: 0x93, 0x23: 0x26, 0x24: 0x36, 0x25: 0x3F, 0x26: 0xF7, 0x27: 0xCC, 0x28: 0x34, 0x29: 0xA5, 0x2A: 0xE5, 0x2B: 0xF1, 
    0x2C: 0x71, 0x2D: 0xD8, 0x2E: 0x31, 0x2F: 0x15, 0x30: 0x04, 0x31: 0xC7, 0x32: 0x23, 0x33: 0xC3, 0x34: 0x18, 0x35: 0x96, 0x36: 0x05, 
    0x37: 0x9A, 0x38: 0x07, 0x39: 0x12, 0x3A: 0x80, 0x3B: 0xE2, 0x3C: 0xEB, 0x3D: 0x27, 0x3E: 0xB2, 0x3F: 0x75, 0x40: 0x09, 0x41: 0x83, 
    0x42: 0x2C, 0x43: 0x1A, 0x44: 0x1B, 0x45: 0x6E, 0x46: 0x5A, 0x47: 0xA0, 0x48: 0x52, 0x49: 0x3B, 0x4A: 0xD6, 0x4B: 0xB3, 0x4C: 0x29, 
    0x4D: 0xE3, 0x4E: 0x2F, 0x4F: 0x84, 0x50: 0x53, 0x51: 0xD1, 0x52: 0x00, 0x53: 0xED, 0x54: 0x20, 0x55: 0xFC, 0x56: 0xB1, 0x57: 0x5B, 
    0x58: 0x6A, 0x59: 0xCB, 0x5A: 0xBE, 0x5B: 0x39, 0x5C: 0x4A, 0x5D: 0x4C, 0x5E: 0x58, 0x5F: 0xCF, 0x60: 0xD0, 0x61: 0xEF, 0x62: 0xAA, 
    0x63: 0xFB, 0x64: 0x43, 0x65: 0x4D, 0x66: 0x33, 0x67: 0x85, 0x68: 0x45, 0x69: 0xF9, 0x6A: 0x02, 0x6B: 0x7F, 0x6C: 0x50, 0x6D: 0x3C, 
    0x6E: 0x9F, 0x6F: 0xA8, 0x70: 0x51, 0x71: 0xA3, 0x72: 0x40, 0x73: 0x8F, 0x74: 0x92, 0x75: 0x9D, 0x76: 0x38, 0x77: 0xF5, 0x78: 0xBC, 
    0x79: 0xB6, 0x7A: 0xDA, 0x7B: 0x21, 0x7C: 0x10, 0x7D: 0xFF, 0x7E: 0xF3, 0x7F: 0xD2, 0x80: 0xCD, 0x81: 0x0C, 0x82: 0x13, 0x83: 0xEC, 
    0x84: 0x5F, 0x85: 0x97, 0x86: 0x44, 0x87: 0x17, 0x88: 0xC4, 0x89: 0xA7, 0x8A: 0x7E, 0x8B: 0x3D, 0x8C: 0x64, 0x8D: 0x5D, 0x8E: 0x19, 
    0x8F: 0x73, 0x90: 0x60, 0x91: 0x81, 0x92: 0x4F, 0x93: 0xDC, 0x94: 0x22, 0x95: 0x2A, 0x96: 0x90, 0x97: 0x88, 0x98: 0x46, 0x99: 0xEE, 
    0x9A: 0xB8, 0x9B: 0x14, 0x9C: 0xDE, 0x9D: 0x5E, 0x9E: 0x0B, 0x9F: 0xDB, 0xA0: 0xE0, 0xA1: 0x32, 0xA2: 0x3A, 0xA3: 0x0A, 0xA4: 0x49, 
    0xA5: 0x06, 0xA6: 0x24, 0xA7: 0x5C, 0xA8: 0xC2, 0xA9: 0xD3, 0xAA: 0xAC, 0xAB: 0x62, 0xAC: 0x91, 0xAD: 0x95, 0xAE: 0xE4, 0xAF: 0x79, 
    0xB0: 0xE7, 0xB1: 0xC8, 0xB2: 0x37, 0xB3: 0x6D, 0xB4: 0x8D, 0xB5: 0xD5, 0xB6: 0x4E, 0xB7: 0xA9, 0xB8: 0x6C, 0xB9: 0x56, 0xBA: 0xF4, 
    0xBB: 0xEA, 0xBC: 0x65, 0xBD: 0x7A, 0xBE: 0xAE, 0xBF: 0x08, 0xC0: 0xBA, 0xC1: 0x78, 0xC2: 0x25, 0xC3: 0x2E, 0xC4: 0x1C, 0xC5: 0xA6, 
    0xC6: 0xB4, 0xC7: 0xC6, 0xC8: 0xE8, 0xC9: 0xDD, 0xCA: 0x74, 0xCB: 0x1F, 0xCC: 0x4B, 0xCD: 0xBD, 0xCE: 0x8B, 0xCF: 0x8A, 0xD0: 0x70, 
    0xD1: 0x3E, 0xD2: 0xB5, 0xD3: 0x66, 0xD4: 0x48, 0xD5: 0x03, 0xD6: 0xF6, 0xD7: 0x0E, 0xD8: 0x61, 0xD9: 0x35, 0xDA: 0x57, 0xDB: 0xB9, 
    0xDC: 0x86, 0xDD: 0xC1, 0xDE: 0x1D, 0xDF: 0x9E, 0xE0: 0xE1, 0xE1: 0xF8, 0xE2: 0x98, 0xE3: 0x11, 0xE4: 0x69, 0xE5: 0xD9, 0xE6: 0x8E, 
    0xE7: 0x94, 0xE8: 0x9B, 0xE9: 0x1E, 0xEA: 0x87, 0xEB: 0xE9, 0xEC: 0xCE, 0xED: 0x55, 0xEE: 0x28, 0xEF: 0xDF, 0xF0: 0x8C, 0xF1: 0xA1, 
    0xF2: 0x89, 0xF3: 0x0D, 0xF4: 0xBF, 0xF5: 0xE6, 0xF6: 0x42, 0xF7: 0x68, 0xF8: 0x41, 0xF9: 0x99, 0xFA: 0x2D, 0xFB: 0x0F, 0xFC: 0xB0, 
    0xFD: 0x54, 0xFE: 0xBB, 0xFF: 0x16
}

inv_sbox = {
    0x63: 0x00, 0x7C: 0x01, 0x77: 0x02, 0x7B: 0x03, 0xF2: 0x04, 0x6B: 0x05, 0x6F: 0x06, 0xC5: 0x07, 0x30: 0x08, 0x01: 0x09, 0x67: 0x0A, 
    0x2B: 0x0B, 0xFE: 0x0C, 0xD7: 0x0D, 0xAB: 0x0E, 0x76: 0x0F, 0xCA: 0x10, 0x82: 0x11, 0xC9: 0x12, 0x7D: 0x13, 0xFA: 0x14, 0x59: 0x15, 
    0x47: 0x16, 0xF0: 0x17, 0xAD: 0x18, 0xD4: 0x19, 0xA2: 0x1A, 0xAF: 0x1B, 0x9C: 0x1C, 0xA4: 0x1D, 0x72: 0x1E, 0xC0: 0x1F, 0xB7: 0x20, 
    0xFD: 0x21, 0x93: 0x22, 0x26: 0x23, 0x36: 0x24, 0x3F: 0x25, 0xF7: 0x26, 0xCC: 0x27, 0x34: 0x28, 0xA5: 0x29, 0xE5: 0x2A, 0xF1: 0x2B, 
    0x71: 0x2C, 0xD8: 0x2D, 0x31: 0x2E, 0x15: 0x2F, 0x04: 0x30, 0xC7: 0x31, 0x23: 0x32, 0xC3: 0x33, 0x18: 0x34, 0x96: 0x35, 0x05: 0x36, 
    0x9A: 0x37, 0x07: 0x38, 0x12: 0x39, 0x80: 0x3A, 0xE2: 0x3B, 0xEB: 0x3C, 0x27: 0x3D, 0xB2: 0x3E, 0x75: 0x3F, 0x09: 0x40, 0x83: 0x41, 
    0x2C: 0x42, 0x1A: 0x43, 0x1B: 0x44, 0x6E: 0x45, 0x5A: 0x46, 0xA0: 0x47, 0x52: 0x48, 0x3B: 0x49, 0xD6: 0x4A, 0xB3: 0x4B, 0x29: 0x4C, 
    0xE3: 0x4D, 0x2F: 0x4E, 0x84: 0x4F, 0x53: 0x50, 0xD1: 0x51, 0x00: 0x52, 0xED: 0x53, 0x20: 0x54, 0xFC: 0x55, 0xB1: 0x56, 0x5B: 0x57, 
    0x6A: 0x58, 0xCB: 0x59, 0xBE: 0x5A, 0x39: 0x5B, 0x4A: 0x5C, 0x4C: 0x5D, 0x58: 0x5E, 0xCF: 0x5F, 0xD0: 0x60, 0xEF: 0x61, 0xAA: 0x62, 
    0xFB: 0x63, 0x43: 0x64, 0x4D: 0x65, 0x33: 0x66, 0x85: 0x67, 0x45: 0x68, 0xF9: 0x69, 0x02: 0x6A, 0x7F: 0x6B, 0x50: 0x6C, 0x3C: 0x6D, 
    0x9F: 0x6E, 0xA8: 0x6F, 0x51: 0x70, 0xA3: 0x71, 0x40: 0x72, 0x8F: 0x73, 0x92: 0x74, 0x9D: 0x75, 0x38: 0x76, 0xF5: 0x77, 0xBC: 0x78, 
    0xB6: 0x79, 0xDA: 0x7A, 0x21: 0x7B, 0x10: 0x7C, 0xFF: 0x7D, 0xF3: 0x7E, 0xD2: 0x7F, 0xCD: 0x80, 0x0C: 0x81, 0x13: 0x82, 0xEC: 0x83, 
    0x5F: 0x84, 0x97: 0x85, 0x44: 0x86, 0x17: 0x87, 0xC4: 0x88, 0xA7: 0x89, 0x7E: 0x8A, 0x3D: 0x8B, 0x64: 0x8C, 0x5D: 0x8D, 0x19: 0x8E, 
    0x73: 0x8F, 0x60: 0x90, 0x81: 0x91, 0x4F: 0x92, 0xDC: 0x93, 0x22: 0x94, 0x2A: 0x95, 0x90: 0x96, 0x88: 0x97, 0x46: 0x98, 0xEE: 0x99, 
    0xB8: 0x9A, 0x14: 0x9B, 0xDE: 0x9C, 0x5E: 0x9D, 0x0B: 0x9E, 0xDB: 0x9F, 0xE0: 0xA0, 0x32: 0xA1, 0x3A: 0xA2, 0x0A: 0xA3, 0x49: 0xA4, 
    0x06: 0xA5, 0x24: 0xA6, 0x5C: 0xA7, 0xC2: 0xA8, 0xD3: 0xA9, 0xAC: 0xAA, 0x62: 0xAB, 0x91: 0xAC, 0x95: 0xAD, 0xE4: 0xAE, 0x79: 0xAF, 
    0xE7: 0xB0, 0xC8: 0xB1, 0x37: 0xB2, 0x6D: 0xB3, 0x8D: 0xB4, 0xD5: 0xB5, 0x4E: 0xB6, 0xA9: 0xB7, 0x6C: 0xB8, 0x56: 0xB9, 0xF4: 0xBA, 
    0xEA: 0xBB, 0x65: 0xBC, 0x7A: 0xBD, 0xAE: 0xBE, 0x08: 0xBF, 0xBA: 0xC0, 0x78: 0xC1, 0x25: 0xC2, 0x2E: 0xC3, 0x1C: 0xC4, 0xA6: 0xC5, 
    0xB4: 0xC6, 0xC6: 0xC7, 0xE8: 0xC8, 0xDD: 0xC9, 0x74: 0xCA, 0x1F: 0xCB, 0x4B: 0xCC, 0xBD: 0xCD, 0x8B: 0xCE, 0x8A: 0xCF, 0x70: 0xD0, 
    0x3E: 0xD1, 0xB5: 0xD2, 0x66: 0xD3, 0x48: 0xD4, 0x03: 0xD5, 0xF6: 0xD6, 0x0E: 0xD7, 0x61: 0xD8, 0x35: 0xD9, 0x57: 0xDA, 0xB9: 0xDB, 
    0x86: 0xDC, 0xC1: 0xDD, 0x1D: 0xDE, 0x9E: 0xDF, 0xE1: 0xE0, 0xF8: 0xE1, 0x98: 0xE2, 0x11: 0xE3, 0x69: 0xE4, 0xD9: 0xE5, 0x8E: 0xE6, 
    0x94: 0xE7, 0x9B: 0xE8, 0x1E: 0xE9, 0x87: 0xEA, 0xE9: 0xEB, 0xCE: 0xEC, 0x55: 0xED, 0x28: 0xEE, 0xDF: 0xEF, 0x8C: 0xF0, 0xA1: 0xF1, 
    0x89: 0xF2, 0x0D: 0xF3, 0xBF: 0xF4, 0xE6: 0xF5, 0x42: 0xF6, 0x68: 0xF7, 0x41: 0xF8, 0x99: 0xF9, 0x2D: 0xFA, 0x0F: 0xFB, 0xB0: 0xFC, 
    0x54: 0xFD, 0xBB: 0xFE, 0x16: 0xFF
}

def print4Bytes(byteArray):
    str = ""
    for i in range(3):
        str += "%02x " % byteArrayToNum(byteArray[i])
    str += "%02x" % byteArrayToNum(byteArray[3])

    print(str)

def print4Tuple(byteTuple):
    byteArray = list(byteTuple)
    str = ""
    for i in range(3):
        str += "%02x " % byteArrayToNum(byteArray[i])
    str += "%02x" % byteArrayToNum(byteArray[3])

    print(str)

def printBytes(byteArray, splitOn):
    str = ""
    newLineNum = 1
    for i in range(len(byteArray)):
        str += "%02x" % byteArrayToNum(byteArray[i])
        if (newLineNum == splitOn):
            str += "\n"
            newLineNum = 0
        newLineNum += 1
    
    print(str)

# Convert plaintext to bytes array
def plainTextToBytes(plaintextString):
    ret = []
    for c in plaintextString:
        ret.append(numToByteArray(ord(c)))
    
    return ret

# Convert number to byte array
def numToByteArray(num):
    byteArray = [0] * 8
    bitVal = 128
    # Loop through array forwards
    for i in range(len(byteArray)):
        if (num >= bitVal):
            byteArray[i] = 1
            num = num - bitVal
        
        # Decrease bitVal
        bitVal = bitVal // 2

    return byteArray

# Convert byte array to number
def byteArrayToNum(byteArray):
    num = 0
    bitVal = 0
    # Loop through array backwards
    for i in range(len(byteArray) - 1, -1, -1):
        # If a bit == 1, add its value to sum
        if (byteArray[i] == 1):
            num += 2 ** bitVal
        
        # Increment bitVal
        bitVal += 1

    return num

# Left shift a polyList
def leftShiftPoly(polyList):
    retList = []
    for i in range(1, len(polyList)):
        retList.append(polyList[i])
    
    retList.append(0)

    return retList

# Xor two polynomials of the same size together
def xorPoly(polyList1, polyList2):
    if (len(polyList1) != len(polyList2)):
        print("len1 =", len(polyList1), "len2 =", len(polyList2))
        raise Exception("error: param lists are different sizes")
    
    retList = []
    # Loop through the two lists
    for i in range(len(polyList1)):
        # XOR the two lists one bit at a time
        retList.append(polyList1[i] ^ polyList2[i])
    
    return retList

# Xor two polynomials of the same size together
def xorPolyInPlace(polyList1, polyList2):
    if (len(polyList1) != len(polyList2)):
        print("len1 = ", len(polyList1), "len2 = ", len(polyList2))
        raise Exception("error: param lists are different sizes")
    
    # Loop through the two lists
    for i in range(len(polyList1)):
        # XOR the two lists one bit at a time (in-place)
        polyList1[i] = polyList1[i] ^ polyList2[i]


# Implementation of xtime()
def xtime(polyList):
    retList = copy.deepcopy(polyList)
    if (retList[0] == 1):
        # Need to xor with AES_8BIT if the high bit is 1
        retList = leftShiftPoly(retList)
        xorPolyInPlace(retList, AES_POLY_8BIT)
    else:
        retList = leftShiftPoly(retList)
    
    return retList

def initRoundConstants():
    # First round constant is just 00000001
    KEY_ROUND_CONSTANTS.append([0,0,0,0,0,0,0,1])
    # Each successive round constant is just xtime() of prev constant
    for i in range(1, 15):
        KEY_ROUND_CONSTANTS.append(xtime(KEY_ROUND_CONSTANTS[i - 1]))

# In-place rotation of the bytes (Ensure this memory works as expected!)
def rotateLeft(byte1, byte2, byte3, byte4):
    return (byte2, byte3, byte4, byte1)

def subBytes(byte):
    return numToByteArray(sbox[byteArrayToNum(byte)])

def invSubBytes(byte):
    return numToByteArray(inv_sbox[byteArrayToNum(byte)])

def addRoundConstant(byte1, round):
    xorPolyInPlace(byte1, KEY_ROUND_CONSTANTS[round])

def keyExpansionCore(bytesTuple, round):
    (byte1, byte2, byte3, byte4) = bytesTuple
    print("input:")
    print4Tuple((byte1, byte2, byte3, byte4))

    (byte1, byte2, byte3, byte4) = rotateLeft(byte1, byte2, byte3, byte4)
    print("rotate left:")
    print4Tuple((byte1, byte2, byte3, byte4))

    byte1 = subBytes(byte1)
    byte2 = subBytes(byte2)
    byte3 = subBytes(byte3)
    byte4 = subBytes(byte4)
    print("sub bytes:")
    print4Tuple((byte1, byte2, byte3, byte4))

    addRoundConstant(byte1, round)
    print("add round constant:")
    print4Tuple((byte1, byte2, byte3, byte4))

    return (byte1, byte2, byte3, byte4)

# Returns the last n bytes of the bytes
def lastNBytes(bytes, numBytes):
    return bytes[(len(bytes) - numBytes):len(bytes)]

# Returns the last n bytes of the bytes
def firstNBytes(bytes, numBytes):
    return bytes[0:numBytes]

# Key expansion for 32 bytes
# initialKey = array of 32 byte arrays
def keyExpansion128(initialKey):
    expansionKey = copy.deepcopy(initialKey)
    round = 0
    while (len(expansionKey) < 176):
        print("CORE round:", round)
        for i in range(4):
            temp1 = copy.deepcopy(lastNBytes(expansionKey, 4))
            if (i == 0):
                temp1 = keyExpansionCore(temp1, round)
            
            temp2 = copy.deepcopy(lastNBytes(expansionKey, 16))
            temp2 = firstNBytes(temp2, 4)

            # xor each byte array in temp1
            xorPolyInPlace(temp1[0], temp2[0])
            xorPolyInPlace(temp1[1], temp2[1])
            xorPolyInPlace(temp1[2], temp2[2])
            xorPolyInPlace(temp1[3], temp2[3])
            
            print("temp1 XOR with temp2")
            print4Bytes(temp1)

            expansionKey.append(temp1[0])
            expansionKey.append(temp1[1])
            expansionKey.append(temp1[2])
            expansionKey.append(temp1[3])
        
        round += 1

    return expansionKey

# Key expansion for 48 bytes
# initialKey = array of 48 byte arrays
def keyExpansion192(initialKey):
    expansionKey = copy.deepcopy(initialKey)
    round = 0
    while (len(expansionKey) < 208):
        print("CORE round:", round)
        for i in range(6):
            temp1 = copy.deepcopy(lastNBytes(expansionKey, 4))
            if (i == 0):
                temp1 = keyExpansionCore(temp1, round)
            
            temp2 = copy.deepcopy(lastNBytes(expansionKey, 24))
            temp2 = firstNBytes(temp2, 4)

            # xor each byte array in temp1
            xorPolyInPlace(temp1[0], temp2[0])
            xorPolyInPlace(temp1[1], temp2[1])
            xorPolyInPlace(temp1[2], temp2[2])
            xorPolyInPlace(temp1[3], temp2[3])
            
            print("temp1 XOR with temp2")
            print4Bytes(temp1)

            expansionKey.append(temp1[0])
            expansionKey.append(temp1[1])
            expansionKey.append(temp1[2])
            expansionKey.append(temp1[3])
        
        round += 1

    return expansionKey

# Key expansion for 48 bytes
# initialKey = array of 48 byte arrays
def keyExpansion256(initialKey):
    expansionKey = copy.deepcopy(initialKey)
    round = 0
    while (len(expansionKey) < 240):
        print("CORE round:", round)
        for i in range(8):
            temp1 = copy.deepcopy(lastNBytes(expansionKey, 4))
            if (i == 0):
                temp1 = keyExpansionCore(temp1, round)
            if (i == 4):
                temp1[0] = subBytes(temp1[0])
                temp1[1] = subBytes(temp1[1])
                temp1[2] = subBytes(temp1[2])
                temp1[3] = subBytes(temp1[3])

            temp2 = copy.deepcopy(lastNBytes(expansionKey, 32))
            temp2 = firstNBytes(temp2, 4)

            # xor each byte array in temp1
            xorPolyInPlace(temp1[0], temp2[0])
            xorPolyInPlace(temp1[1], temp2[1])
            xorPolyInPlace(temp1[2], temp2[2])
            xorPolyInPlace(temp1[3], temp2[3])
            
            print("temp1 XOR with temp2")
            print4Bytes(temp1)

            expansionKey.append(temp1[0])
            expansionKey.append(temp1[1])
            expansionKey.append(temp1[2])
            expansionKey.append(temp1[3])
        
        round += 1

    return expansionKey

# Column matrix into linear
def matrixToLinear(bytesMatrix):
    ret = []
    for col in range(0, 4):
        for row in range(0, 4):
            ret.append(bytesMatrix[row][col])
    return ret

# Loads a list into a 4x4 matrix one column at a time
def linearToMatrix(linearBytes):
    ret = [[],[],[],[]]
    indexNum = 0
    for col in range(0, 4):
        for row in range(0, 4):
            ret[row].append(linearBytes[indexNum])
            indexNum += 1
    return ret

# XOR's the key with the given matrix (in-place)
def addRoundKey(plaintextBytesMatrix, expandedKeyBytes, round):
    # Xor the plaintext with each key round portion
    roundIndex = round * 16
    expandedKeyMatrix = linearToMatrix(expandedKeyBytes[roundIndex:roundIndex + 16])
    for row in range(0, 4):
        for col in range(0, 4):
            xorPolyInPlace(plaintextBytesMatrix[row][col], expandedKeyMatrix[row][col])

# Shifts the rows of the matrix (in-place)
def shiftRows(bytesMatrix):
    matrixCopy = copy.deepcopy(bytesMatrix)
    bytesMatrix[1] = [matrixCopy[1][1], matrixCopy[1][2], matrixCopy[1][3], matrixCopy[1][0]]
    bytesMatrix[2] = [matrixCopy[2][2], matrixCopy[2][3], matrixCopy[2][0], matrixCopy[2][1]]
    bytesMatrix[3] = [matrixCopy[3][3], matrixCopy[3][0], matrixCopy[3][1], matrixCopy[3][2]]

# Inversely shifts the rows of the matrix (in-place)
def invShiftRows(bytesMatrix):
    matrixCopy = copy.deepcopy(bytesMatrix)
    bytesMatrix[1] = [matrixCopy[1][3], matrixCopy[1][0], matrixCopy[1][1], matrixCopy[1][2]]
    bytesMatrix[2] = [matrixCopy[2][2], matrixCopy[2][3], matrixCopy[2][0], matrixCopy[2][1]]
    bytesMatrix[3] = [matrixCopy[3][1], matrixCopy[3][2], matrixCopy[3][3], matrixCopy[3][0]]

# Subs the bytes using the sbox
def subBytesEncrypt(plaintextBytesMatrix):
    for row in range(0, 4):
        for col in range(0, 4):
            plaintextBytesMatrix[row][col] = subBytes(plaintextBytesMatrix[row][col])

# Subs the bytes using the sbox (decryption)
def subBytesDecrypt(plaintextBytesMatrix):
    for row in range(0, 4):
        for col in range(0, 4):
            plaintextBytesMatrix[row][col] = invSubBytes(plaintextBytesMatrix[row][col])

# Mixes one column to complete one matrix multiplication step
def mixOneColumn(xtimeList, bytesColumn):
    ret = []
    for i in range(0, 4):
        if (xtimeList[i] == 1):
            ret.append(copy.deepcopy(bytesColumn[i]))
        elif (xtimeList[i] == 2):
            ret.append(xtime(copy.deepcopy(bytesColumn[i])))
        elif (xtimeList[i] == 3):
            xtime1 = xtime(copy.deepcopy(bytesColumn[i]))
            ret.append(xorPoly(xtime1, copy.deepcopy(bytesColumn[i])))
    
    # Xor all the columns together
    xorPolyInPlace(ret[0], ret[1])
    xorPolyInPlace(ret[0], ret[2])
    xorPolyInPlace(ret[0], ret[3])

    return ret[0]

MIX_COLUMNS_MATRIX = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]

# Works in 2d list
def mixColumns(plaintextBytesMatrix):
    plaintextBytesMatrixCpy = copy.deepcopy(plaintextBytesMatrix)
    for col in range(0, 4):
        for row in range(0, 4):
            colList = [plaintextBytesMatrixCpy[0][col], plaintextBytesMatrixCpy[1][col], 
                       plaintextBytesMatrixCpy[2][col], plaintextBytesMatrixCpy[3][col]]
            plaintextBytesMatrix[row][col] = mixOneColumn(MIX_COLUMNS_MATRIX[row], colList)

# Multiplies the polyList2 by polyList1 using xtime function
def multPoly(polyList2, polyList1):
    # Find the index of the highest '1' bit to know how many xtimes to perform
    lastOneBit = polyList2.index(1)

    xTimedLists = []
    curxTime = copy.deepcopy(polyList1)
    # Loop through the array from smallest bit to largest bit (right to left)
    for i in range(len(polyList1) - 1, lastOneBit - 1, -1):
        if (polyList2[i] == 1):
            # Need to store this xtime for our xors
            xTimedLists.append(curxTime)
        curxTime = xtime(curxTime)

    # Xor the xTimedLists together
    # print(xTimedLists)
    retList = copy.deepcopy(polyList1)
    if len(xTimedLists) > 0:
        retList = [0] * 8
        for i in range(len(xTimedLists)):
            retList = xorPoly(retList, xTimedLists[i])

    return retList

INV_MIX_COLUMNS_MATRIX = [[0x0E, 0x0B, 0x0D, 0x09], 
                          [0x09, 0x0E, 0x0B, 0x0D], 
                          [0x0D, 0x09, 0x0E, 0x0B],
                          [0x0B, 0x0D, 0x09, 0x0E]]

def invMixOneColumn(xTimeList, bytesColumn):
    ret = []
    xTimePolyList = [numToByteArray(x) for x in xTimeList]
    for i in range(0, 4):
        # Multiple one row by one column
        ret.append(multPoly(xTimePolyList[i], bytesColumn[i]))
    
    # Xor all the columns together
    xorPolyInPlace(ret[0], ret[1])
    xorPolyInPlace(ret[0], ret[2])
    xorPolyInPlace(ret[0], ret[3])

    return ret[0]

def invMixColumns(cipherBytesMatrix):
    cipherBytesCpy = copy.deepcopy(cipherBytesMatrix)
    for col in range(0, 4):
        for row in range(0, 4):
            colList = [cipherBytesCpy[0][col], cipherBytesCpy[1][col], 
                       cipherBytesCpy[2][col], cipherBytesCpy[3][col]]
            cipherBytesMatrix[row][col] = invMixOneColumn(INV_MIX_COLUMNS_MATRIX[row], colList)


# Encrypt a 128 bit plaintext using the expanded key
def encrypt128(plaintextBytes, expandedKeyBytes, cbcMode, prevCipherBytes):
    keySize = len(expandedKeyBytes)
    totalRounds = 0
    if (keySize == 176):
        totalRounds = 10
    elif (keySize == 216):
        totalRounds = 12
    elif (keySize == 256):
        totalRounds = 14

    print("Encrypting: key size", keySize)
    printBytes(plaintextBytes, 0)
    print("Key:")
    printBytes(expandedKeyBytes[0:16], 0)
    plaintextBytesMatrix = linearToMatrix(plaintextBytes)

    for round in range(0, totalRounds):
        #Check for cbc, and change the first addRoundKey
        if (cbcMode == 1 and round == 0):
            print("Add round key cbc:")
            addRoundKey(plaintextBytesMatrix, expandedKeyBytes, round)
            # Pretends to do another addRoundKey step, but actually just passes prevCipher as the key
            addRoundKey(plaintextBytesMatrix, prevCipherBytes, 0)
            printBytes(matrixToLinear(plaintextBytesMatrix), 0)
        else:
            print("Add round key:")
            addRoundKey(plaintextBytesMatrix, expandedKeyBytes, round)
            printBytes(matrixToLinear(plaintextBytesMatrix), 0)

        print("Sub bytes:")
        subBytesEncrypt(plaintextBytesMatrix)
        printBytes(matrixToLinear(plaintextBytesMatrix), 0)

        print("Shift rows:")
        shiftRows(plaintextBytesMatrix)
        printBytes(matrixToLinear(plaintextBytesMatrix), 0)
        if (round != totalRounds - 1):
            print("Mix columns:")
            mixColumns(plaintextBytesMatrix)
            printBytes(matrixToLinear(plaintextBytesMatrix), 0)
    
    print("Add round key:")
    addRoundKey(plaintextBytesMatrix, expandedKeyBytes, totalRounds)
    printBytes(matrixToLinear(plaintextBytesMatrix), 0)

    return matrixToLinear(plaintextBytesMatrix)

def decrypt128(ciphertextBytes, expandedKeyBytes, cbcMode, prevCipherBytes):
    keySize = len(expandedKeyBytes)
    totalRounds = 0
    if (keySize == 176):
        totalRounds = 10
    elif (keySize == 216):
        totalRounds = 12
    elif (keySize == 256):
        totalRounds = 14

    print("Decrypting: key size", keySize)
    printBytes(ciphertextBytes, 0)
    print("Key:")
    printBytes(expandedKeyBytes[0:16], 0)
    ciphertextBytesMatrix = linearToMatrix(ciphertextBytes)

    # First round
    print("Inv Add round key:")
    addRoundKey(ciphertextBytesMatrix, expandedKeyBytes, totalRounds)
    printBytes(matrixToLinear(ciphertextBytesMatrix), 0)

    for round in range(totalRounds - 1, -1, -1):
        print("Round [", round, "]")

        print("Inv Shift rows:")
        invShiftRows(ciphertextBytesMatrix)
        printBytes(matrixToLinear(ciphertextBytesMatrix), 0)

        print("Inv Sub bytes:")
        subBytesDecrypt(ciphertextBytesMatrix)
        printBytes(matrixToLinear(ciphertextBytesMatrix), 0)

        #Check for cbc, and change the first addRoundKey
        if (cbcMode == 1 and round == 0):
            print("Inv Add round key cbc:")
            # Pretends to do another addRoundKey step, but actually just passes prevCipher as the key
            addRoundKey(ciphertextBytesMatrix, prevCipherBytes, 0)
            # Normal add round key for round 0
            addRoundKey(ciphertextBytesMatrix, expandedKeyBytes, round)
            printBytes(matrixToLinear(ciphertextBytesMatrix), 0)
        else:
            print("Inv Add round key:")
            addRoundKey(ciphertextBytesMatrix, expandedKeyBytes, round)
            printBytes(matrixToLinear(ciphertextBytesMatrix), 0)

        if (round != 0):
            print("Inv Mix columns:")
            invMixColumns(ciphertextBytesMatrix)
            printBytes(matrixToLinear(ciphertextBytesMatrix), 0)
    
    return matrixToLinear(ciphertextBytesMatrix)



def encrypt(plaintextBytes, keyBytes, cbcMode):
    # Make expanded key
    keySize = len(keyBytes)
    expandedKey = None
    if (keySize == 16):
        expandedKey = keyExpansion128(keyBytes)
    elif (keySize == 24):
        expandedKey = keyExpansion192(keyBytes)
    elif (keySize == 32):
        expandedKey = keyExpansion256(keyBytes)
    
    print("Expanded Key:")
    printBytes(expandedKey, 16)
    
    cipherText = []

    # For each 128 bit block, call encrypt128
    for block in range(0, len(plaintextBytes), 16):
        print("Encrypting Plaintext[", block, ":", block + 16, "]")
        if (cbcMode == 1 and block != 0):
            cipherText = cipherText + encrypt128(plaintextBytes[block:block + 16], expandedKey, cbcMode, cipherText[len(cipherText) - 16: len(cipherText)])
        else:
            cipherText = cipherText + encrypt128(plaintextBytes[block:block + 16], expandedKey, 0, None)
    
    print("Entire Ciphertext:")
    printBytes(cipherText, 0)

def decrypt(ciphertextBytes, keyBytes, cbcMode):
    # Make expanded key
    keySize = len(keyBytes)
    expandedKey = None
    if (keySize == 16):
        expandedKey = keyExpansion128(keyBytes)
    elif (keySize == 24):
        expandedKey = keyExpansion192(keyBytes)
    elif (keySize == 32):
        expandedKey = keyExpansion256(keyBytes)
    
    print("Expanded Key:")
    printBytes(expandedKey, 16)

    plainText = []
    originalCiphertext = copy.deepcopy(ciphertextBytes)

    # For each 128 bit block, call decrypt128
    for block in range(0, len(ciphertextBytes), 16):
        print("Decrypting Ciphertext[", block, ":", block + 16, "]")

        if (cbcMode == 1 and block != 0):
            plainText = plainText + decrypt128(ciphertextBytes[block:block + 16], expandedKey, cbcMode, originalCiphertext[block - 16:block])
        else:
            plainText = plainText + decrypt128(ciphertextBytes[block:block + 16], expandedKey, 0, None)
    
    print("Entire Plaintext:")
    printBytes(plainText, 0)

# Convert a hex string to an array of bytes
def hexStringToBytes(hexString):
    ret = []
    for i in range(0, len(hexString), 2):
        if ((i + 1) >= len(hexString)):
            # Only one char
            ret.append(numToByteArray(int(hexString[i], base = 16)))
        else:
            ret.append(numToByteArray(int(hexString[i:i+2], base = 16)))
    
    return ret

# MAIN DRIVER CODE --------------------------------------------
initRoundConstants()

cryptoMode = int(input("Type (0 for encryption) or (1 for decryption): "))
inputMode = int(input("Choose input mode (0 = text input, 1 = file input): "))

if (cryptoMode == 0):
    textToEncrypt = None
    inputKey = None
    if (inputMode == 0):
        textToEncrypt = input("Enter text to encrypt: ")
        inputKey = input("Enter key: ")
    elif (inputMode == 1):
        textToEncryptFilename = input("Enter filename for text to encrypt: ")
        inputKeyFilename = input("Enter filename for key: ")
        textToEncryptFile = open(textToEncryptFilename, 'r')
        inputKeyFile = open(inputKeyFilename)
        textToEncrypt = textToEncryptFile.read()
        inputKey = inputKeyFile.read()

    cbc = int(input("Enter cbc mode (0 = ecb, 1 = cbc): "))
    inputKeyBytes = hexStringToBytes(inputKey)
    bytesToEncrypt = hexStringToBytes(textToEncrypt)
    encrypt(bytesToEncrypt, inputKeyBytes, cbc)

elif (cryptoMode == 1):
    textToDecrypt = None
    inputKey = None
    if (inputMode == 0):
        textToDecrypt = input("Enter text to decrypt: ")
        inputKey = input("Enter key: ")
    elif (inputMode == 1):
        textToDecryptFilename = input("Enter filename for text to decrypt: ")
        inputKeyFilename = input("Enter filename for key: ")
        textToDecryptFile = open(textToDecryptFilename, 'r')
        inputKeyFile = open(inputKeyFilename)
        textToDecrypt = textToDecryptFile.read()
        inputKey = inputKeyFile.read()

    cbc = int(input("Enter cbc mode (0 = ecb, 1 = cbc): "))
    inputKeyBytes = hexStringToBytes(inputKey)
    bytesToDecrypt = hexStringToBytes(textToDecrypt)
    decrypt(bytesToDecrypt, inputKeyBytes, cbc)

# -------------------------------------------------------------

# TESTS --------------
#
# initRoundConstants()
# print("Init ----------")
# print(KEY_ROUND_CONSTANTS)

# # Test addPoly ---
# print("\nXor tests ----------")
# polyList1 = [1, 1, 0, 0, 0, 0, 0, 1]
# polyList2 = [0, 1, 0, 0, 0, 1, 1, 0]
# print("PolyList1:  ", polyList1)
# print("PolyList2:  ", polyList2)
# polyList3 = xorPoly(polyList1, polyList2)
# print("Lists xored:", polyList3)

# # Test xtime ---
# print("\nxtime tests ----------")
# polyList1 = [0, 1, 1, 0, 1, 0, 1, 0]
# print("PolyList1:       ", polyList1)
# polyList1 = xtime(polyList1)
# print("xtime(PolyList1):", polyList1)
# polyList1 = xtime(polyList1)
# print("xtime(PolyList1):", polyList1)
# polyList1 = xtime(polyList1)
# print("xtime(PolyList1):", polyList1)

# # Test multPoly ---
# print("\nmultPoly tests ----------")
# polyList1 = [0, 1, 0, 0, 1, 0, 0, 1]
# polyList2 = [0, 0, 0, 0, 0, 1, 1, 0]
# print("PolyList1:  ", polyList1)
# print("PolyList2:  ", polyList2)
# polyList3 = multPoly(polyList1, polyList2)
# print("Lists multed:", polyList3)

# # Test conversion functions ---
# print("\nconversion tests ----------")
# polyList1 = [0, 1, 0, 1, 1, 0, 0, 1]
# print("PolyList1:                   ", polyList1)
# print("PolyList1 to num:  ", byteArrayToNum(polyList1))
# print("PolyList1 back to byte array:", numToByteArray(byteArrayToNum(polyList1)))
# linearList = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
# matrix = linearToMatrix(linearList)
# print("Linear list:", linearList)
# print("Converted to matrix:\n", matrix)
# linearAgain = matrixToLinear(matrix)
# print("Linear list again:", linearAgain)
# print("Plaintext:", "abcdefghijklmnop")
# print("Plaintext to bytes array:")
# printBytes(plainTextToBytes("abcdefghijklmnop"), 16)

# # rotateLeft test ---
# print("\nrotateLeft tests ----------")
# byte1 = [0, 1, 0, 1, 1, 0, 0, 1]
# byte2 = [0, 0, 0, 0, 0, 0, 0, 1]
# byte3 = [1, 1, 1, 1, 1, 0, 0, 1]
# byte4 = [0, 0, 0, 1, 0, 0, 0, 1]
# print("bytes:        ", byte1, byte2, byte3, byte4)
# (byte1, byte2, byte3, byte4) = rotateLeft(byte1, byte2, byte3, byte4)
# print("rotated bytes:", byte1, byte2, byte3, byte4)

# # subBytes test ---
# print("\nsubBytes tests ----------")
# polyList1 = [0, 1, 0, 1, 1, 0, 0, 1]
# print("PolyList1:       ", polyList1)
# print("PolyList1 subbed:", subBytes(polyList1))

# KEY EXPANSION CORE TESTS -----
# print("\nKey expansion core tests ----------")
# byte1 = numToByteArray(0xcc)
# byte2 = numToByteArray(0xdd)
# byte3 = numToByteArray(0xee)
# byte4 = numToByteArray(0xff)
# #print4Bytes(byte1, byte2, byte3, byte4)
# (byte1, byte2, byte3, byte4) = keyExpansionCore((byte1, byte2, byte3, byte4), 0)
# print("Core expanded round 0:")
#print4Bytes(byte1, byte2, byte3, byte4)

#KEY EXPANSION TESTS -----
# print("\nKey expansion core 128-bit tests ----------")
# initialKeyHex = [0x11, 0x55, 0x77, 0x22, 0x33, 0x88, 0x99, 0x11,
#                  0x00, 0x44, 0x22, 0x33, 0x14, 0x15, 0x16, 0xff]
# initialKey = [numToByteArray(i) for i in initialKeyHex]
# expansionKey = keyExpansion128(initialKey)
# print("Initial key:")
# printBytes(initialKey, 16)
# print("Expanded key:")
# printBytes(expansionKey, 16)

# print("\nKey expansion core 192-bit tests ----------")
# initialKeyHex = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
#                  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
#                  0x10, 0x11, 0x20, 0x21, 0x30, 0x31, 0x40, 0x41]
# initialKey = [numToByteArray(i) for i in initialKeyHex]
# expansionKey = keyExpansion192(initialKey)
# print("Initial key:")
# printBytes(initialKey, 24)
# print("Expanded key:")
# printBytes(expansionKey, 24)

# print("\nKey expansion core 256-bit tests ----------")
# initialKeyHex = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
#                  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
#                  0x10, 0x11, 0x20, 0x21, 0x30, 0x31, 0x40, 0x41,
#                  0x50, 0x51, 0x60, 0x61, 0x70, 0x71, 0x80, 0x81]
# initialKey = [numToByteArray(i) for i in initialKeyHex]
# expansionKey = keyExpansion256(initialKey)
# print("Initial key:")
# printBytes(initialKey, 32)
# print("Expanded key:")
# printBytes(expansionKey, 32)

# Mix Columns Test
# print("\nMix Columns test ----------")
# xtimePoly = MIX_COLUMNS_MATRIX[0]
# byteRow = [numToByteArray(0xef), numToByteArray(0xc3), numToByteArray(0x78), numToByteArray(0x73)]
# print(byteRow)
# mixedByte = mixOneColumn(xtimePoly, byteRow)
# print(mixedByte)

# print("\nEncryption 128-bit test ----------")
# initialKeyHex = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
#                  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
# initialKey = [numToByteArray(i) for i in initialKeyHex]
# expansionKey = keyExpansion128(initialKey)
# print("Initial key:")
# printBytes(initialKey, 16)
# print("Expanded key:")
# printBytes(expansionKey, 16)
# plaintext = "abcdefghijklmnop"
# print("Plaintext:", plaintext)
# encrypt128(plainTextToBytes(plaintext), expansionKey, 0)