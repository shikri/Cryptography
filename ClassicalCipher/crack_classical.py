#!/usr/bin/env python

import sys
from BitVector import *                                                       #(A)

if len(sys.argv) is not 3:                                                    #(B)
    sys.exit('''Needs two command-line arguments, one for '''
             '''the encrypted file and the other for the '''
             '''cracked output file''')


PassPhrase = "Cryptography is the art of  secret writing"                     #(C)

BLOCKSIZE = 64                                                                #(D)
numbytes = BLOCKSIZE // 8                                                     #(E)

# Reduce the passphrase to a bit array of size BLOCKSIZE:
bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)                                    #(F)
for i in range(0,len(PassPhrase) // numbytes):                                #(G)
    textstr = PassPhrase[i*numbytes:(i+1)*numbytes]                           #(H)
    bv_iv ^= BitVector( textstring = textstr )                                #(I)

# Get key from user:
key_bv = BitVector(textstring="        ")                                                            #(M)


count = [dict() for x in range(8)]

# Create a bitvector for storing the ciphertext bit array:
msg_encrypted_bv = BitVector( size = 0 )                                      #(R)

# Carry out differential XORing of bit blocks and encryption:
previous_block = bv_iv                                                        #(S)
bv = BitVector( filename = sys.argv[1] )                                      #(T)
while (bv.more_to_read):                                                      #(U)
    bv_read = bv.read_bits_from_file(BLOCKSIZE*2)
    bv_read = bv_read.get_bitvector_in_ascii()
    bv_read = BitVector(hexstring = bv_read)                                  #(V)
    temp = bv_read.deep_copy()
    if len(bv_read) < BLOCKSIZE:                                              #(W)
        bv_read += BitVector(size = (BLOCKSIZE - len(bv_read)))               #(X)
    bv_read ^= key_bv                                                         #(Y)
    bv_read ^= previous_block                                                 #(Z)
    previous_block = temp.deep_copy()          		                          #(a)
    msg_encrypted_bv += bv_read                                               #(b)

    bv_read = bv_read.get_bitvector_in_ascii()
    for i in range(8): 
        if bv_read[i] in count[i]: 
            count[i][bv_read[i]] += 1
        else: 
            count[i][bv_read[i]] = 1

finalKey = ""
for i in range(8):
    finalKey += max(count[i], key=count[i].get)
finalKey_bv = BitVector(textstring=finalKey)^key_bv

msg_cracked_bv = BitVector(size=0)
for i in range(0,len(msg_encrypted_bv),64):
    msg_cracked_bv += msg_encrypted_bv[i:i+64]^finalKey_bv

# Convert the encrypted bitvector into a hex string:    
outputascii = msg_cracked_bv.get_bitvector_in_ascii()                  #(c)
# print(outputascii)

# Write ciphertext bitvector to the output file:
FILEOUT = open(sys.argv[2], 'w')                                              #(d)
FILEOUT.write(outputascii)                                                      #(e)
FILEOUT.close()                                                               #(f)
