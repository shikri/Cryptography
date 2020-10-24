#!/usr/bin/env python

import sys
from BitVector import *                                                       #(A)
from key_mtp import get_key

if len(sys.argv) is not 3:                                                    #(B)
    sys.exit('''Needs two command-line arguments, one for '''
             '''the message file and the other for the '''
             '''encrypted output file''')

# Create a bitvector for storing the ciphertext bit array:
msg_encrypted_bv = BitVector( size = 0 )                                      #(R)

filename = sys.argv[1] 
file = open(filename,"r")
content = file.read()

bv_read = BitVector(textstring = content)
msg_encrypted_bv = bv_read^get_key(len(bv_read))

# Convert the encrypted bitvector into a hex string:    
outputhex = msg_encrypted_bv.get_hex_string_from_bitvector()                  #(c)

# Write ciphertext bitvector to the output file:
FILEOUT = open(sys.argv[2], 'w')                                              #(d)
FILEOUT.write(outputhex)                                                      #(e)
FILEOUT.close()                                                               #(f)