#!/usr/bin/env python

import time
import collections
import bitcoin.ecdsa as BitcoinEcdsa

def main():
    ecdsa = BitcoinEcdsa.Ecdsa()

    print("GENERATE BITCOIN KEY PAIR:")
    time_start = time.time()
    private_key, public_key = ecdsa.make_keypair()
    d = private_key
    x = public_key[0]
    y = public_key[1]
    Q = ecdsa.public_key(public_key)
    print("Private key:")
    print("  d = %s" % str(hex(d))[2:])
    print("Public key:")
    print("  x = %s" % str(hex(x))[2:]) # 'x-coordinate' of bitcoin public key.
    print("  y = %s" % str(hex(y))[2:]) # 'y-coordinate' of bitcoin public key.
    print("  Q = %s" % Q) # 'pubKey' (uncompressed bitcoin public key) in bitcoin transaction.
    time_spent = time.time() - time_start
    print("Spent time: %.3f sec." % time_spent)

    print("")

    print("SIGN AND VERIFY BITCOIN TRANSACTION:")
    time_start = time.time()
    message = b"Hello!" 
    signature = ecdsa.sign_message(0, d, message)
    print("Signature:")
    print("  r = %s" % str(hex(signature[0]))[2:]) # 'sigR' in bitcoin transaction.
    print("  s = %s" % str(hex(signature[1]))[2:]) # 'sigS' in bitcoin transaction.
    print("  z = %s" % str(hex(signature[2]))[2:]) # 'sigZ' (message digest) in bitcoin transaction.
    print("Verification: %s" % ecdsa.verify_signature(public_key, signature))
    time_spent = time.time() - time_start
    print("Spent time: %.3f sec." % time_spent)

if __name__ == "__main__":
	main()
