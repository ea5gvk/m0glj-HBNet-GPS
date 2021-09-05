# Script to generate a key for Encrypted OpenBridge

from cryptography.fernet import Fernet
import re

def gen_key():
    key = Fernet.generate_key()
    return key

print('Key: ' + str(gen_key())[2:-1])
