# Clean RSA Module for Chat Application

import binascii
from random import randint

# -----------------------------
# Utility Functions
# -----------------------------

def str2hex(word):
    return binascii.hexlify(word.encode()).decode().upper()

def hex2bin(s):
    mp = {'0':"0000",'1':"0001",'2':"0010",'3':"0011",
          '4':"0100",'5':"0101",'6':"0110",'7':"0111",
          '8':"1000",'9':"1001",'A':"1010",'B':"1011",
          'C':"1100",'D':"1101",'E':"1110",'F':"1111"}
    return "".join(mp[i] for i in s)

def hexadecimalToDecimal(hexval):
    return int(hexval, 16)

# -----------------------------
# RSA KEY GENERATION
# -----------------------------

def calc():
    # simple fixed primes (stable for demo)
    P = [971,157,127,211,421]
    Q = [4783,3709,7547,6869,3001]

    r = randint(0,4)

    p = P[r]
    q = Q[r]

    n = p * q
    phi = (p - 1) * (q - 1)

    # choose e
    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a

    e = 3
    while gcd(e, phi) != 1:
        e += 2

    # compute d
    def modinv(a, m):
        for x in range(1, m):
            if (a * x) % m == 1:
                return x

    d = modinv(e, phi)

    return n, e, d

# -----------------------------
# MESSAGE PROCESSING
# -----------------------------

def preprocess_message(message, n):
    # convert string to ascii list
    mes = [ord(c) for c in message]

    # chunk message (simple version)
    pla = mes.copy()

    return pla, mes

# -----------------------------
# ENCRYPTION
# -----------------------------

def to_cipher(E, n, pla):
    cipher = []
    for p in pla:
        cipher.append(pow(p, E, n))
    return cipher

# -----------------------------
# DECRYPTION
# -----------------------------

def to_plain(D, n, cipher, mes):
    plain = []
    for c in cipher:
        plain.append(pow(c, D, n))

    # convert back to string
    text = "".join(chr(p) for p in plain)
    return text


# -----------------------------
# IMPORTANT:
# No execution code here
# -----------------------------