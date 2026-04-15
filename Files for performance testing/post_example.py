import sys
sys.path.append('Falcon')
import reconciliation as rc
import Quantum_Channel as qc
import numpy as np
from Falcon import falcon
import pickle5 as pc
import copy
import logging
import random

logging.basicConfig(filename="protcol.log", level=logging.INFO, format='%(levelname)s %(asctime)s %(message)s')


def falcon_keyGen(n):
    sk = falcon.SecretKey(n)
    pk = falcon.PublicKey(sk)
    return sk, pk
def flacon_signing(basis, sk):
    Basis = bytearray([ord(i) for i in basis])
    sig = sk.sign(Basis)
    return sig
def falcon_veryfy(basis, sig, pubkey):
    Basis = bytearray([ord(i) for i in basis])
    return pubkey.verify(Basis, sig)
def bob_signing(bob_basis):
    sk_bob, pk_bob = falcon_keyGen(1024)
    with open('Bob_Publickey.txt', 'wb') as fh:
        pc.dump(pk_bob, fh)
    logging.info('Bob_Publickey: %s', pk_bob)
    # Bob signing his basis
    Bob_signature = flacon_signing(bob_basis, sk_bob)
    print("bob signed his basis using falcon-1024")
    # Bob sending Bon_Signature, bob_basis
    return Bob_signature, bob_basis
def Alice_veryfy(Bob_signature,bob_basis):
    # Alice Verifying bob signature
    pk_bob_off = open("Bob_Publickey.txt", "rb")
    Bob_Pk_recived = pc.load(pk_bob_off)
    #bob_basis_attacked=random.shuffle(bob_basis)
    Alice_verify = falcon_veryfy(bob_basis, Bob_signature, Bob_Pk_recived)
    if Alice_verify == False:
        print('Verification failed')
        return False
    else:
        print("Alice verified the signature using Bob's falcon Public key")
        # print("Verification Successful Alice Side")
        return True
def send_basis(alice_basis, bob_basis):
    sk_Alice, pk_Alice = falcon_keyGen(1024)
    with open('Alice_Publickey.txt', 'wb') as fh:
        pc.dump(pk_Alice, fh)
    logging.info('Alice_Publickey: %s', pk_Alice)
    sk_bob, pk_bob = falcon_keyGen(1024)
    with open('Bob_Publickey.txt', 'wb') as fh:
        pc.dump(pk_bob, fh)
    logging.info('Bob_Publickey: %s', pk_bob)
    # Bob signing his basis
    Bob_signature = flacon_signing(bob_basis, sk_bob)
    print("bob signed his basis using falcon-1024")
    # Bob sending Bon_Signature, bob_basis

    # Alice Verifying bob signature
    pk_bob_off = open("Bob_Publickey.txt", "rb")
    Bob_Pk_recived = pc.load(pk_bob_off)
    Alice_verify = falcon_veryfy(bob_basis, Bob_signature, Bob_Pk_recived)
    if Alice_verify == False:
        print('Verification failed')
    else:
        print("Alice verified the signature using Bob's falcon Public key")
        # print("Verification Successful Alice Side")
        pass

    ALice_signature = flacon_signing(alice_basis, sk_Alice)  ## Alice signing her basis and sending her basis and sig
    print("Alice signed her basis using falcon")

    pk_Alice_off = open("Alice_Publickey.txt", "rb")
    Alice_Pk_recived = pc.load(pk_Alice_off)
    Bob_verify = falcon_veryfy(alice_basis, ALice_signature, Alice_Pk_recived)

    if Bob_verify == False:
        print('Verification failed')
    else:
        print("Bob verified the signature using Alice's falcon Public key")
        pass

    return True
def attack(basis):
    attack_base = basis.copy()
    random.shuffle(attack_base)
    return attack_base
def attack_basis(original_basis):
    basis = copy.deepcopy(original_basis)
    status=input("perform MIM attack at this stage : ")
    if status=='n':
        attack_status= False
        return basis, attack_status
    else:
        while True:
            basis_indices_str = input(f"enter basis_indices to flip (0-{len(basis) - 1})  ")
            basis_indices = [int(i) for i in basis_indices_str.split(',')]
            if all(0 <= i < len(basis) for i in basis_indices):
                break
            print(f"Invalid base indices. please enter basis indices between 0 and {len(basis) - 1}.")
        for i in basis_indices:
            if basis[i] == 'Z':
                basis[i] = 'X'
            elif basis[i] == 'X':
                basis[i] = 'Z'
        attack_status = True
        return basis,attack_status
def Alice_signing(alice_basis):
    sk_Alice, pk_Alice = falcon_keyGen(1024)
    with open('Alice_Publickey.txt', 'wb') as fh:
        pc.dump(pk_Alice, fh)
    logging.info('Alice_Publickey: %s', pk_Alice)
    ALice_signature = flacon_signing(alice_basis, sk_Alice)  ## Alice signing her basis and sending her basis and sig
    
    return ALice_signature,alice_basis
def Bob_veryfy(Alice_signature, alice_basis):
    pk_Alice_off = open("Alice_Publickey.txt", "rb")
    Alice_Pk_recived = pc.load(pk_Alice_off)
    Bob_verify = falcon_veryfy(alice_basis, Alice_signature, Alice_Pk_recived)
    if Bob_verify == False:
        print('Verification failed')
        return False
    else:
        print("Bob verified the signature using Alice's falcon Public key")
        return True
def shiftedKey(key, alice_basis, bob_basis):
    keep = []
    discard = []
    for qubit, basis in enumerate(zip(alice_basis, bob_basis)):
        if basis[0] == basis[1]:
            keep.append(qubit)
        else:
            discard.append(qubit)
    shift_key = ([int(key[qubit]) for qubit in keep])
    return shift_key
def shifted_key_pading(key):
    padkey = copy.deepcopy(key)
    count = 0
    while len(padkey) % 6 != 0:
        count += 1
        padkey.append(1)
    return np.array(padkey), count
def AddError(bob, error_prob):
    k = 0
    while k <= len(bob):
        error_mask = np.random.choice(2, size=bob.shape, p=[1.0 - error_prob, error_prob])
        error_list = list(np.where(error_mask, ~bob + 2, bob))

        if all([bob[i] == error_list[i] for i in range(len(bob))]) == False:
            break
    err = np.array(error_list)
    return err
def qber(bob_shift_key):
    bob_shift_key_err = list(AddError(np.array(bob_shift_key), 0.08))
    return bob_shift_key_err



def protocol_with_mim(): #Perfoms man in the middile attacks
    n=6
    alice_shift_key = []
    while len(alice_shift_key) < (12):
        alice_key, alice_basis, bob_key, bob_basis = qc.Quantum_Channel(4*n)
        print('alice_basis:',alice_basis)
        print('bob_basis',bob_basis)
        Bob_signature,bob_basis=bob_signing(bob_basis)
        bob_basis_attacked, mim_status_bb =attack_basis(bob_basis)
        print('bob basis_ is:',bob_basis_attacked)
        Alice_veryfy_status=Alice_veryfy(Bob_signature, bob_basis_attacked)
        if not Alice_veryfy_status:
            print("Basis information changed")
            print("man in the middle attack detected  ")
            break
        Alice_signature,alice_basis=Alice_signing(alice_basis)
        Alice_basis_attacked, mim_status_ab =attack_basis(alice_basis)
        if not mim_status_ab:
            print("no more communications to perform mim attack")
            break
        print('Alice_basis_attacked is :',Alice_basis_attacked)
        Bob_veryfy_status=Alice_veryfy(Alice_signature, Alice_basis_attacked)
        if not Bob_veryfy_status:
            print("Basis information changed")
            print("man in the middle attack detected  ")
            break
        alice_shift_key = shiftedKey(alice_key, alice_basis, bob_basis)
        bob_shift_key = shiftedKey(bob_key, alice_basis, bob_basis)
        bob_shift_key_err = qber(bob_shift_key)
        Rc_status, Rc_key = ReconciliationH(alice_shift_key, bob_shift_key_err)
        if Rc_status:
            #print("Alice Raw Key:",alice_key)
            #print("Bob Measured Key:",bob_key)
            print("Reconciliation Successful")
            print('Alice_shift_key:', alice_shift_key)
            print("Bob_shift_key_error:", bob_shift_key_err)
            print("Reconciled key:", Rc_key)
            return alice_shift_key, Rc_key
        else:
            pass


def protocol_without_mim():
    n=6
    alice_shift_key = []
    while len(alice_shift_key) < (12):
        alice_key, alice_basis, bob_key, bob_basis = qc.Quantum_Channel(4*n)
        send_basis(alice_basis, bob_basis)
        alice_shift_key = shiftedKey(alice_key, alice_basis, bob_basis)
        bob_shift_key = shiftedKey(bob_key, alice_basis, bob_basis)
        bob_shift_key_err = qber(bob_shift_key)
        NTRU_Bob = NTRU_gen('bob', 503, 3, 256)
        NTRU_Alice = NTRU_gen('Alice', 503, 3, 256)
        Rc_status, Rc_key = ReconciliationH(alice_shift_key, bob_shift_key_err, NTRU_Alice, NTRU_Bob)
        if Rc_status:
            #print("Alice Raw Key:",alice_key)
            #print("Bob Measured Key:",bob_key)
            print("Reconciliation Successful")
            print('Alice_shift_key:', alice_shift_key)
            print("Bob_shift_key_error:", bob_shift_key_err)
            print("Reconciled key:", Rc_key)
            return alice_shift_key, Rc_key
        else:
            pass




def protocol():
    mim = input("Man in the middle attack required or not: ")
    if mim=='y':
        protocol_with_mim()
    else:
        protocol_without_mim()



if __name__ == "__main__":
    protocol()

logging.shutdown()
