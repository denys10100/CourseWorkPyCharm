import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from Cryptodome.Cipher import AES


def b64(msg):
    # base64 допоміжна функція кодування
    return base64.encodebytes(msg).decode('utf-8').strip()

def hkdf(inp, length):
    # використовуєм HKDF на вході, щоб отримати ключ
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=b'',
                info=b'', backend=default_backend())
    return hkdf.derive(inp)

def pad(msg):
    num = 16 - (len(msg) % 16)
    return msg + bytes([num] * num)

def unpad(msg):
    # видалити заповнення pkcs7
    return msg[:-msg[-1]]

# Realize Symmetric Ratchet
class SymmetricRatchet(object):
    def __init__(state, key):
        state.state = key #kdf key

    def next(state, inp=b''):
        # повернем храповик, изменив состояние и получив новый ключ и IV
        output = hkdf(state.state + inp, 80)
        state.state = output[:32]
        outkey, iv = output[32:64], output[64:]
        return outkey, iv


class Bob(object):
    def __init__(state):

        state.IKb = X25519PrivateKey.generate()
        state.SPKb = X25519PrivateKey.generate()
        state.OPKb = X25519PrivateKey.generate()
        state.DHratchet = X25519PrivateKey.generate()

    def x3dh(state, alice):

        dh1 = state.SPKb.exchange(alice.IKa.public_key())
        dh2 = state.IKb.exchange(alice.EKa.public_key())
        dh3 = state.SPKb.exchange(alice.EKa.public_key())
        dh4 = state.OPKb.exchange(alice.EKa.public_key())

        state.sk = hkdf(dh1 + dh2 + dh3 + dh4, 32)
        print('[Bob]\tShared key:', b64(state.sk))

    def RatchetInitBob(state):

        state.root_ratchet = SymmetricRatchet(state.sk)

        state.recv_ratchet = SymmetricRatchet(state.root_ratchet.next()[0])
        state.send_ratchet = SymmetricRatchet(state.root_ratchet.next()[0])

    def dh_ratchet(state, alice_public):

        dh_recv = state.DHratchet.exchange(alice_public)
        shared_recv = state.root_ratchet.next(dh_recv)[0]

        state.recv_ratchet = SymmetricRatchet(shared_recv)
        print('[Bob]\tRecv ratchet seed:', b64(shared_recv))

        state.DHratchet = X25519PrivateKey.generate()
        dh_send = state.DHratchet.exchange(alice_public)
        shared_send = state.root_ratchet.next(dh_send)[0]
        state.send_ratchet = SymmetricRatchet(shared_send)
        print('[Bob]\tSend ratchet seed:', b64(shared_send))

    def send(state, alice, msg):
        key, iv = state.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        print('[Bob]\tSending ciphertext to Alice:', b64(cipher))
        # send ciphertext and current DH public key
        alice.recv(cipher, state.DHratchet.public_key())

    def recv(state, cipher, alice_public_key):
        # отримати новий відкритий ключ Аліси і використовувати його для виконання DH
        state.dh_ratchet(alice_public_key)
        key, iv = state.recv_ratchet.next()
        # розшифрує повідомлення за допомогою нової трещотки recv
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher))
        print('[Bob]\tDecrypted message:', msg)

    # def dh_ratchet_rotation_send(state, public_key: bytes) -> None:
    #     state.DHratchet = X25519PrivateKey.generate()
    #     dh_send = state.DHratchet.exchange(public_key)
    #     shared_send = state.root_ratchet.next(dh_send)[0]
    #     state.send_ratchet = SymmetricRatchet(shared_send)
    #

class Alice(object):
    def __init__(state):
        #згенерувати ключі Аліси
        state.IKa = X25519PrivateKey.generate()
        state.EKa = X25519PrivateKey.generate()
        state.DHratchet = None

    def x3dh(state, bob):
        # виконати 4 обміни Діффі Хеллмана (X3DH)
        dh1 = state.IKa.exchange(bob.SPKb.public_key())
        dh2 = state.EKa.exchange(bob.IKb.public_key())
        dh3 = state.EKa.exchange(bob.SPKb.public_key())
        dh4 = state.EKa.exchange(bob.OPKb.public_key())
        # спільний ключ KDF(DH1||DH2||DH3||DH4)
        state.sk = hkdf(dh1 + dh2 + dh3 + dh4, 32)
        print('[Alice]\tShared key:', b64(state.sk))

    def RatchetInitAlice(state):
        # ініціалізуйте кореневий ланцюжок за допомогою спільного ключа
        state.root_ratchet = SymmetricRatchet(state.sk)

        state.send_ratchet = SymmetricRatchet(state.root_ratchet.next()[0])
        state.recv_ratchet = SymmetricRatchet(state.root_ratchet.next()[0])

    def dh_ratchet(state, bob_public):
        if state.DHratchet is not None:
            #для першого разу
            dh_recv = state.DHratchet.exchange(bob_public)
            shared_recv = state.root_ratchet.next(dh_recv)[0]
            state.recv_ratchet = SymmetricRatchet(shared_recv)
            print('[Alice]\tRecv ratchet seed:', b64(shared_recv))

        state.DHratchet = X25519PrivateKey.generate()
        dh_send = state.DHratchet.exchange(bob_public)
        shared_send = state.root_ratchet.next(dh_send)[0]
        state.send_ratchet = SymmetricRatchet(shared_send)
        print('[Alice]\tSend ratchet seed:', b64(shared_send))

    def send(state, bob, msg):
        key, iv = state.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        print('[Alice]\tSending ciphertext to Bob:', b64(cipher))
        # надіслати зашифрований текст і поточний відкритий ключ DH
        bob.recv(cipher, state.DHratchet.public_key())

    def recv(state, cipher, bob_public_key):
        # отримати новий відкритий ключ Боба і використовувати його для виконання DH
        state.dh_ratchet(bob_public_key)
        key, iv = state.recv_ratchet.next()
        # розшифрує повідомлення за допомогою нової ratchet recv
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher))
        print('[Alice]\tDecrypted message:', msg)

    # def dh_ratchet_rotation_send(state, public_key: bytes):
    #     state.DHratchet = X25519PrivateKey.generate()
    #
    #     dh_send = state.DHratchet.exchange(public_key)
    #     shared_send = state.root_ratchet.next(dh_send)[0]
    #
    #     state.send_ratchet = SymmetricRatchet(shared_send)
    #
    #     print('[Alice]\tSend ratchet seed:', b64(shared_send))



    
alice = Alice()
bob = Bob()

alice.x3dh(bob)

bob.x3dh(alice)

alice.RatchetInitAlice()
bob.RatchetInitBob()

alice.dh_ratchet(bob.DHratchet.public_key())

alice.send(bob, b'Start dialogue !')

bob.send(alice, b'sdsdsd')
alice.send(bob, b'Hello !')


