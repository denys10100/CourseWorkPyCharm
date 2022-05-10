#from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from LibraryProject.DHx25519 import GENERATE_DH, DH


#GENERATE_DH() +
#DH(dh_pair, dh_pub) +
# KDF_RK(SK, DH(state.DHs, state.DHr))
# SK, bob_dh_public_key, state.RK, state.CKs, CKr,  MKSKIPPED ?

# SK - корневой согласованый ключ

class Alice(object):
    def __init__(state):
        # generate Alice's keys
        state.IKa = GENERATE_DH()
        state.EKa = GENERATE_DH()
    
    def RatchetInitAlice(state, SK, bob_dh_public_key):
        state.DHs = GENERATE_DH()
        state.DHr = bob_dh_public_key
        state.RK, state.CKs = KDF_RK(SK, DH(state.DHs, state.DHr))
        state.CKr = None
        state.Ns = 0
        state.Nr = 0
        state.PN = 0
        state.MKSKIPPED = {}
    
    # def x3dh(state, bob):
    #     # perform the 4 Diffie Hellman exchanges (X3DH)
    #     dh1 = DH(state.IKa, bob.SPKb)
    #     dh2 = DH(state.EKa, bob.IKb)
    #     dh3 = DH(state.EKa, bob.SPKb)
    #     dh4 = DH(state.EKa, bob.OPKb.public_key())
    #     # the shared key is KDF(DH1||DH2||DH3||DH4)
    #     # state.sk = hkdf(dh1 + dh2 + dh3 + dh4, 32)
    #     # print('[Alice]\tShared key:', b64(state.sk))
        
class Bob(object):
    
    def __init__(state):
        # generate Bob's keys
        state.IKb = GENERATE_DH()
        state.SPKb = GENERATE_DH()
        state.OPKb = GENERATE_DH()
    
    def RatchetInitBob(state, SK, bob_dh_key_pair):
        state.DHs = bob_dh_key_pair
        state.DHr = None
        state.RK = SK
        state.CKs = None
        state.CKr = None
        state.Ns = 0
        state.Nr = 0
        state.PN = 0
        state.MKSKIPPED = {}

    def x3dh(state, alice):
        # perform the 4 Diffie Hellman exchanges (X3DH)
        dh1 = DH(state.SPKb, alice.IKa.public_key())
        dh2 = DH(state.IKb, alice.EKa.public_key())
        dh3 = DH(state.SPKb, alice.EKa.public_key())
        dh4 = DH(state.OPKb, alice.EKa.public_key())

        # the shared key is KDF(DH1||DH2||DH3||DH4)
        # state.sk = hkdf(dh1 + dh2 + dh3 + dh4, 32)
        # print('[Bob]\tShared key:', b64(state.sk))

alice = Alice()
bob = Bob()
print(bob.IKb)

# Alice performs an X3DH while Bob is offline, using his uploaded keys
alice.x3dh(bob)
#
# # Bob comes online and performs an X3DH using Alice's public keys
# bob.x3dh(alice)