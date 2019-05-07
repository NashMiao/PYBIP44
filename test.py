# -*- coding: utf-8 -*-

from pybip44 import HDPrivateKey
from pybip44.hdkeys.hd_public_key import HDPublicKey

if __name__ == '__main__':
    master_key = HDPrivateKey.master_key_from_mnemonic(
        'obscure worry home pass museum toss else accuse limb hover denial alpha', 'ont')
    print('Master Key: ', master_key.to_hex())

    print('------------------------------------------')

    root_keys = HDPrivateKey.from_path(master_key, "m/44'/1024'/0'")
    acct_pri_key = root_keys[-1]
    acct_pub_key = acct_pri_key.public_key
    print('Account Master Public Key (Hex): ' + acct_pub_key.to_hex())
    print('Account Master Private Key (Hex): ' + acct_pri_key.to_hex())
    print('------------------------------------------')
    for i in range(10):
        print("Index %s:" % i)

        hd_private_key = HDPrivateKey.from_path(root_keys[-1], '{change}/{index}'.format(change=0, index=i))
        hd_public_key = hd_private_key[-1].public_key
        print("Private Key (HEX): " + hd_private_key[-1].to_hex())
        print("Public Key (HEX): ", hd_public_key.to_hex())
        print("Address: " + hd_public_key.address)

        print('------------------------------------------')

        hd_private_key = HDPublicKey.from_path(acct_pub_key, '{change}/{index}'.format(change=0, index=i))
        hd_public_key = hd_private_key[-1]
        print("Public Key (HEX): ", hd_public_key.to_hex())
        print("Address: " + hd_public_key.address)

        print('******************************************')
