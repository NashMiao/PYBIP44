# -*- coding: utf-8 -*-
import hashlib
import hmac

from pybip44.chain_private_key import ONTPrivateKey
from pybip44.chain_public_key import ONTPublicKey
from .hd_key import HDKey, HARDENED_HEXA


class HDPublicKey(HDKey):

    def __init__(self, public_key, chain_code, index, depth,
                 parent_fingerprint=b'\x00\x00\x00\x00'):

        HDKey.__init__(self, public_key, chain_code, index, depth, parent_fingerprint)

    @property
    def compressed_bytes(self):
        """ Byte string corresponding to a compressed representation
        of this public key.

        Returns:
            b (bytes): A 33-byte long byte string.
        """
        return self._key.compressed_bytes

    @property
    def identifier(self):
        """ Returns the identifier for the key.

        A key's identifier and fingerprint are defined as:
        https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#key-identifiers

        In this case, it will return the RIPEMD-160 hash of the
        non-extended public key.

        Returns:
            bytes: A 20-byte RIPEMD-160 hash.
        """
        return self._key.hash160(True)

    @property
    def address(self, compressed=True):
        return self._key.address(compressed)

    def to_hex(self, compressed=True):
        return self._key.to_hex(compressed)

    @staticmethod
    def from_parent(parent_key, i):
        if i & 0x80000000:
            raise ValueError("Can't generate a hardened child key from a parent public key.")
        else:
            I = hmac.new(parent_key.chain_code,
                         parent_key.compressed_bytes + i.to_bytes(length=4, byteorder='big'),
                         hashlib.sha512).digest()
            Il, Ir = I[:32], I[32:]
            parse_Il = int.from_bytes(Il, 'big')
            if parse_Il >= parent_key._key.curve_g_n:
                return None

            temp_priv_key = ONTPrivateKey(parse_Il)
            Ki = temp_priv_key.public_key.point + parent_key._key.point
            if Ki.IsInfinity:
                return None

            child_depth = parent_key.depth + 1
            return HDPublicKey(public_key=ONTPublicKey(Ki),
                               chain_code=Ir,
                               index=i,
                               depth=child_depth,
                               parent_fingerprint=parent_key.fingerprint)
