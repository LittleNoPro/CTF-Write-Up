def otp_decrypt(p, k):
    k_r = (k * ((len(p) // len(k)) + 1))[:len(p)]
    return bytes([p ^ k for p, k in zip(p, k_r)])

def check_cat_box_decrypt(ciphertext, cat_state):
    c = bytearray(ciphertext)
    if cat_state == 1:
        for i in range(len(c)):
            c[i] ^= 0xAC
            c[i] = (c[i] >> 1) | ((c[i] & 1) << 7)
    else:
        for i in range(len(c)):
            c[i] ^= 0xCA
            c[i] = ((c[i] << 1) & 0xFF) | (c[i] >> 7)
    return bytes(c)


c_ciphertext = "4b49e0d0c0d647585f5d60db46e6ca634e625fda57ccd15ee061da63c1e2575cdec3d96043cf48ce5dcdcfc9e156ce6350506266e6615ce2566062dadcdbd9e1505258da5bdb5e626253c853ce46c2c8e04ec2d0dcd9ce6157d6d6d063dec0da4c53d0e0e646c05f5c4353dcd152dc4dc350cfd25b52ce51dbe0d15e62e2d9d64058c3de5ecf4fcddcd6dcc1665ee3cfcd5dcb465766dde14c49d9e651c1d6c6"
c_ciphertext = bytes.fromhex(c_ciphertext)

ciphertext = check_cat_box_decrypt(c_ciphertext, 0)

plaintext = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
plaintext = plaintext.encode('utf-8')

KEY = otp_decrypt(ciphertext, plaintext)

Encrypted = "31055d271a3d132a2d2b46640b1902531c10232f7a0c773940572f46025c7a2e201d231852222a3d0728392e6311125667605467094413053405467230632f5e3034212f6e632051423645260658170c5b0c5f750434495f2e7938395b3f106d4c3d27155119066a2a1326287732280b1d741821373e56760a5b773b4541222b042b00203c0205016179391f5d68540a022b440b7a562a410914675d39193c57"
Encrypted = bytes.fromhex(Encrypted)
FLAG = otp_decrypt(KEY, Encrypted)

print(FLAG.decode('utf-8'))
