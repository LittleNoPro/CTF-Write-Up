import hashlib

def xor_bytes(b1, b2):
    return bytes(a ^ b for a, b in zip(b1, b2))

def sha256_hash(data):
    return hashlib.sha256(data).digest()

def decrypt_xor_known_plaintext(ciphertext_hex, known_plaintext):
    ciphertext = bytes.fromhex(ciphertext_hex)

    block_size = 32
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]

    key = xor_bytes(blocks[0], known_plaintext.encode())

    decrypted_plaintext = known_plaintext
    for block in blocks[1:]:
        key = sha256_hash(key)
        decrypted_block = xor_bytes(block, key)
        decrypted_plaintext += decrypted_block.decode(errors="ignore")

    return decrypted_plaintext

ciphertext_hex = "146ffa07f717a0a1cd51be5f725e14d2f7e2db4791541e53c5e5243294d17d931506978bc85d22d0e0e77ea5a44f7da392404acb8dbfd58ea4652fb67a44b7b157d8a5d51e5044a9fe4254bb7fbb5aadc5e466fa1945f7bdf5687f58eaee70fc1553250a46346116648a5d32e399c6722b5ff0d36592f9b23dafc7dca76d2d77a7197febbf33cfd03d37e3fea9b4b63cf006d6e8cc5633b3627a0b00a522bc565dfef21580a2a5d6e4bb72741257af038cc77923670c47efa35476cc435fee419d510be571a300ef76f4e89ed1bc404a58de5c4f16421553d5682bce58f30bc6"
known_plaintext = "Great and Noble Leader of the Ta"

decrypted_message = decrypt_xor_known_plaintext(ciphertext_hex, known_plaintext)
print("Decrypted Message:", decrypted_message)