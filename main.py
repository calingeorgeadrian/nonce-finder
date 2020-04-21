import binascii
import hashlib, struct
from random import randint

ver = 0x20400000
prev_block = "00000000000000000006a4a234288a44e715275f1775b77b2fddb6c02eb6b72f"
mrkl_root = "2dc60c563da5368e0668b81bc4d8dd369639a1134f68e425a9a74e428801e5b8"
time_ = 0x5DB8AB5E
bits = 0x17148EDF

exp = bits >> 24
mant = bits & 0xffffff
target_hexstr = '%064x' % (mant * (1 << (8 * (exp - 3))))
target_str = binascii.unhexlify(target_hexstr)

nonce1_found = False
nonce1 = None
hash1 = None
first_five = []
nonce2_start = None
nonce2_found = False
nonce2 = None
hash2 = None
tests_done = None

nonce_start = 3000000000
nonce_limit = 3100000000

nonce = nonce_start
while nonce < nonce_limit:
    header = (struct.pack("<L", ver) + binascii.unhexlify(prev_block)[::-1] +
              binascii.unhexlify(mrkl_root)[::-1] + struct.pack("<LLL", time_, bits, nonce))
    hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()

    hash_val = binascii.hexlify(hash[::-1])

    if nonce <= nonce_start + 4:
        first_five.append(hash_val)

    if hash[::-1] < target_str:
        nonce1_found = True
        nonce1 = nonce
        hash1 = hash_val.decode('utf-8')

        nonce2_start = randint(nonce1 + 1, nonce1 + 100000000)
        new_nonce = nonce2_start
        while new_nonce < nonce2_start + 100000000:
            header2 = (struct.pack("<L", ver) + binascii.unhexlify(prev_block)[::-1] +
                      binascii.unhexlify(mrkl_root)[::-1] + struct.pack("<LLL", time_, bits, new_nonce))
            hash2 = hashlib.sha256(hashlib.sha256(header2).digest()).digest()

            hash_val2 = binascii.hexlify(hash2[::-1])

            if hash2[::-1] < target_str:
                nonce2_found = True
                nonce2 = new_nonce
                hash2 = hash_val2.decode('utf-8')
                tests_done = new_nonce - nonce2_start
                break

            new_nonce += 1
        break
    nonce += 1

print('Cazul 1:')
print('Nonce1:', nonce1, '(', hex(nonce1), ')')
print('Block Hash:', hash1)
print('Primele 5 valori hash:')
for val in first_five:
    print(val.decode('utf-8'))

print('Cazul 2:')
print('Nonce2 start:', nonce2_start)
if nonce2_found:
    print('Numar testari:', tests_done)
    print('Succes: DA')
    print('Nonce2:', nonce2, '(', hex(nonce2), ')')
    print('Block Hash:', hash2)
else:
    print('Numar testari:', 100000000)
    print('Succes: NU')
    print('Nonce2: -')
    print('Block Hash: -')