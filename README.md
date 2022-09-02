# AES-Implementation
A command-line python program that encrypts and decrypts text using the AES algorithm

# How to Run:
My AES program should be run from the command line without any parameters. The user will
first be asked which mode to run the software in (encryption or decryption). The user will then
be prompted to choose file mode or text mode. File mode allows the user to input a filename for
the plaintext and key,while text mode allows the user to input hexadecimal text directly. The user
is also prompted to choose between cbc mode and ecb mode through a text input prompt.
My implementation will only accept key sizes of 16, 24, and 32 bytes and plaintexts that can be
broken up into 16 byte chunks evenly.

# Study of Entropy

I encrypted two 16-byte plaintexts, one with low entropy and one with high entropy, using the
same key and calculated the entropy of each resulting ciphertext:


Key: 8e0ab6172861baef816eba892c52615f

Plaintext 1: 00000000000000000000000000000000

Frequency of “1” = 0

Frequency of “0” = 128

[Entropy of plaintext 1] = 0


Plaintext 2: 2136BA8C76E8081C7D6DDBAD71823BAC

Frequency of “1” = 64

Frequency of “0” = 64

[Entropy of plaintext 2] = 1


Ciphertext 1: 323b68bfcf1cb411a45a49a1ba97762e

Frequency of “1” = 65

Frequency of “0” = 63

[Entropy of ciphertext 1] = 0.99982


Ciphertext 2: c4aeee60b2f1e75ecaec4a58551a1ce4

Frequency of “1” = 65

Frequency of “0” = 63

[Entropy of ciphertext 2] = 0.99982


As we can see from this experiment, the entropy of both ciphertexts is 0.99982 even though the
entropy of plaintext 1 is very low and the entropy of plaintext 2 is very high. This shows that the
difference in entropy of the plaintexts is not visibly reflected in the entropy of the ciphertexts.

# Altering One Bit of Key

Now I will alter one bit of the key. The hex value of the new key is:

Key: 8E4AB6172861BAEF816EBA892C52615F

New ciphertext1 (xor) ciphertext1 = 5d4fa3eb8707418339337ea52784bd61

The amount of bits that changed from ciphertext1 to the new ciphertext1 is 65. This is
about 51% of the total bits.

New ciphertext2 (xor) ciphertext2 = dc5338763eaec77fb5d779e6b9575076
The amount of bits that changed from ciphertext2 to the new ciphertext2 is 77. This is
about 60% of the total bits.

Since changing one single bit of the key changed about 50% of the bits in each ciphertext an
attacker would probably not be able to identify which single bit was altered because the
ciphertexts with the altered key are extremely different from the ciphertexts with the original key.

# Altering Key Length

Now I will add 8 bytes to the key length. The hex value of the new key is:

Key: 8e0ab6172861baef816eba892c52615f81EF6A7283945B7D

New ciphertext1 (xor) ciphertext1 = 772bf202aac752920c4aed9d7dffe6f4

The amount of bits that changed from ciphertext1 to the new ciphertext1 is 71. This is
about 55% of the total bits.

New ciphertext2 (xor) ciphertext2 = 368fdd312747cbe483007463e3c389f2
The amount of bits that changed from ciphertext2 to the new ciphertext2 is 63. This is
about 49% of the total bits.

Since changing the key length to 24 bytes changed about 50% of the bits in each ciphertext an
attacker would probably not be able to determine the key length by looking at the difference in
each ciphertext because the ciphertexts created using the 24-byte key are extremely different
from the ciphertexts created using the original 16-byte key.
