from Crypto.Util.number import long_to_bytes, inverse

c = 8533139361076999596208540806559574687666062896040360148742851107661304651861689
n =769457290801263793712740792519696786147248001937382943813345728685422050738403253
e = 65537

"""
N is too small leads to Factorized Large Integers 
This is known as the first attack on RSA public key (N, e). After getting the factorization of N, an attacker can easily construct φ(N),
from which the decryption exponent d = e-1 mod φ(N) can be found. Factoring the modulus is referred to as brute-force attack
RSA encryption:

N = p*q
"""

p = 1617549722683965197900599011412144490161
q = 475693130177488446807040098678772442581573

totient = (p-1) * (q-1)

"""
Calculate d=e^-1
"""
d = inverse(e, totient)

"""
Decrypt message M = C^d mod N
"""

M = pow(c, d, n)
print (long_to_bytes(M))