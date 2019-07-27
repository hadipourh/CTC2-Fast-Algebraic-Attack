![CTC(B = 10, Nr)](https://github.com/hadipourh/CTC2-Fast-Algebraic-Attack/blob/master/Pictures/CTC_10.svg)
# CTC2-Fast-Algebraic-Attack
A python class implementing Courtois Toy Cipher (CTC2), equipped with some methods to algebaic cryptanalysis of CTC2.

## What is CTC?

CTC is a toy cipher designed by Courtois, in order to study algebraic attacks on block ciphers. Although it is very similar to the other block ciphers such as Present, it is not a real encryption tool. Soon after Courtois published CTC for the first time in [1], Dunkelman and Keller showed that a few bits of the key can be recovered by linear cryptanalysis [2], which cannot however compromise a security of a larger key. Although CTC had been presented only for studying algebraic attack, Courtois decided to revise it so that it is also secure against linear cryptanalysis, and that's why he presented the second version of CTC called CTC2 in [3]. there is little difference between CTC and CTC2,  but CTC2 is more secure against linear cryptanalysis.

## What can you do by these codes?

The ``CTC2.py`` inlcudes a class called CTC, which is equipped with some methods to generate algebraic equations of CTC2 over  finite field GF(2). A Jupyter file named ``CTC.ipynb`` shows you, how to use this class in SageMath software to extract algebraic equations of CTC2 over GF(2), and solve them via a SAT solver such as Cryptominisat. Therefore you can generate CTC2 equations, and try to break CTC2 via solving the extracted equations with your own way, which may be better than the previous methods. Currently up to 10 rounds of CTC2 have been broken by algebraic attacks.

[1]: [How Fast can be Algebraic Attacks on Block Ciphers? (2006)](https://eprint.iacr.org/2006/168)

[2]: [Linear Cryptanalysis of CTC (2006)](https://eprint.iacr.org/2006/250)

[3]: [CTC2 and Fast Algebraic Attacks on Block Ciphers Revisited (2007)](https://eprint.iacr.org/2007/152)
