# Many-Time Pad Attack

## Overview
This project recovers the plaintext of a ciphertext encrypted under a **reused one-time pad (OTP)** — a classic cryptographic flaw known as the **many-time pad attack**.  Because XOR is a reversible and symmetric operation, if two ciphertexts share the same key, their XOR gives the XOR of their plaintexts:
```
C1 ⊕ C2 = (P1 ⊕ K) ⊕ (P2 ⊕ K) = P1 ⊕ P2
```

This relationship enables statistical inference of the underlying key by exploiting patterns in natural language, especially the frequent use of spaces.

---

## Methodology

1. **Hex Decoding**  
   All ciphertexts are converted from hexadecimal strings into byte arrays for bitwise manipulation.

2. **Pairwise XOR Analysis**  
   Every pair of ciphertexts is XORed. When a byte in the XOR output corresponds to an alphabetic ASCII character, it strongly suggests that **one of the plaintexts contains a space (' ')** at that position.

3. **Key Reconstruction**  
   If ciphertext `i` is assumed to have a space at index *k*, the corresponding key byte is derived as:
    ```
    key[k] = ciphertext[i][k] ⊕ 0x20
    ```

The derived key byte is validated by checking whether it produces printable characters in other ciphertexts.

4. **Heuristic Completion**  
For undeciphered positions, frequent English letters (`e, t, a, o, i, n, s, h, r`) are tested to identify key bytes that yield mostly readable text across ciphertexts.

5. **Partial Decryption**  
Using all recovered key bytes, the target ciphertext is decrypted. Unknown positions are replaced with `'?'`, and the plaintext is saved to `secret.txt`.

