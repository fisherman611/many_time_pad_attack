import string
from collections import Counter

def hex_to_bytes(hex_string):
    """
    Convert a hex string (with or without spaces/newlines) into bytes.
    E.g:
        hex_to_bytes('414243') -> b'ABC'
    """
    return bytes.fromhex(hex_string.replace(' ', '').replace('\n', ''))


def xor_2_bytes(bytes_a, bytes_b):
    """
    XOR two byte sequences of the same length.
    E.g:
        xor_2_bytes(b'ABC', b'XYZ') -> b'\x19\x1b\x19'
    """
    return bytes(a ^ b for a, b in zip(bytes_a, bytes_b))


def is_printable(char):
    """
    Check if a character is printable (letters, digits, punctuation, etc.).
    E.g:
        is_printable('A') -> True
        is_printable('\n') -> False
    """
    return char in string.printable and char not in '\t\n\r\x0b\x0c'


def detect_possible_spaces(xor_bytes):
    """
    Return indices where XOR result likely indicates a space in one plaintext.
    E.g:
        detect_possible_spaces(b'x\x1b\x19') -> [0]
    """
    return [i for i, b in enumerate(xor_bytes) if b < 128 and chr(b).isalpha()]



def collect_space_indices(ciphertexts):
    """
    Compare every pair of ciphertexts to guess where spaces (' ') might appear.
    The idea: letter XOR space → uppercase/lowercase letter.
    """
    n = len(ciphertexts)
    max_len = max(len(ct) for ct in ciphertexts)
    space_scores = [Counter() for _ in range(max_len)]

    for i in range(n):
        for j in range(i + 1, n):
            min_len = min(len(ciphertexts[i]), len(ciphertexts[j]))
            xor_result = xor_2_bytes(ciphertexts[i][:min_len], ciphertexts[j][:min_len])
            for pos in range(min_len):
                if xor_result[pos] < 128 and chr(xor_result[pos]).isalpha():
                    space_scores[pos][i] += 1
                    space_scores[pos][j] += 1

    likely_spaces = []
    for pos in range(max_len):
        if space_scores[pos]:
            cipher_idx, score = space_scores[pos].most_common(1)[0]
            likely_spaces.append((pos, cipher_idx, score))
    return likely_spaces



def derive_key_from_space(ciphertexts, target_idx, pos, known_space_idx):
    """Derive key byte assuming ciphertext[known_space_idx] has a space at pos."""
    if pos >= len(ciphertexts[known_space_idx]) or pos >= len(ciphertexts[target_idx]):
        return None
    key_candidate = ciphertexts[known_space_idx][pos] ^ 0x20  # XOR with space
    decrypted_char = ciphertexts[target_idx][pos] ^ key_candidate
    if decrypted_char < 128 and is_printable(chr(decrypted_char)):
        return key_candidate
    return None


def decrypt_with_known_key(ciphertext, key_partial):
    """Decrypt ciphertext using only known key bytes (unknown positions → '?')."""
    result = []
    for i in range(len(ciphertext)):
        if i < len(key_partial) and key_partial[i] is not None:
            char = chr(ciphertext[i] ^ key_partial[i])
            result.append(char if is_printable(char) else '?')
        else:
            result.append('?')
    return ''.join(result)


def main():
    ciphertexts_hex = [
        "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e",
        "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f",
        "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb",
        "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa",
        "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070",
        "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4",
        "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce",
        "315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3",
        "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027",
        "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83"
    ]
    
    target_hex = "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904"
    
    ciphertexts = [hex_to_bytes(ct) for ct in ciphertexts_hex]
    target = hex_to_bytes(target_hex)
    all_ct = ciphertexts + [target]
    target_idx = len(ciphertexts)

    print("\nStep 1: Analyzing for likely spaces...")
    space_candidates = collect_space_indices(all_ct)

    partial_key = [None] * len(target)

    print("\nStep 2: Deriving key from space positions...")
    for pos, c_idx, score in space_candidates:
        if pos < len(target):
            k = derive_key_from_space(all_ct, target_idx, pos, c_idx)
            if k is not None:
                partial_key[pos] = k
                print(f"Pos {pos:2d}: key=0x{k:02x} (confidence={score})")

    print("\nStep 3: Heuristic guessing...")
    common_chars = [' ', 'e', 't', 'a', 'o', 'i', 'n', 's', 'h', 'r']
    for i in range(len(target)):
        if partial_key[i] is None:
            for j, other in enumerate(ciphertexts):
                if i < len(other):
                    for char in common_chars:
                        k = other[i] ^ ord(char)
                        decrypted = target[i] ^ k
                        if decrypted < 128 and is_printable(chr(decrypted)):
                            valid = 0
                            total = 0
                            for ct in ciphertexts:
                                if i < len(ct):
                                    total += 1
                                    if ct[i] ^ k < 128 and is_printable(chr(ct[i] ^ k)):
                                        valid += 1
                            if total > 0 and valid / total > 0.5:
                                partial_key[i] = k
                                print(f"Heuristic pos {i:2d}: key=0x{k:02x}")
                                break
                if partial_key[i] is not None:
                    break

    decrypted_text = decrypt_with_known_key(target, partial_key)
    print("\nDecrypted result:")
    print(decrypted_text)

    known = sum(k is not None for k in partial_key)
    print(f"\nKnown key bytes: {known}/{len(target)} ({known/len(target)*100:.1f}%)")

    return decrypted_text


if __name__ == "__main__":
    msg = main()
    with open("secret.txt", "w", encoding="utf-8") as f:
        f.write(msg)