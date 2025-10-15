import struct
import sys
import argparse

def tetra_twist(data: bytes) -> int:
    """
    Custom hash function that is used to generate the encryption key.
    This has strong avalanche properties and is used to ensure that
    small changes to the input result in large changes to the output.
    """

    assert len(data) == 4, "Input should be 4 bytes"

    # Convert bytes (little-endian) to an integer
    input_val = int.from_bytes(data, 'little')
    prime1 = 0x9E3779B1 # A commonly used constant in hashing/mixing functions

    # A series of bitwise operations for mixing and avalanche effect
    input_val ^= input_val >> 15
    input_val *= prime1
    input_val &= 0xFFFFFFFF # Keep it 32-bit
    input_val ^= input_val >> 12
    input_val *= prime1
    input_val &= 0xFFFFFFFF
    input_val ^= input_val >> 4
    input_val *= prime1
    input_val &= 0xFFFFFFFF
    input_val ^= input_val >> 16

    return input_val & 0xFFFFFFFF

def transform(offset: int, key: int) -> int:
    """Generates a 4-byte keystream block based on file offset and master key."""
    # Keystream is generated from a combination of the key and the current position
    key2 = key + offset
    # The output is the custom hash of the key2's 4-byte representation
    return tetra_twist(struct.pack("<I", key2))

def decrypt_file(filepath: str, key: int):
    """Reads, decrypts, and writes the output file using the provided key."""
    try:
        enc_data = open(filepath, 'rb').read()
    except FileNotFoundError:
        print(f"Error: Encrypted file not found at '{filepath}'")
        sys.exit(1)

    dec_data = bytearray(enc_data)  # Buffer for decrypted output
    enc_len = len(enc_data)

    # Process data in 4-byte chunks
    for i in range(0, enc_len, 4):
        offset = i
        end = i + 4

        # 1. Extract a 4-byte chunk
        chunk = enc_data[i:min(end, enc_len)]
        padding_needed = 4 - len(chunk)

        # 2. Pad with zeros if it's the final, incomplete chunk (required for struct.unpack)
        if padding_needed > 0:
            chunk += b'\x00' * padding_needed

        # 3. Unpack 4-byte chunk (little endian)
        dword, = struct.unpack("<I", chunk)

        # 4. Generate the keystream block
        keystream = transform(offset, key)

        # 5. Decrypt using XOR operation
        dword = dword ^ keystream

        # 6. Repack and save the decrypted data chunk
        # Note: We only write back the original number of bytes in the chunk
        dec_data[i:min(end, enc_len)] = struct.pack("<I", dword)[:len(chunk)]

    # Write the decrypted data to the output file
    output_filepath = f'{filepath}.decrypted'
    with open(output_filepath, 'wb') as f:
        f.write(dec_data)

    print(f"Successfully decrypted '{filepath}' using key 0x{key:X} to '{output_filepath}'")

if __name__ == '__main__':
    # 1. Setup argument parser
    parser = argparse.ArgumentParser(
        description="Decrypts a file encrypted with the custom tetra_twist stream cipher.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Usage Examples:\n"
               "  python3 decryptor.py secrets.bin DEADBEEF\n"
               "  python3 decryptor.py data.enc 12345678"
    )

    # 2. Add required argument for the file path
    parser.add_argument(
        'input_file',
        type=str,
        help='The path to the encrypted file to be decrypted.'
    )

    # 3. Add required argument for the master key
    parser.add_argument(
        'master_key',
        type=str,
        help='The 32-bit (4-byte) master key, provided as an 8-character hexadecimal string (e.g., DEADBEEF).'
    )

    # 4. Parse the arguments
    args = parser.parse_args()

    # 5. Convert the hex string key to an integer and validate
    try:
        # Convert from hex string to integer
        key_int = int(args.master_key, 16)

        # Basic validation: check if the key is within the 32-bit range
        if not (0 <= key_int <= 0xFFFFFFFF):
             raise ValueError("Key value is out of the expected 32-bit range (0 to FFFFFFFF).")

    except ValueError:
        print(f"Error: Invalid master key format: '{args.master_key}'")
        print("Please provide the key as a valid hexadecimal string.")
        sys.exit(1)

    # 6. Run the decryption
    decrypt_file(args.input_file, key_int)
