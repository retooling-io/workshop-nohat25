import pefile
import os
import sys

def hash_x65599(buffer: str, case_sensitive: bool = True) -> int:
    """
    Computes a hash value for a string using the X65599 algorithm,
    mimicking the behavior of a 32-bit unsigned integer (uint32_t).

    Args:
        buffer: The input string (export name).
        case_sensitive: If False, converts 'a'-'z' to 'A'-'Z' before hashing.

    Returns:
        The 32-bit unsigned integer hash value.
    """
    hash_val = 0
    # Modulus to simulate 32-bit unsigned integer overflow (2^32)
    MODULUS_32BIT = 2**32

    for char in buffer:
        ch = char
        ch_ord = ord(ch)

        # Case insensitive conversion (a-z to A-Z) if required
        if not case_sensitive:
            if 'a' <= ch <= 'z':
                # Convert lowercase to uppercase by subtracting 32 (ASCII difference)
                ch_ord = ord(ch) - ord(' ')

        # The core hash operation: hash = ch + 65599 * hash
        # The modulo operation enforces the 32-bit limit.
        hash_val = (ch_ord + 65599 * hash_val) % MODULUS_32BIT

    return hash_val

# --- PE Parsing and Hashing Function ---

def parse_pe_exports_and_hash(pe_filepath: str, output_filepath: str, case_sensitive: bool = True):
    """
    Parses a PE file (DLL/EXE), extracts export names, hashes them, 
    and writes the results to an output file.

    Args:
        pe_filepath: Path to the target DLL or EXE file.
        output_filepath: Path to the file where results (hash, name) will be written.
        case_sensitive: Whether to perform a case-sensitive hash calculation.
    """
    print(f"[*] Starting analysis of: {pe_filepath}")
    
    if not os.path.exists(pe_filepath):
        print(f"[!] Error: PE file not found at '{pe_filepath}'")
        return

    try:
        # 1. Load the PE file
        pe = pefile.PE(pe_filepath)

        # 2. Check for the Export Directory
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            print("[!] Warning: PE file does not contain an Export Directory. Skipping.")
            return

        # 3. Open the output file for writing
        with open(output_filepath, 'w') as outfile:
            print(f"[*] Processing exports and writing results to: {output_filepath}")
            outfile.write("HashValue,ExportName\n") # Write header

            # 4. Loop over all exports
            for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                
                # Check if the export has a name (some exports are only ordinal)
                if export.name:
                    # Decode the name from bytes to string
                    export_name = export.name.decode('utf-8')
                    
                    # 5. Calculate the hash
                    calculated_hash = hash_x65599(export_name, case_sensitive)
                    
                    # Format the hash as an 8-digit hexadecimal string (e.g., 0x0123ABCD)
                    hash_hex = f"0x{calculated_hash:08X}"

                    # 6. Write the hash and original name to the output file
                    outfile.write(f"{hash_hex},{export_name}\n")
                    # print(f"  - {hash_hex}: {export_name}") # Optional: Print to console
        
        print(f"[*] Successfully processed {len(pe.DIRECTORY_ENTRY_EXPORT.symbols)} exports.")
        print(f"[*] Done. Results saved to '{output_filepath}'")

    except pefile.PEFormatError as e:
        print(f"[!] Error: Failed to parse PE file. It might be corrupt or an unsupported format. Details: {e}")
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")

if __name__ == '__main__': 
    # Example 1: Standard usage (case-sensitive hashing)
    # input_dll = 'C:\\Windows\\System32\\kernel32.dll' 
    # output_csv = 'kernel32_hashes.csv'
    
    input_dll = sys.argv[1] 
    output_csv = sys.argv[2]

    print("\n--- Example Execution Attempt ---")
    parse_pe_exports_and_hash(input_dll, output_csv)
    print("---------------------------------")
    print("To run successfully, please replace 'input_dll' with a path to a real DLL file and uncomment the function call.")
