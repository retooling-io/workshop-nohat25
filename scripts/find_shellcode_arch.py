import sys
from capstone import *

def my_skip_callback(buffer, offset, userdata, last):
    print(f"got invalid {userdata} \n")
    return 3

def analyze_shellcode_architecture(shellcode_bytes):
    """
    Attempts to determine the target architecture of a binary shellcode blob
    by disassembling its first 1024 bytes (or less if the blob is smaller)
    across various common architectures and identifying which one produces
    the most successfully disassembled instructions.

    Args:
        shellcode_bytes (bytes): The binary shellcode blob.

    Returns:
        tuple: A tuple containing (most_likely_architecture, max_instructions).
               Returns (None, 0) if no instructions could be disassembled.
    """
    architectures = {
        "X86 (32-bit)": (CS_ARCH_X86, CS_MODE_32),
        "X64 (64-bit)": (CS_ARCH_X86, CS_MODE_64),
        "ARM (32-bit - ARM mode)": (CS_ARCH_ARM, CS_MODE_ARM),
        "ARM (32-bit - Thumb mode)": (CS_ARCH_ARM, CS_MODE_THUMB),
        "AArch64 (64-bit ARM)": (CS_ARCH_ARM64, CS_MODE_ARM), # CS_MODE_ARM is used for AArch64
        "MIPS (32-bit - Little Endian)": (CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN),
        "MIPS (32-bit - Big Endian)": (CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN),
        "MIPS64 (64-bit - Little Endian)": (CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN),
        "MIPS64 (64-bit - Big Endian)": (CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN),
        "RISC-V (32-bit)": (CS_ARCH_RISCV, CS_MODE_RISCV32), # Added RISC-V 32-bit
        "RISC-V (64-bit)": (CS_ARCH_RISCV, CS_MODE_RISCV64), # Added RISC-V 64-bit
    }

    max_instructions = 0
    most_likely_architecture = None
    disassembly_details = {} # To store instruction count for each architecture

    # Limit to the first 4096 bytes or the full blob if smaller
    data_to_analyze = shellcode_bytes[:4096]
    print(f"Analyzing {len(data_to_analyze)} bytes of shellcode...\n")

    for arch_name, (arch_const, mode_const) in architectures.items():
        try:
            # Initialize Capstone disassembler for the current architecture
            md = Cs(arch_const, mode_const)
            #md.detail = False # We only need the count, not detailed instruction info
            md.skipdata = True
            #md.skipdata_setup = ("db", my_skip_callback, None)

            instructions_count = 0
            # Disassemble the data
            for _ in md.disasm(data_to_analyze, 0): # 0x1000 is a dummy base address
                if(_.mnemonic != 'db' and _.mnemonic != '.byte'):
                    #print(f'{_.mnemonic}')
                    if _.mnemonic == 'ret':
                        instructions_count += 1
                    # wrong heuristic
                    #instructions_count += 1
            disassembly_details[arch_name] = instructions_count
            print(f"  {arch_name}: {instructions_count} instructions disassembled.")

            # Update if this architecture yielded more instructions
            if instructions_count > max_instructions:
                max_instructions = instructions_count
                most_likely_architecture = arch_name

        except CsError as e:
            # Handle Capstone errors (e.g., unsupported mode combinations)
            disassembly_details[arch_name] = f"Error: {e}"
            print(f"  {arch_name}: Error during disassembly - {e}")
        except Exception as e:
            disassembly_details[arch_name] = f"Unexpected Error: {e}"
            print(f"  {arch_name}: Unexpected error - {e}")

    print("\n--- Disassembly Summary ---")
    for arch_name, count in disassembly_details.items():
        print(f"{arch_name}: {count} instructions")

    return most_likely_architecture, max_instructions

if __name__ == "__main__":
    shellcode_blob = b''

    if len(sys.argv) > 1:
        shellcode_blob = open(sys.argv[1], 'rb+').read()

    print("--- Shellcode Architecture Detection ---")
    print(f"Input shellcode length: {len(shellcode_blob)} bytes\n")

    if not shellcode_blob:
        print("Error: No shellcode data provided. Please update 'example_shellcode_hex' or load from a file.")
    else:
        likely_arch, instruction_count = analyze_shellcode_architecture(shellcode_blob)

        if likely_arch:
            print(f"\nConclusion: The most likely architecture is '{likely_arch}' with {instruction_count} successfully disassembled instructions.")
        else:
            print("\nCould not determine a likely architecture. No instructions were successfully disassembled for any tested architecture.")
