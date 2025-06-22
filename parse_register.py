import os
import re
import sys
import argparse
from typing import Optional, Tuple, Dict, Any, List
import pandas as pd

# --- Controller definitions remain the same ---
LC_CONTROLLERS = [
    {'name': 'LV',  'prefix': 'lv_',  'offset': 0x800},
    {'name': 'MV1', 'prefix': 'mv1_', 'offset': 0xA00},
    {'name': 'MV2', 'prefix': 'mv2_', 'offset': 0xC00},
]

def parse_version(version_str: str) -> tuple:
    """Converts a version string 'x.y.z' into a comparable tuple (x, y, z)."""
    try:
        return tuple(map(int, version_str.split('.')))
    except (ValueError, AttributeError):
        # Return a non-comparable low value for invalid formats
        return (0, 0, 0)

def find_latest_file(prefix: str, directory: str) -> Optional[str]:
    """
    Finds the file in a directory that matches a prefix and has the latest version number.
    
    Args:
        prefix: The filename prefix to search for (e.g., 'QBgMap_MC_').
        directory: The path to the directory to search in.
    
    Returns:
        The full path to the latest version of the file, or None if no matching files are found.
    """
    # Regex to capture the version string (e.g., '0.11.0') from the filename
    pattern = re.compile(re.escape(prefix) + r"(\d+\.\d+\.\d+)\.xlsx$")
    
    latest_version = (0, 0, 0)
    latest_file_path = None

    try:
        for filename in os.listdir(directory):
            match = pattern.match(filename)
            if match:
                version_str = match.group(1)
                version_tuple = parse_version(version_str)
                if version_tuple > latest_version:
                    latest_version = version_tuple
                    latest_file_path = os.path.join(directory, filename)
    except FileNotFoundError:
        return None # Directory doesn't exist
        
    return latest_file_path

# --- The load_register_map function and all decoding functions are identical to the previous version ---
def load_register_map(excel_path: str) -> Dict[str, List[Dict[str, str]]]:
    # This is the exact same Excel loading logic as before.
    register_map = {}
    REQUIRED_COLUMNS = ['IO_Tool_Addr', 'RegDescription', 'posslice', 'Label']
    try:
        df = pd.read_excel(excel_path, sheet_name=0, dtype=str).fillna('')
        if not all(col in df.columns for col in REQUIRED_COLUMNS):
            missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
            print(f"Error: Excel file '{excel_path}' is missing required columns: {missing}", file=sys.stderr)
            sys.exit(1)
        for row in df.to_dict('records'):
            addr = row['IO_Tool_Addr'].strip().upper()
            if not addr: continue
            desc = row['RegDescription'].strip()
            pslice = row['posslice'].strip()
            label = row['Label'].strip()
            if addr not in register_map: register_map[addr] = []
            register_map[addr].append({'description': desc, 'slice': pslice, 'label': label})
    except FileNotFoundError:
        print(f"Error: The file '{excel_path}' was not found.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred while reading the Excel file '{excel_path}': {e}", file=sys.stderr)
        sys.exit(1)
    return register_map
def find_address_context(address_str, mc_map, lc_map): # ... identical to before ...
    address_norm = address_str.upper().replace("0X", "")
    try: address_int = int(address_norm, 16)
    except ValueError: return None, None, None
    for ctrl in LC_CONTROLLERS:
        base_addr_int = address_int - ctrl['offset']
        if base_addr_int >= 0:
            base_addr_str = f"{base_addr_int:X}"
            if base_addr_str in lc_map: return base_addr_str, ctrl, 'LC'
    if address_norm in mc_map: return address_norm, {'name': 'MC', 'prefix': 'mc_'}, 'MC'
    if address_norm in lc_map: return address_norm, {'name': 'LC Base', 'prefix': ''}, 'LC'
    return None, None, None
def parse_slice(slice_str): # ... identical to before ...
    if ':' in slice_str: return int(slice_str.split(':')[0]), int(slice_str.split(':')[1])
    else: return int(slice_str), int(slice_str)
def extract_bit_field(register_value, high_bit, low_bit): # ... identical to before ...
    width = high_bit - low_bit + 1
    mask = (1 << width) - 1
    return (register_value >> low_bit) & mask

def main():
    parser = argparse.ArgumentParser(
        description="Decode register values using auto-detected latest or specified versions of register maps.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("address", help="The register address (e.g., A0000000 for MC, A0008AA8 for LC).")
    parser.add_argument("value", help="The 32-bit value from the address (e.g., 0x01020304).")
    parser.add_argument("--dir", default=".", help="Directory to search for register map files (default: current directory).")
    parser.add_argument("--mc-version", help="Specify an exact MC version to use (e.g., '0.8.0'). Overrides auto-detection.")
    parser.add_argument("--lc-version", help="Specify an exact LC version to use (e.g., '0.11.0'). Overrides auto-detection.")

    args = parser.parse_args()
    search_dir = args.dir

    # Determine the MC file path
    if args.mc_version:
        mc_file_path = os.path.join(search_dir, f"QBgMap_MC_{args.mc_version}.xlsx")
        if not os.path.exists(mc_file_path):
            print(f"Error: Specified MC file not found: {mc_file_path}", file=sys.stderr)
            sys.exit(1)
    else:
        mc_file_path = find_latest_file("QBgMap_MC_", search_dir)
        if not mc_file_path:
            print(f"Error: Could not automatically find any MC register map file (QBgMap_MC_*.xlsx) in '{search_dir}'.", file=sys.stderr)
            sys.exit(1)

    # Determine the LC file path
    if args.lc_version:
        lc_file_path = os.path.join(search_dir, f"QBgMap_LC_{args.lc_version}.xlsx")
        if not os.path.exists(lc_file_path):
            print(f"Error: Specified LC file not found: {lc_file_path}", file=sys.stderr)
            sys.exit(1)
    else:
        lc_file_path = find_latest_file("QBgMap_LC_", search_dir)
        if not lc_file_path:
            print(f"Error: Could not automatically find any LC register map file (QBgMap_LC_*.xlsx) in '{search_dir}'.", file=sys.stderr)
            sys.exit(1)

    print(f"INFO: Using MC map: '{os.path.basename(mc_file_path)}'", file=sys.stderr)
    print(f"INFO: Using LC map: '{os.path.basename(lc_file_path)}'", file=sys.stderr)

    # --- The rest of the script continues as before ---
    mc_map = load_register_map(mc_file_path)
    lc_map = load_register_map(lc_file_path)

    try: value_int = int(args.value, 16)
    except ValueError:
        print(f"Error: Invalid hex value provided: '{args.value}'", file=sys.stderr)
        sys.exit(1)

    base_address, controller, map_type = find_address_context(args.address, mc_map, lc_map)

    if not base_address:
        print(f"Error: Address {args.address.upper()} not found in the loaded register maps.", file=sys.stderr)
        sys.exit(1)

    active_map = mc_map if map_type == 'MC' else lc_map
    fields = active_map[base_address]
    description = fields[0]['description']
    title_prefix, field_prefix = f"{controller['name']}: ", controller['prefix']

    print("\n" + "-" * 65)
    print(f"Decoding Register: {title_prefix}{description} (Address: {args.address.upper()})")
    print(f"Input Value: 0x{value_int:08X} ({value_int})")
    print("-" * 65)
    print(f"{'Label':<25} {'Slice':<10} {'Value (Hex)':<15} {'Value (Dec)'}")
    print(f"{'-'*25:<25} {'-'*10:<10} {'-'*15:<15} {'-'*12}")
    for field in fields:
        label, slice_str = field['label'], field['slice']
        try:
            high, low = parse_slice(slice_str)
            field_value = extract_bit_field(value_int, high, low)
            prefixed_label = f"{field_prefix}{label}"
            print(f"{prefixed_label:<25} {slice_str:<10} {'0x' + hex(field_value)[2:].upper():<15} {field_value}")
        except ValueError:
            print(f"Could not parse slice '{slice_str}' for label '{label}'. Skipping.")
    print("-" * 65)

if __name__ == "__main__":
    main()