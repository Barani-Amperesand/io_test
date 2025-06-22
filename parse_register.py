import os
import re
import sys
import argparse
from typing import Optional, Tuple, Dict, Any, List
import pandas as pd

# Controller definitions
LC_CONTROLLERS = [
    {'name': 'LV',  'prefix': 'lv_',  'offset': 0x800},
    {'name': 'MV1', 'prefix': 'mv1_', 'offset': 0xA00},
    {'name': 'MV2', 'prefix': 'mv2_', 'offset': 0xC00},
]

def find_latest_file(prefix: str, directory: str) -> Optional[str]:
    """Finds the file in a directory that matches a prefix and has the latest version."""
    pattern = re.compile(re.escape(prefix) + r"(\d+\.\d+\.\d+)\.xlsx$")
    latest_version, latest_file_path = (0, 0, 0), None
    try:
        for filename in os.listdir(directory):
            match = pattern.match(filename)
            if match:
                version_tuple = tuple(map(int, match.group(1).split('.')))
                if version_tuple > latest_version:
                    latest_version, latest_file_path = version_tuple, os.path.join(directory, filename)
    except FileNotFoundError:
        return None
    return latest_file_path

def load_register_map(excel_path: str) -> Dict[str, List[Dict[str, str]]]:
    """Parses a register map from an Excel (.xlsx) file into a dictionary."""
    register_map, REQUIRED_COLUMNS = {}, ['IO_Tool_Addr', 'RegDescription', 'posslice', 'Label']
    try:
        df = pd.read_excel(excel_path, sheet_name=0, dtype=str).fillna('')
        if not all(col in df.columns for col in REQUIRED_COLUMNS):
            missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
            print(f"Error: Excel file '{excel_path}' is missing required columns: {missing}", file=sys.stderr)
            sys.exit(1)
        for row in df.to_dict('records'):
            addr = row['IO_Tool_Addr'].strip().upper()
            if not addr: continue
            desc, pslice, label = row['RegDescription'].strip(), row['posslice'].strip(), row['Label'].strip()
            if addr not in register_map: register_map[addr] = []
            register_map[addr].append({'description': desc, 'slice': pslice, 'label': label})
    except FileNotFoundError:
        print(f"Error: The file '{excel_path}' was not found.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred while reading Excel file '{excel_path}': {e}", file=sys.stderr)
        sys.exit(1)
    return register_map

def process_and_print_register(address_str: str, value_str: str, mc_map: dict, lc_map: dict):
    """Decodes and prints the bit-fields for a single address and value pair."""
    try:
        value_int = int(value_str, 16)
    except (ValueError, TypeError):
        print(f"Warning: Invalid value '{value_str}' for address '{address_str}'. Skipping.", file=sys.stderr)
        return

    base_address, controller, map_type = find_address_context(address_str, mc_map, lc_map)

    if not base_address:
        print(f"Warning: Address {address_str.upper()} not found in maps. Skipping.", file=sys.stderr)
        return

    active_map = mc_map if map_type == 'MC' else lc_map
    fields = active_map[base_address]
    description = fields[0]['description']
    title_prefix, field_prefix = f"{controller['name']}: ", controller['prefix']

    print("-" * 65)
    print(f"Decoding Register: {title_prefix}{description} (Address: {address_str.upper()})")
    print(f"Input Value: 0x{value_int:08X} ({value_int})")
    print("-" * 65)
    print(f"{'Label':<25} {'Slice':<10} {'Value (Hex)':<15} {'Value (Dec)'}")
    print(f"{'-'*25:<25} {'-'*10:<10} {'-'*15:<15} {'-'*12}")
    for field in fields:
        label, slice_str = field['label'], field['slice']
        try:
            high, low = int(slice_str.split(':')[0]), int(slice_str.split(':')[1]) if ':' in slice_str else int(slice_str)
            field_value = ((value_int >> low) & ((1 << (high - low + 1)) - 1))
            prefixed_label = f"{field_prefix}{label}"
            print(f"{prefixed_label:<25} {slice_str:<10} {'0x' + hex(field_value)[2:].upper():<15} {field_value}")
        except (ValueError, IndexError):
            print(f"Could not parse slice '{slice_str}' for label '{label}'. Skipping.")
    print("-" * 65 + "\n")

def find_address_context(address_str, mc_map, lc_map):
    """Determines which map (MC or LC) and controller to use based on the address."""
    address_norm = address_str.upper().replace("0X", "")
    try:
        address_int = int(address_norm, 16)
    except ValueError:
        return None, None, None
    for ctrl in LC_CONTROLLERS:
        base_addr_int = address_int - ctrl['offset']
        if base_addr_int >= 0:
            base_addr_str = f"{base_addr_int:X}"
            if base_addr_str in lc_map:
                return base_addr_str, ctrl, 'LC'
    if address_norm in mc_map:
        return address_norm, {'name': 'MC', 'prefix': 'mc_'}, 'MC'
    if address_norm in lc_map:
        return address_norm, {'name': 'LC Base', 'prefix': ''}, 'LC'
    return None, None, None


def main():
    parser = argparse.ArgumentParser(
        description="Decode register values from CLI or a file, using auto-detected or specified register maps.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Positional args for CLI mode are optional
    parser.add_argument("address", nargs='?', default=None, help="The register address (for CLI mode).")
    parser.add_argument("value", nargs='?', default=None, help="The 32-bit value (for CLI mode).")
    
    # Optional file input argument
    parser.add_argument("--file", help="Path to a file containing address-value pairs to process.")

    # Version control arguments
    parser.add_argument("--dir", default=".", help="Directory to search for register map files (default: current directory).")
    parser.add_argument("--mc-version", help="Specify an exact MC version to use (e.g., '0.8.0').")
    parser.add_argument("--lc-version", help="Specify an exact LC version to use (e.g., '0.11.0').")

    args = parser.parse_args()

    # Validate input mode
    is_file_mode = args.file is not None
    is_cli_mode = args.address is not None and args.value is not None

    if is_file_mode and is_cli_mode:
        parser.error("argument --file: not allowed with positional 'address' and 'value' arguments.")
    if not is_file_mode and not is_cli_mode:
        parser.error("the following arguments are required: address and value (for CLI mode) OR --file (for file mode).")

    # Load register maps (once per run)
    search_dir = args.dir
    mc_file_path = os.path.join(search_dir, f"QBgMap_MC_{args.mc_version}.xlsx") if args.mc_version else find_latest_file("QBgMap_MC_", search_dir)
    lc_file_path = os.path.join(search_dir, f"QBgMap_LC_{args.lc_version}.xlsx") if args.lc_version else find_latest_file("QBgMap_LC_", search_dir)

    if not mc_file_path or not os.path.exists(mc_file_path):
        print(f"Error: MC register map file could not be found.", file=sys.stderr)
        sys.exit(1)
    if not lc_file_path or not os.path.exists(lc_file_path):
        print(f"Error: LC register map file could not be found.", file=sys.stderr)
        sys.exit(1)

    print(f"INFO: Using MC map: '{os.path.basename(mc_file_path)}'", file=sys.stderr)
    print(f"INFO: Using LC map: '{os.path.basename(lc_file_path)}'", file=sys.stderr)
    
    mc_map = load_register_map(mc_file_path)
    lc_map = load_register_map(lc_file_path)

    # Process the input based on the mode
    if is_file_mode:
        line_pattern = re.compile(r"^(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)")
        try:
            with open(args.file, 'r') as f:
                for line in f:
                    match = line_pattern.match(line)
                    if match:
                        addr, val = match.groups()
                        process_and_print_register(addr, val, mc_map, lc_map)
        except FileNotFoundError:
            print(f"Error: Input file not found: {args.file}", file=sys.stderr)
            sys.exit(1)
    else: # CLI mode
        process_and_print_register(args.address, args.value, mc_map, lc_map)

if __name__ == "__main__":
    main()