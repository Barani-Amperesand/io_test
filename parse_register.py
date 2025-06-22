import csv
import sys
import argparse
from typing import Optional, Tuple, Dict, Any, List

# Define the Local Controller (LC) specifics
LC_CONTROLLERS = [
    {'name': 'LV',  'prefix': 'lv_',  'offset': 0x800},
    {'name': 'MV1', 'prefix': 'mv1_', 'offset': 0xA00},
    {'name': 'MV2', 'prefix': 'mv2_', 'offset': 0xC00},
]

def load_register_map(csv_path: str) -> Dict[str, List[Dict[str, str]]]:
    """
    Parses a register map CSV into a dictionary for quick lookups.
    It reads columns by name, making it robust for complex CSVs.
    """
    register_map = {}
    REQUIRED_COLUMNS = ['IO_Tool_Addr', 'RegDescription', 'posslice', 'Label']
    try:
        with open(csv_path, mode='r', encoding='utf-8-sig', newline='') as infile:
            reader = csv.DictReader(infile)
            if not all(col in reader.fieldnames for col in REQUIRED_COLUMNS):
                missing = [col for col in REQUIRED_COLUMNS if col not in reader.fieldnames]
                print(f"Error: CSV file '{csv_path}' is missing required columns: {missing}", file=sys.stderr)
                sys.exit(1)

            for i, row in enumerate(reader, start=2):
                try:
                    if not row.get('IO_Tool_Addr'): continue
                    addr = row['IO_Tool_Addr'].strip().upper()
                    if not addr: continue # Ensure address is not empty after stripping
                    desc, pslice, label = row['RegDescription'].strip(), row['posslice'].strip(), row['Label'].strip()
                    if addr not in register_map:
                        register_map[addr] = []
                    register_map[addr].append({'description': desc, 'slice': pslice, 'label': label})
                except KeyError as e:
                    print(f"Warning: Skipping malformed row {i} in CSV. Missing key: {e}", file=sys.stderr)
                    continue
    except FileNotFoundError:
        print(f"Error: The file '{csv_path}' was not found.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred while reading the CSV file '{csv_path}': {e}", file=sys.stderr)
        sys.exit(1)
    return register_map

def find_address_context(
    address_str: str, 
    mc_map: Dict[str, Any],
    lc_map: Dict[str, Any]
) -> Tuple[Optional[str], Optional[Dict[str, Any]], Optional[str]]:
    """
    Determines which map (MC or LC) and controller to use based on the address.
    """
    address_norm = address_str.upper().replace("0X", "")
    try:
        address_int = int(address_norm, 16)
    except ValueError:
        return None, None, None

    # Priority 1: Check for specific LC controller offsets (LV, MV1, MV2)
    for ctrl in LC_CONTROLLERS:
        base_addr_int = address_int - ctrl['offset']
        if base_addr_int >= 0:
            # CORRECTED LOGIC: Convert the entire calculated integer to a hex string.
            base_addr_str = f"{base_addr_int:X}"
            if base_addr_str in lc_map:
                return base_addr_str, ctrl, 'LC'
    
    # Priority 2: Check if it's a base address in the MC map
    if address_norm in mc_map:
        return address_norm, {'name': 'MC', 'prefix': 'mc_'}, 'MC'

    # Priority 3: Check if it's a base address in the LC map
    if address_norm in lc_map:
        return address_norm, {'name': 'LC Base', 'prefix': ''}, 'LC'
            
    return None, None, None

def parse_slice(slice_str: str) -> tuple[int, int]:
    """Parses a slice string like '31:24' or '7' into (high, low) bits."""
    if ':' in slice_str:
        return int(slice_str.split(':')[0]), int(slice_str.split(':')[1])
    else:
        return int(slice_str), int(slice_str)

def extract_bit_field(register_value: int, high_bit: int, low_bit: int) -> int:
    """Extracts a value from a bit field using masking and shifting."""
    width = high_bit - low_bit + 1
    mask = (1 << width) - 1
    return (register_value >> low_bit) & mask

def main():
    """Main function to parse arguments and print register field values."""
    parser = argparse.ArgumentParser(
        description="Parse a 32-bit register value using Master (MC) and Local (LC) Controller maps.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("mc_csv_file", help="Path to the Master Controller (MC) register map CSV.")
    parser.add_argument("lc_csv_file", help="Path to the Local Controller (LC) register map CSV.")
    parser.add_argument("address", help="The register address (e.g., A0000000 for MC, A0008AA8 for LC).")
    parser.add_argument("value", help="The 32-bit value from the address (e.g., 0x01020304).")

    args = parser.parse_args()
    mc_map = load_register_map(args.mc_csv_file)
    lc_map = load_register_map(args.lc_csv_file)

    try:
        value_int = int(args.value, 16)
    except ValueError:
        print(f"Error: Invalid hex value provided: '{args.value}'", file=sys.stderr)
        sys.exit(1)

    base_address, controller, map_type = find_address_context(args.address, mc_map, lc_map)

    if not base_address:
        print(f"Error: Address {args.address.upper()} not found in either MC or LC register maps.", file=sys.stderr)
        sys.exit(1)

    active_map = mc_map if map_type == 'MC' else lc_map
    fields = active_map[base_address]
    description = fields[0]['description']
    
    title_prefix, field_prefix = f"{controller['name']}: ", controller['prefix']

    print("-" * 65)
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