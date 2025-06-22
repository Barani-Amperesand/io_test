import sys
import argparse
from typing import Optional, Tuple, Dict, Any, List
import pandas as pd  # Import the pandas library

# --- (Controller definitions and other functions remain the same) ---
LC_CONTROLLERS = [
    {'name': 'LV',  'prefix': 'lv_',  'offset': 0x800},
    {'name': 'MV1', 'prefix': 'mv1_', 'offset': 0xA00},
    {'name': 'MV2', 'prefix': 'mv2_', 'offset': 0xC00},
]

def load_register_map(excel_path: str) -> Dict[str, List[Dict[str, str]]]:
    """
    Parses a register map from an Excel (.xlsx) file into a dictionary.
    """
    register_map = {}
    REQUIRED_COLUMNS = ['IO_Tool_Addr', 'RegDescription', 'posslice', 'Label']
    try:
        # Use pandas to read the first sheet of the Excel file into a DataFrame
        df = pd.read_excel(excel_path, sheet_name=0, dtype=str).fillna('')
        
        if not all(col in df.columns for col in REQUIRED_COLUMNS):
            missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
            print(f"Error: Excel file '{excel_path}' is missing required columns: {missing}", file=sys.stderr)
            sys.exit(1)

        # Convert the DataFrame to a list of dictionaries
        for row in df.to_dict('records'):
            addr = row['IO_Tool_Addr'].strip().upper()
            if not addr: continue # Skip rows with no address

            desc = row['RegDescription'].strip()
            pslice = row['posslice'].strip()
            label = row['Label'].strip()
            
            if addr not in register_map:
                register_map[addr] = []
            
            register_map[addr].append({
                'description': desc,
                'slice': pslice,
                'label': label
            })

    except FileNotFoundError:
        print(f"Error: The file '{excel_path}' was not found.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred while reading the Excel file '{excel_path}': {e}", file=sys.stderr)
        sys.exit(1)
    return register_map

# --- The rest of the script is identical to the previous working version ---
def find_address_context(
    address_str: str, 
    mc_map: Dict[str, Any],
    lc_map: Dict[str, Any]
) -> Tuple[Optional[str], Optional[Dict[str, Any]], Optional[str]]:
    address_norm = address_str.upper().replace("0X", "")
    try: address_int = int(address_norm, 16)
    except ValueError: return None, None, None
    for ctrl in LC_CONTROLLERS:
        base_addr_int = address_int - ctrl['offset']
        if base_addr_int >= 0:
            base_addr_str = f"{base_addr_int:X}"
            if base_addr_str in lc_map:
                return base_addr_str, ctrl, 'LC'
    if address_norm in mc_map: return address_norm, {'name': 'MC', 'prefix': 'mc_'}, 'MC'
    if address_norm in lc_map: return address_norm, {'name': 'LC Base', 'prefix': ''}, 'LC'
    return None, None, None

def parse_slice(slice_str: str) -> tuple[int, int]:
    if ':' in slice_str: return int(slice_str.split(':')[0]), int(slice_str.split(':')[1])
    else: return int(slice_str), int(slice_str)

def extract_bit_field(register_value: int, high_bit: int, low_bit: int) -> int:
    width = high_bit - low_bit + 1
    mask = (1 << width) - 1
    return (register_value >> low_bit) & mask

def main():
    parser = argparse.ArgumentParser(
        description="Parse a 32-bit register value using Master (MC) and Local (LC) Controller Excel maps.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    # Updated help text to mention .xlsx files
    parser.add_argument("mc_excel_file", help="Path to the Master Controller (MC) register map (.xlsx).")
    parser.add_argument("lc_excel_file", help="Path to the Local Controller (LC) register map (.xlsx).")
    parser.add_argument("address", help="The register address (e.g., A0000000 for MC, A0008AA8 for LC).")
    parser.add_argument("value", help="The 32-bit value from the address (e.g., 0x01020304).")

    args = parser.parse_args()
    
    # Load both register maps from Excel files
    mc_map = load_register_map(args.mc_excel_file)
    lc_map = load_register_map(args.lc_excel_file)

    try: value_int = int(args.value, 16)
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