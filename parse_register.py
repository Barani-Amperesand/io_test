import csv
import sys
import argparse
from typing import Optional, Tuple, Dict, Any, List

# Define the controller specifics
CONTROLLERS = [
    {'name': 'LV',  'prefix': 'lv_',  'offset': 0x800},
    {'name': 'MV1', 'prefix': 'mv1_', 'offset': 0xA00},
    {'name': 'MV2', 'prefix': 'mv2_', 'offset': 0xC00},
]

def load_register_map(csv_path: str) -> Dict[str, List[Dict[str, str]]]:
    """
    Parses the full register map CSV into a dictionary for quick lookups.
    It reads columns by name, making it robust for complex CSVs.
    """
    register_map = {}
    # These are the specific column names we need from the new CSV format.
    REQUIRED_COLUMNS = ['IO_Tool_Addr', 'RegDescription', 'posslice', 'Label']

    try:
        # 'utf-8-sig' handles the BOM character (\ufeff) at the file start
        with open(csv_path, mode='r', encoding='utf-8-sig', newline='') as infile:
            reader = csv.DictReader(infile)
            
            # Verify that the CSV has the necessary columns before processing
            header = reader.fieldnames
            if not all(col in header for col in REQUIRED_COLUMNS):
                missing = [col for col in REQUIRED_COLUMNS if col not in header]
                print(f"Error: CSV file '{csv_path}' is missing required columns: {missing}", file=sys.stderr)
                sys.exit(1)

            for i, row in enumerate(reader, start=2): # start=2 for line number (1-based + header)
                try:
                    # Skip rows that don't have a valid IO Tool Address
                    if not row.get('IO_Tool_Addr'):
                        continue
                    
                    addr = row['IO_Tool_Addr'].strip().upper()
                    description = row['RegDescription'].strip()
                    posslice = row['posslice'].strip()
                    label = row['Label'].strip()
                    
                    if addr not in register_map:
                        register_map[addr] = []
                    
                    register_map[addr].append({
                        'description': description,
                        'slice': posslice,
                        'label': label
                    })
                except KeyError as e:
                    # This case handles malformed rows if a key is unexpectedly missing
                    print(f"Warning: Skipping malformed row {i} in CSV. Missing key: {e}", file=sys.stderr)
                    continue

    except FileNotFoundError:
        print(f"Error: The file '{csv_path}' was not found.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred while reading the CSV file: {e}", file=sys.stderr)
        sys.exit(1)
        
    return register_map

def find_base_address_and_controller(
    address_str: str, 
    register_map: Dict[str, Any]
) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """
    Determines the base address and controller by checking for known offsets.
    """
    address_norm = address_str.upper().replace("0X", "")
    try:
        address_int = int(address_norm, 16)
    except ValueError:
        return None, None

    # Check for offsetted controller addresses first
    for ctrl in CONTROLLERS:
        base_addr_int = address_int - ctrl['offset']
        if base_addr_int >= 0:
            base_addr_str = f"{base_addr_int:X}"
            # The base address must start with 'A000' as per the file format
            if base_addr_str.startswith('A000') and base_addr_str in register_map:
                return base_addr_str, ctrl
    
    # If not found, check if the address is a base address itself
    if address_norm in register_map:
        return address_norm, {'name': 'Base', 'prefix': ''}
            
    return None, None

def parse_slice(slice_str: str) -> tuple[int, int]:
    """Parses a slice string like '31:24' or '7' into (high, low) bits."""
    if ':' in slice_str:
        parts = slice_str.split(':')
        return int(parts[0]), int(parts[1])
    else:
        bit = int(slice_str)
        return bit, bit

def extract_bit_field(register_value: int, high_bit: int, low_bit: int) -> int:
    """Extracts a value from a bit field using masking and shifting."""
    width = high_bit - low_bit + 1
    mask = (1 << width) - 1
    return (register_value >> low_bit) & mask

def main():
    """Main function to parse arguments and print register field values."""
    parser = argparse.ArgumentParser(
        description="Parse a 32-bit register value using a full register map CSV.\n"
                    "Automatically detects LV/MV1/MV2 controller offsets.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("csv_file", help="Path to the register map CSV file.")
    parser.add_argument("address", help="The register address (e.g., A0008AA8 for MV1).")
    parser.add_argument("value", help="The 32-bit value from the address (e.g., 0x01020304).")

    args = parser.parse_args()
    register_map = load_register_map(args.csv_file)

    try:
        value_int = int(args.value, 16)
    except ValueError:
        print(f"Error: Invalid hex value provided: '{args.value}'", file=sys.stderr)
        sys.exit(1)

    base_address, controller = find_base_address_and_controller(args.address, register_map)

    if not base_address:
        print(f"Error: Address {args.address} (or its base equivalent) not found in {args.csv_file}", file=sys.stderr)
        sys.exit(1)

    fields = register_map[base_address]
    description = fields[0]['description']
    
    # --- Format and print the output ---
    title_prefix = f"{controller['name']}: " if controller['name'] != 'Base' else ""
    field_prefix = controller['prefix']

    print("-" * 65)
    print(f"Decoding Register: {title_prefix}{description} (Address: {args.address.upper()})")
    print(f"Input Value: 0x{value_int:08X} ({value_int})")
    print("-" * 65)
    print(f"{'Label':<25} {'Slice':<10} {'Value (Hex)':<15} {'Value (Dec)'}")
    print(f"{'-'*25:<25} {'-'*10:<10} {'-'*15:<15} {'-'*12}")

    for field in fields:
        label = field['label']
        slice_str = field['slice']
        
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