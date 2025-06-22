import os
import re
import sys
import argparse
import struct
from typing import Optional, Tuple, Dict, Any, List
import pandas as pd

def build_mc_memory_map() -> List[Dict[str, Any]]:
    """Programmatically generates the MC address map based on the defined architecture."""
    mem_map = [
        {'name': 'Master RegIface (conf)', 'start_addr': 0xA0000000, 'end_addr': 0xA00001FF, 'map_to_use': 'MC'},
        {'name': 'Master RegIface (stat)', 'start_addr': 0xA0008000, 'end_addr': 0xA00081FF, 'map_to_use': 'MC'},
    ]
    block_size = 0x200
    
    endpoints = [
        {'name': 'LVC',  'prefix': 'lv_',  'offset': 0x000},
        {'name': 'MVC1', 'prefix': 'mv1_', 'offset': 0x200},
        {'name': 'MVC2', 'prefix': 'mv2_', 'offset': 0x400},
    ]

    for link_num in range(1, 13):
        tx_link_base = 0xA0000000 + (link_num * 0x800)
        rx_link_base = 0xA0008000 + (link_num * 0x800)
        
        for ep in endpoints:
            tx_start = tx_link_base + ep['offset']
            mem_map.append({
                'name': f"Link-{link_num} - {ep['name']}TX",
                'start_addr': tx_start, 'end_addr': tx_start + block_size - 1,
                'map_to_use': 'LC', 'prefix': ep['prefix'],
            })
            rx_start = rx_link_base + ep['offset']
            mem_map.append({
                'name': f"Link-{link_num} - {ep['name']}RX",
                'start_addr': rx_start, 'end_addr': rx_start + block_size - 1,
                'map_to_use': 'LC', 'prefix': ep['prefix'],
            })
    return mem_map

def int_to_float32(i: int) -> float:
    try: return struct.unpack('f', struct.pack('I', i))[0]
    except struct.error: return float('nan')

def find_latest_file(prefix: str, directory: str) -> Optional[str]:
    pattern = re.compile(re.escape(prefix) + r"(\d+\.\d+\.\d+)\.xlsx$")
    latest_version, latest_file_path = (0, 0, 0), None
    try:
        for filename in os.listdir(directory):
            match = pattern.match(filename)
            if match:
                version_tuple = tuple(map(int, match.group(1).split('.')))
                if version_tuple > latest_version:
                    latest_version, latest_file_path = version_tuple, os.path.join(directory, filename)
    except FileNotFoundError: return None
    return latest_file_path

def load_register_map(excel_path: str) -> Dict[str, List[Dict[str, str]]]:
    register_map, REQUIRED_COLUMNS = {}, ['IO_Tool_Addr', 'RegDescription', 'posslice', 'Label', 'RegSize']
    try:
        df = pd.read_excel(excel_path, sheet_name=0, dtype=str).fillna('')
        if not all(col in df.columns for col in REQUIRED_COLUMNS):
            missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
            print(f"Error: Excel file '{excel_path}' is missing required columns: {missing}", file=sys.stderr); sys.exit(1)
        for row in df.to_dict('records'):
            base_addr_str = row.get('IO_Tool_Addr', '').strip().upper()
            if not base_addr_str: continue
            try: reg_size = int(float(row.get('RegSize', '1').strip()))
            except (ValueError, TypeError): reg_size = 1
            try: base_addr_int = int(base_addr_str, 16)
            except ValueError: continue
            original_label = row.get('Label', '').strip()
            data_format = 'float' if original_label.endswith(('_real', '_filt')) else 'decimal'
            for i in range(reg_size):
                offset_addr_int = base_addr_int + (i * 4)
                offset_addr_str = f"{offset_addr_int:X}"
                instance_label = f"{original_label}_{i + 1}" if reg_size > 1 else original_label
                field_info = {'description': row.get('RegDescription', '').strip(), 'slice': row.get('posslice', '').strip(), 'label': instance_label, 'format': data_format}
                if offset_addr_str not in register_map: register_map[offset_addr_str] = []
                if field_info not in register_map[offset_addr_str]:
                    register_map[offset_addr_str].append(field_info)
    except FileNotFoundError: print(f"Error: The file '{excel_path}' was not found.", file=sys.stderr); sys.exit(1)
    except Exception as e: print(f"An error occurred while reading Excel file '{excel_path}': {e}", file=sys.stderr); sys.exit(1)
    return register_map

def find_address_context(address_int: int, mc_mem_map: list) -> Tuple[Optional[str], Optional[dict], Optional[str]]:
    for block in mc_mem_map:
        if block['start_addr'] <= address_int <= block['end_addr']:
            map_to_use = block['map_to_use']
            if map_to_use == 'MC':
                return f"{address_int:X}", block, 'MC'
            elif map_to_use == 'LC':
                relative_offset = address_int - block['start_addr']
                lc_base = 0xA0008000 if (address_int & 0x8000) else 0xA0000000
                lc_lookup_addr = lc_base + relative_offset
                return f"{lc_lookup_addr:X}", block, 'LC'
    return None, None, None

def process_and_print_register(address_str: str, value_str: str, mc_map: dict, lc_map: dict, mc_mem_map: list):
    try: value_int = int(value_str, 16)
    except (ValueError, TypeError):
        print(f"Warning: Invalid value '{value_str}' for address '{address_str}'. Skipping.", file=sys.stderr); return
    try: address_int = int(address_str, 16)
    except (ValueError, TypeError):
        print(f"Warning: Invalid address format '{address_str}'. Skipping.", file=sys.stderr); return

    lookup_addr, block_info, map_type = find_address_context(address_int, mc_mem_map)

    if not lookup_addr:
        print(f"Warning: Address {address_str.upper()} not found in memory map. Skipping.", file=sys.stderr); return
    
    active_map = mc_map if map_type == 'MC' else lc_map
    if lookup_addr not in active_map:
        print(f"Warning: Address {address_str.upper()} decoded to lookup address {lookup_addr}, which is not in the {map_type} map. Skipping.", file=sys.stderr); return

    fields = active_map[lookup_addr]
    description = fields[0]['description']
    title = f"{block_info['name']}: {description}"
    prefix = block_info.get('prefix', '')

    print("-" * 80)
    # The "Decoding Register: " prefix has been removed from the next line.
    print(f"{title} (Address: {address_str.upper()})")
    print(f"Input Value: 0x{value_int:08X} ({value_int})")
    print("-" * 80)
    print(f"{'Label':<35} {'Slice':<10} {'Value (Hex)':<15} {'Interpreted Value':<17}")
    print(f"{'-'*35:<35} {'-'*10:<10} {'-'*15:<15} {'-'*17}")
    for field in fields:
        label, slice_str, data_format = field['label'], field['slice'], field.get('format', 'decimal')
        try:
            high, low = int(slice_str.split(':')[0]), int(slice_str.split(':')[1]) if ':' in slice_str else int(slice_str)
            width = high - low + 1
            field_value_int = ((value_int >> low) & ((1 << width) - 1))
            prefixed_label = f"{prefix}{label}"
            if data_format == 'float' and width == 32:
                float_val = int_to_float32(field_value_int)
                display_value = f"{float_val:g}"
                if '.' not in display_value and 'e' not in display_value.lower():
                    display_value += ".0"
            else:
                display_value = str(field_value_int)
                if data_format == 'float': display_value += " (non-32-bit)"
            print(f"{prefixed_label:<35} {slice_str:<10} {'0x' + hex(field_value_int)[2:].upper():<15} {display_value:<17}")
        except (ValueError, IndexError):
            print(f"Could not parse slice '{slice_str}' for label '{label}'. Skipping.")
    print("-" * 80 + "\n")

def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
        description="Decode register values using a detailed, link-aware memory map architecture.")
    parser.add_argument("address", nargs='?', default=None, help="The register address (for CLI mode).")
    parser.add_argument("value", nargs='?', default=None, help="The 32-bit value (for CLI mode).")
    parser.add_argument("--file", help="Path to a file containing address-value pairs to process.")
    parser.add_argument("--dir", default=".", help="Directory to search for register map files (default: current directory).")
    parser.add_argument("--mc-version", help="Specify an exact MC version to use (e.g., '0.8.0').")
    parser.add_argument("--lc-version", help="Specify an exact LC version to use (e.g., '0.11.0').")
    args = parser.parse_args()

    is_file_mode, is_cli_mode = args.file is not None, args.address is not None and args.value is not None
    if is_file_mode and is_cli_mode:
        parser.error("argument --file: not allowed with positional 'address' and 'value' arguments.")
    if not is_file_mode and not is_cli_mode:
        parser.error("the following arguments are required: address and value (for CLI mode) OR --file (for file mode).")

    search_dir = args.dir
    mc_file_path = os.path.join(search_dir, f"QBgMap_MC_{args.mc_version}.xlsx") if args.mc_version else find_latest_file("QBgMap_MC_", search_dir)
    lc_file_path = os.path.join(search_dir, f"QBgMap_LC_{args.lc_version}.xlsx") if args.lc_version else find_latest_file("QBgMap_LC_", search_dir)
    if not mc_file_path or not os.path.exists(mc_file_path):
        print("Error: MC register map file could not be found.", file=sys.stderr); sys.exit(1)
    if not lc_file_path or not os.path.exists(lc_file_path):
        print("Error: LC register map file could not be found.", file=sys.stderr); sys.exit(1)

    print(f"INFO: Using MC map: '{os.path.basename(mc_file_path)}'", file=sys.stderr)
    print(f"INFO: Using LC map: '{os.path.basename(lc_file_path)}'", file=sys.stderr)
    
    mc_map = load_register_map(mc_file_path)
    lc_map = load_register_map(lc_file_path)
    mc_mem_map = build_mc_memory_map()

    if is_file_mode:
        line_pattern = re.compile(r"^(0x[0-9a-fA-F]+)[\s:]+(0x[0-9a-fA-F]+)")
        try:
            with open(args.file, 'r') as f:
                for line in f:
                    match = line_pattern.match(line.strip())
                    if match:
                        process_and_print_register(match.group(1), match.group(2), mc_map, lc_map, mc_mem_map)
        except FileNotFoundError:
            print(f"Error: Input file not found: {args.file}", file=sys.stderr); sys.exit(1)
    else:
        process_and_print_register(args.address, args.value, mc_map, lc_map, mc_mem_map)

if __name__ == "__main__":
    main()