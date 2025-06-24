import argparse
import os
import re
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple, Union

import pandas as pd


# Standalone utility function for file discovery
def find_latest_file(prefix: str, directory: str) -> Optional[str]:
    """Finds the file in a directory that matches a prefix and has the latest version."""
    pattern = re.compile(re.escape(prefix) + r"(\d+\.\d+\.\d+)\.xlsx$")
    latest_version, latest_file_path = (0, 0, 0), None
    try:
        for filename in os.listdir(directory):
            match = pattern.match(filename)
            if match:
                version_tuple = tuple(map(int, match.group(1).split(".")))
                if version_tuple > latest_version:
                    latest_version, latest_file_path = version_tuple, os.path.join(
                        directory, filename
                    )
    except FileNotFoundError:
        return None
    return latest_file_path


class RegisterDecoder:
    """A class to load register maps and decode register values."""

    def __init__(self, mc_file_path: str, lc_file_path: str):
        """
        Initializes the decoder by loading register maps. This is the expensive, one-time setup.

        Args:
            mc_file_path: Path to the Master Controller register map Excel file.
            lc_file_path: Path to the Local Controller register map Excel file.
        """
        print(
            f"INFO: Initializing decoder with MC map: '{os.path.basename(mc_file_path)}'",
            file=sys.stderr,
        )
        print(
            f"INFO: Initializing decoder with LC map: '{os.path.basename(lc_file_path)}'",
            file=sys.stderr,
        )
        self.mc_map = self._load_register_map(mc_file_path)
        self.lc_map = self._load_register_map(lc_file_path)
        self.mc_mem_map = self._build_mc_memory_map()
        print("INFO: Decoder initialized successfully.", file=sys.stderr)

    def decode(
        self, address: Union[int, str], value: Union[int, str], do_print: bool = False
    ) -> Optional[List[Dict[str, Any]]]:
        """
        Decodes a single register address and value.

        Args:
            address: The register address (integer or hex string).
            value: The 32-bit register value (integer or hex string).
            do_print: If True, prints the formatted output to the console.

        Returns:
            A list of dictionaries, where each dictionary represents a decoded bit-field,
            or None if the address or value is invalid.
        """
        try:
            address_int = int(address, 16) if isinstance(address, str) else address
            value_int = int(value, 16) if isinstance(value, str) else value
        except (ValueError, TypeError):
            print(
                f"Warning: Invalid address or value format. Skipping.", file=sys.stderr
            )
            return None

        lookup_addr, block_info, map_type = self._find_address_context(address_int)

        if not lookup_addr:
            if do_print:
                print(
                    f"Warning: Address {hex(address_int).upper()} not found in memory map. Skipping.",
                    file=sys.stderr,
                )
            return None

        active_map = self.mc_map if map_type == "MC" else self.lc_map
        if lookup_addr not in active_map:
            if do_print:
                print(
                    f"Warning: Address {hex(address_int).upper()} decoded to lookup address {lookup_addr}, which is not in the {map_type} map. Skipping.",
                    file=sys.stderr,
                )
            return None

        fields = active_map[lookup_addr]
        decoded_fields = []

        for field_data in fields:
            label, slice_str, data_format = (
                field_data["label"],
                field_data["slice"],
                field_data.get("format", "decimal"),
            )
            try:
                high, low = int(slice_str.split(":")[0]), (
                    int(slice_str.split(":")[1]) if ":" in slice_str else int(slice_str)
                )
                width = high - low + 1
                field_value_int = (value_int >> low) & ((1 << width) - 1)

                if data_format == "float" and width == 32:
                    interpreted_value = self._int_to_float32(field_value_int)
                else:
                    interpreted_value = field_value_int

                decoded_fields.append(
                    {
                        "label": field_data["label"],
                        "slice": slice_str,
                        "hex_value": f"0x{field_value_int:X}",
                        "interpreted_value": interpreted_value,
                        "format": data_format,
                        "register_name": field_data.get("register_name", "N/A"),
                    }
                )
            except (ValueError, IndexError):
                continue

        if do_print:
            self._print_decoded_output(
                hex(address_int),
                value_int,
                block_info,
                fields[0]["description"],
                decoded_fields,
            )

        return decoded_fields

    def _print_decoded_output(
        self,
        address_str: str,
        value_int: int,
        block_info: dict,
        description: str,
        decoded_fields: list,
    ):
        """Private helper to handle the console printing."""
        title = f"{block_info['name']}: {description}"
        prefix = block_info.get("prefix", "")
        register_name = decoded_fields[0].get("register_name", "N/A")

        print("-" * 80)
        print(f"{title} (Address: {address_str.upper()})")
        print(f"Input Value: 0x{value_int:08X} ({value_int})")
        print(f"Register: {register_name}")
        print("-" * 80)
        print(
            f"{'Label':<35} {'Slice':<10} {'Value (Hex)':<15} {'Interpreted Value':<17}"
        )
        print(f"{'-'*35:<35} {'-'*10:<10} {'-'*15:<15} {'-'*17}")
        for field in decoded_fields:
            prefixed_label = f"{prefix}{field['label']}"
            display_value = self._format_display_value(
                field["interpreted_value"], field["format"]
            )
            print(
                f"{prefixed_label:<35} {field['slice']:<10} {field['hex_value']:<15} {display_value:<17}"
            )
        print("-" * 80 + "\n")

    def _format_display_value(self, value: Any, data_format: str) -> str:
        """Private helper to format the final value for printing."""
        if data_format == "float":
            display_str = f"{value:g}"
            if "." not in display_str and "e" not in display_str.lower():
                display_str += ".0"
            return display_str
        return str(value)

    def _find_address_context(
        self, address_int: int
    ) -> Tuple[Optional[str], Optional[dict], Optional[str]]:
        for block in self.mc_mem_map:
            if block["start_addr"] <= address_int <= block["end_addr"]:
                map_to_use = block["map_to_use"]
                if map_to_use == "MC":
                    return f"{address_int:X}", block, "MC"
                elif map_to_use == "LC":
                    relative_offset = address_int - block["start_addr"]
                    lc_base = 0xA0008000 if (address_int & 0x8000) else 0xA0000000
                    return f"{lc_base + relative_offset:X}", block, "LC"
        return None, None, None

    @staticmethod
    def _int_to_float32(i: int) -> float:
        try:
            return struct.unpack("f", struct.pack("I", i))[0]
        except struct.error:
            return float("nan")

    @staticmethod
    def _build_mc_memory_map() -> List[Dict[str, Any]]:
        mem_map, block_size = [
            {
                "name": "Master RegIface (conf)",
                "start_addr": 0xA0000000,
                "end_addr": 0xA00001FF,
                "map_to_use": "MC",
            },
            {
                "name": "Master RegIface (stat)",
                "start_addr": 0xA0008000,
                "end_addr": 0xA00081FF,
                "map_to_use": "MC",
            },
        ], 0x200
        endpoints = [
            {"name": "LVC", "prefix": "lv_", "offset": 0x000},
            {"name": "MVC1", "prefix": "mv1_", "offset": 0x200},
            {"name": "MVC2", "prefix": "mv2_", "offset": 0x400},
        ]
        for link_num in range(1, 13):
            tx_base, rx_base = 0xA0000000 + (link_num * 0x800), 0xA0008000 + (
                link_num * 0x800
            )
            for ep in endpoints:
                mem_map.append(
                    {
                        "name": f"Link-{link_num} - {ep['name']}TX",
                        "start_addr": tx_base + ep["offset"],
                        "end_addr": tx_base + ep["offset"] + block_size - 1,
                        "map_to_use": "LC",
                        "prefix": ep["prefix"],
                    }
                )
                mem_map.append(
                    {
                        "name": f"Link-{link_num} - {ep['name']}RX",
                        "start_addr": rx_base + ep["offset"],
                        "end_addr": rx_base + ep["offset"] + block_size - 1,
                        "map_to_use": "LC",
                        "prefix": ep["prefix"],
                    }
                )
        return mem_map

    @staticmethod
    def _load_register_map(excel_path: str) -> Dict[str, List[Dict[str, str]]]:
        register_map, REQUIRED_COLUMNS = {}, [
            "IO_Tool_Addr",
            "RegDescription",
            "Instance",
            "Register",
            "posslice",
            "Label",
            "RegSize",
        ]
        folat_fields = ("_real", "_filt", "_scale", "_offset")
        try:
            df = pd.read_excel(excel_path, sheet_name=0, dtype=str).fillna("")
            if not all(col in df.columns for col in REQUIRED_COLUMNS):
                print(
                    f"Error: Excel file '{excel_path}' is missing {set(REQUIRED_COLUMNS) - set(df.columns)}",
                    file=sys.stderr,
                )
                sys.exit(1)
            for row in df.to_dict("records"):
                base_addr_str = row.get("IO_Tool_Addr", "").strip().upper()
                if not base_addr_str:
                    continue
                try:
                    reg_size = int(float(row.get("RegSize", "1").strip()))
                except (ValueError, TypeError):
                    reg_size = 1
                try:
                    base_addr_int = int(base_addr_str, 16)
                except ValueError:
                    continue
                original_label, data_format = row.get("Label", "").strip(), (
                    "float"
                    if row.get("Label", "").strip().endswith(folat_fields)
                    else "decimal"
                )
                for i in range(reg_size):
                    offset_addr_str = f"{base_addr_int + (i * 4):X}"
                    instance_label = (
                        f"{original_label}_{i + 1}" if reg_size > 1 else original_label
                    )
                    field_info = {
                        "description": row.get("RegDescription", "").strip(),
                        "slice": row.get("posslice", "").strip(),
                        "label": instance_label,
                        "format": data_format,
                        "register_name": row.get("Instance", "").strip()
                        + "_"
                        + row.get("Register", "").strip(),
                    }
                    if offset_addr_str not in register_map:
                        register_map[offset_addr_str] = []
                    if field_info not in register_map[offset_addr_str]:
                        register_map[offset_addr_str].append(field_info)
        except FileNotFoundError:
            print(f"Error: The file '{excel_path}' was not found.", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(
                f"An error occurred while reading Excel file '{excel_path}': {e}",
                file=sys.stderr,
            )
            sys.exit(1)
        return register_map


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description="Decode register values from CLI or a file, using a detailed, link-aware memory map architecture.",
    )
    parser.add_argument(
        "address", nargs="?", default=None, help="The register address (for CLI mode)."
    )
    parser.add_argument(
        "value", nargs="?", default=None, help="The 32-bit value (for CLI mode)."
    )
    parser.add_argument(
        "--file", help="Path to a file containing address-value pairs to process."
    )
    parser.add_argument(
        "--dir",
        default=".",
        help="Directory to search for register map files (default: current directory).",
    )
    parser.add_argument(
        "--mc-version", help="Specify an exact MC version to use (e.g., '0.8.0')."
    )
    parser.add_argument(
        "--lc-version", help="Specify an exact LC version to use (e.g., '0.11.0')."
    )
    args = parser.parse_args()

    is_file_mode, is_cli_mode = (
        args.file is not None,
        args.address is not None and args.value is not None,
    )
    if is_file_mode and is_cli_mode:
        parser.error(
            "argument --file: not allowed with positional 'address' and 'value' arguments."
        )
    if not is_file_mode and not is_cli_mode:
        parser.error(
            "the following arguments are required: address and value (for CLI mode) OR --file (for file mode)."
        )

    search_dir = args.dir
    mc_file_path = (
        os.path.join(search_dir, f"QBgMap_MC_{args.mc_version}.xlsx")
        if args.mc_version
        else find_latest_file("QBgMap_MC_", search_dir)
    )
    lc_file_path = (
        os.path.join(search_dir, f"QBgMap_LC_{args.lc_version}.xlsx")
        if args.lc_version
        else find_latest_file("QBgMap_LC_", search_dir)
    )
    if not mc_file_path or not os.path.exists(mc_file_path):
        print("Error: MC register map file could not be found.", file=sys.stderr)
        sys.exit(1)
    if not lc_file_path or not os.path.exists(lc_file_path):
        print("Error: LC register map file could not be found.", file=sys.stderr)
        sys.exit(1)

    decoder = RegisterDecoder(mc_file_path=mc_file_path, lc_file_path=lc_file_path)

    if is_file_mode:
        line_pattern = re.compile(r"^(0x[0-9a-fA-F]+)[\s:]+(0x[0-9a-fA-F]+)")
        try:
            with open(args.file, "r") as f:
                for line in f:
                    match = line_pattern.match(line.strip())
                    if match:
                        decoder.decode(match.group(1), match.group(2), do_print=True)
        except FileNotFoundError:
            print(f"Error: Input file not found: {args.file}", file=sys.stderr)
            sys.exit(1)
    else:
        decoder.decode(args.address, args.value, do_print=True)
