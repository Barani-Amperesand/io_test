import argparse
import json
import os
import re
import sys
import time
from urllib.parse import urlencode

import register_pb2
import requests
import serial

try:
    from parse_register import RegisterDecoder, find_latest_file

    DECODER_AVAILABLE = True
except ImportError:
    DECODER_AVAILABLE = False


def _print_warning_banner(messages):
    """Prints a highly visible warning banner."""
    print("\n" + "*" * 80)
    print("*" + " " * 78 + "*")
    for msg in messages:
        print(f"* {'!! WARNING !!':<15} {msg:<60} *")
    print("*" + " " * 78 + "*")
    print("*" * 80 + "\n")


def perform_version_check(comm_interface, mc_filepath, lc_filepath):
    """
    Reads hardware revision registers and compares them against register map file versions.
    """
    print("Performing hardware and file version integrity check...")

    mc_match = re.search(r"(\d+)\.(\d+)\.(\d+)", os.path.basename(mc_filepath))
    lc_match = re.search(r"(\d+)\.(\d+)\.(\d+)", os.path.basename(lc_filepath))

    if not mc_match or not lc_match:
        print(
            "WARNING: Could not parse version numbers from one or more register map filenames. Skipping check."
        )
        return

    mc_file_ver = tuple(map(int, mc_match.groups()))
    lc_file_ver = tuple(map(int, lc_match.groups()))

    mc_hw_val = comm_interface.read_single_register("A00080A4")
    if mc_hw_val is None:
        print("WARNING: Failed to read MC hardware revision register. Skipping check.")
    elif mc_hw_val == 0:
        print(
            "WARNING: MC hardware revision is 0x0. Device may be uninitialized. Skipping check."
        )
    else:
        hw_major, hw_minor, hw_patch = (
            (mc_hw_val >> 24) & 0xFF,
            (mc_hw_val >> 16) & 0xFF,
            (mc_hw_val >> 8) & 0xFF,
        )
        mc_hw_ver = (hw_major, hw_minor, hw_patch)
        if mc_hw_ver != mc_file_ver:
            _print_warning_banner(
                [
                    "Master Controller (MC) version mismatch!",
                    f"  Hardware reported: {hw_major}.{hw_minor}.{hw_patch}",
                    f"  Register map file is for: {mc_file_ver[0]}.{mc_file_ver[1]}.{mc_file_ver[2]}",
                    "Parsing results may be incorrect.",
                ]
            )

    lc_hw_val = comm_interface.read_single_register("A00088A8")
    if lc_hw_val is None:
        print("WARNING: Failed to read LC hardware revision register. Skipping check.")
    elif lc_hw_val == 0:
        print(
            "WARNING: LC hardware revision is 0x0. Device may be uninitialized. Skipping check."
        )
    else:
        hw_major, hw_minor, hw_patch = (
            (lc_hw_val >> 24) & 0xFF,
            (lc_hw_val >> 16) & 0xFF,
            (lc_hw_val >> 8) & 0xFF,
        )
        lc_hw_ver = (hw_major, hw_minor, hw_patch)
        if lc_hw_ver != lc_file_ver:
            _print_warning_banner(
                [
                    "Local Controller (LC) version mismatch!",
                    f"  Hardware reported: {hw_major}.{hw_minor}.{hw_patch}",
                    f"  Register map file is for: {lc_file_ver[0]}.{lc_file_ver[1]}.{lc_file_ver[2]}",
                    "Parsing results may be incorrect.",
                ]
            )

    print("Version integrity check complete.\n")


def parse_file_commands(lines):
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if not line:
            i += 1
            continue
        comment_pos = line.find("#")
        if comment_pos != -1:
            if comment_pos == 0:
                print(">> " + line[comment_pos + 1 :])
            line = line[:comment_pos].strip()
            if not line:
                i += 1
                continue
        if line.startswith("LOOP "):
            try:
                iteration_count = int(line.split()[1])
                loop_commands = []
                i += 1
                while i < len(lines):
                    loop_line = lines[i].strip()
                    comment_pos = loop_line.find("#")
                    if comment_pos != -1:
                        if comment_pos == 0:
                            print(">> " + loop_line[comment_pos + 1 :])
                        loop_line = loop_line[:comment_pos].strip()
                    if loop_line == "LOOP END":
                        break
                    elif loop_line:
                        loop_commands.append(loop_line)
                    i += 1
                if i >= len(lines) and (i == 0 or lines[i - 1].strip() != "LOOP END"):
                    raise ValueError("LOOP END not found")
                print(f">> Starting loop with {iteration_count} iterations")
                for iteration in range(iteration_count):
                    print(f">> Iteration {iteration + 1}/{iteration_count}")
                    for cmd in loop_commands:
                        yield cmd
                print(">> Loop completed")
            except (ValueError, IndexError) as e:
                print(f"Error in loop syntax: {e}")
        else:
            yield line
        i += 1


class VirtualPort:
    def __init__(self):
        self.is_open, self._buffer = True, b""

    def write(self, data):
        if data.startswith(b"R-A00080A4"):
            self._buffer += (
                b"Reading 4 bytes from address 0xA00080A4:\r\n00 08 00 14 \r\n>\r\n"
            )
        elif data.startswith(b"R-A00088A8"):
            self._buffer += (
                b"Reading 4 bytes from address 0xA00088A8:\r\n00 0B 00 00 \r\n>\r\n"
            )
        elif data.startswith(b"R-"):
            parts = data.strip().split(b"-")
            addr_str, count = parts[1].decode(), int(parts[2])
            self._buffer += (
                f"Reading {count} bytes from address 0x{addr_str}:\r\n".encode()
            )
            for i in range(count):
                self._buffer += f"{0xAA+i:02X} ".encode()
            if (i + 1) % 16 == 0:
                self._buffer += b"\r\n"
            self._buffer += b"\r\n>\r\n"
        elif data.startswith(b"W-"):
            parts = data.strip().split(b"-")
            addr_str, byte_count = parts[1].decode(), len(parts) - 2
            self._buffer += f"Writing {byte_count} bytes to address 0x{addr_str}\r\nOK\r\n>\r\n".encode()
        elif data.strip() == b"V":
            self._buffer += b"VirtualPort v1.0\r\n>\r\n"
        else:
            self._buffer += b"OK\r\n>\r\n"

    def read(self, size=1):
        if not self._buffer:
            return b""
        result = self._buffer[:size]
        self._buffer = self._buffer[size:]
        return result

    @property
    def in_waiting(self):
        return len(self._buffer)

    def close(self):
        self.is_open = False


class SerialCommandSender:
    def __init__(self, port, baudrate=115200, timeout=1, decoder=None):
        self.decoder = decoder
        if port.upper() == "VIRTUAL":
            print("Using VirtualPort for testing")
            self.ser = VirtualPort()
        else:
            try:
                self.ser = serial.Serial(
                    port=port,
                    baudrate=baudrate,
                    timeout=timeout,
                    bytesize=serial.EIGHTBITS,
                    parity=serial.PARITY_NONE,
                    stopbits=serial.STOPBITS_ONE,
                )
            except serial.SerialException as e:
                print(f"Error opening serial port {port}: {e}")
                sys.exit(1)

    def get_response(self):
        response = ""
        while True:
            if self.ser.in_waiting:
                char = self.ser.read().decode(errors="ignore")
                if ">" in char:
                    break
                response += char
            time.sleep(0.0001)
        return response.strip()

    def send_command(self, command):
        command_to_send = command.replace(" ", "-") + "\r\n"
        print(f">> {command}")
        self.ser.write(command_to_send.encode())
        return self.get_response()

    def read_single_register(self, address):
        command = f"R {address} 4"
        response_text = self.send_command(command)
        hex_bytes = re.findall(r"[0-9A-Fa-f]{2}", response_text)
        if len(hex_bytes) >= 4:
            word_str = "".join(hex_bytes[:4])
            return int(word_str, 16)
        return None

    def _parse_and_decode_read_response(self, response_text, base_address_str):
        base_addr_int = int(base_address_str, 16)

        try:
            data_payload = response_text.split(":", 1)[1]
        except IndexError:
            print("No data found in serial response (could not find ':' delimiter).")
            return

        hex_bytes = re.findall(r"[0-9A-Fa-f]{2}", data_payload)
        if not hex_bytes:
            print("No data found in serial response to parse.")
            return
        for i in range(0, len(hex_bytes), 4):
            chunk = hex_bytes[i : i + 4]
            if len(chunk) < 4:
                continue
            word_int, word_addr = int("".join(chunk), 16), base_addr_int + i
            self.decoder.decode(word_addr, word_int, do_print=True)

    def process_file(self, filename):
        try:
            with open(filename, "r") as file:
                lines = file.readlines()
            for command in parse_file_commands(lines):
                response = self.send_command(command)
                if command.startswith("R ") and self.decoder:
                    self._parse_and_decode_read_response(response, command.split()[1])
                elif command.startswith("W ") and self.decoder:
                    parts, byte_payload = command.split(), command.split()[2:]
                    base_addr_int = int(parts[1], 16)
                    print(f"Parsing Write Payload for Base Address: {parts[1]}")
                    for i in range(0, len(byte_payload), 4):
                        chunk = byte_payload[i : i + 4]
                        if len(chunk) < 4:
                            continue
                        word_int, word_addr = int("".join(chunk), 16), base_addr_int + i
                        self.decoder.decode(word_addr, word_int, do_print=True)
                    print(response + "\n")
                else:
                    print(response + "\n")
        except Exception as e:
            print(f"Error during serial processing: {e}")

    def close(self):
        if self.ser.is_open:
            self.ser.close()


class ReadRegisterInterface:
    def __init__(self, base_url, decoder=None):
        self.base_url, self.decoder = base_url, decoder

    def read(self, address, count):
        query = urlencode({"address": address, "count": count})
        url = f"{self.base_url}/register/read?{query}"
        try:
            response = requests.get(url)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"Error sending request: {e}")
            return
        data, register_interface = response.content, register_pb2.RegisterInterface()
        try:
            register_interface.ParseFromString(data)
        except Exception as e:
            print(f"Error decoding protobuf: {e}")
            return
        for i, value in enumerate(register_interface.result[: int(count)]):
            addr_offset = register_interface.address + (i * 4)
            if self.decoder:
                self.decoder.decode(addr_offset, value, do_print=True)
            else:
                print(f"0x{addr_offset:08X} 0x{value:08X}")

    def read_single_register(self, address):
        query = urlencode({"address": address, "count": 1})
        url = f"{self.base_url}/register/read?{query}"
        try:
            response = requests.get(url)
            response.raise_for_status()
        except requests.exceptions.RequestException:
            return None
        data, register_interface = response.content, register_pb2.RegisterInterface()
        try:
            register_interface.ParseFromString(data)
            if register_interface.result:
                return register_interface.result[0]
        except Exception:
            return None
        return None

    def write(self, address, payload):
        count = len(payload)
        payload = payload + [0] * (64 - count)
        register_interface = register_pb2.RegisterInterface(
            handshake=0,
            address=int(address, 16),
            count=int(count),
            payload=payload,
            result=[],
            operation=register_pb2.RegisterOperation.RO_WRITE,
        )
        url = f"{self.base_url}/register/write"
        try:
            response = requests.post(
                url,
                data=register_interface.SerializeToString(),
                headers={"Content-Type": "application/octet-stream"},
                timeout=10,
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"Error sending request: {e}")
            return
        data, register_interface = response.content, register_pb2.RegisterInterface()
        try:
            register_interface.ParseFromString(data)
        except Exception as e:
            print(f"Error decoding protobuf: {e}")
            return


class CommandParsing:
    pattern = r"^\s*([RW])\s+([0-9A-Fa-f]+)\s+(.*)$"

    def __init__(self, ip=None, decoder=None):
        if not ip.startswith("http"):
            self.ip = f"http://{ip}"
        else:
            self.ip = ip
        self.reg_interface = ReadRegisterInterface(self.ip, decoder=decoder)

    def parse(self, lines):
        for command_line in parse_file_commands(lines):
            if command_line.startswith("D "):
                try:
                    milliseconds, seconds = (
                        int(command_line.split()[1]),
                        int(command_line.split()[1]) / 1000.0,
                    )
                    print(f">> Delaying for {milliseconds} milliseconds...")
                    time.sleep(seconds)
                except (ValueError, IndexError):
                    print(f"Error: Invalid delay format: '{command_line}'.")
                continue
            match = re.match(self.pattern, command_line)
            if match:
                operation, address, payload_str = match.groups()
                if operation == "R":
                    count = int(payload_str.strip()) // 4
                    print(f">> Reading: address={address}, count={count}")
                    self.reg_interface.read(address, count)
                    print()
                elif operation == "W":
                    payload_parts = payload_str.strip().split()
                    if not payload_parts:
                        print(f"Error: Write command has no payload: '{command_line}'")
                        continue
                    try:
                        payload = []
                        if len(payload_parts[0]) == 8:
                            if not all(len(p) == 8 for p in payload_parts):
                                raise ValueError(
                                    "If using 8-char words, all must be 8 chars long."
                                )
                            for word_string in payload_parts:
                                payload.append(int(word_string, 16))
                        elif len(payload_parts[0]) == 2:
                            if len(payload_parts) % 4 != 0:
                                raise ValueError(
                                    f"Byte count must be a multiple of 4. Got {len(payload_parts)}."
                                )
                            for i in range(0, len(payload_parts), 4):
                                chunk = payload_parts[i : i + 4]
                                full_hex_string = "".join(chunk)
                                payload.append(int(full_hex_string, 16))
                        else:
                            raise ValueError(
                                "Payload must be space-separated 8-char words OR 2-char bytes."
                            )
                        if self.reg_interface.decoder:
                            print(
                                f">> Writing Parsed Payload to Base Address: {address}"
                            )
                            base_addr_int = int(address, 16)
                            for i, word in enumerate(payload):
                                word_addr = base_addr_int + (i * 4)
                                self.reg_interface.decoder.decode(
                                    word_addr, word, do_print=True
                                )
                        else:
                            hex_values_str = ", ".join([f"0x{v:08X}" for v in payload])
                            print(
                                f"Writing: address={address}, values=[{hex_values_str}]"
                            )
                        self.reg_interface.write(address, payload)
                    except ValueError as e:
                        print(
                            f"Error processing write command: '{command_line}'\n  -> {e}"
                        )
                        continue
                    print()
            else:
                print(f"Skipping non-matching command: '{command_line}'")


def get_ip_config(device_identifier, config_file="devices.json"):
    """
    Resolves a device identifier to an IP:port string.
    - If identifier is a key in config_file, returns its config (e.g., "mc-51").
    - If identifier is not in config_file, assumes it's a direct IP:port string.
    """
    if os.path.exists(config_file):
        try:
            with open(config_file, "r") as f:
                devices = json.load(f)
            if device_identifier in devices:
                device_info = devices[device_identifier]
                return f"{device_info['ip']}:{device_info['port']}"
        except (json.JSONDecodeError, KeyError) as e:
            # Raise an error to be caught in main for a clearer message
            raise ValueError(f"Error reading or parsing {config_file}: {e}")
    # If config file doesn't exist or identifier not found, assume it's a direct IP.
    return device_identifier


# ==============================================================================
# Main Execution Logic
# ==============================================================================
def main():
    # Dynamically determine the correct way to call the program in examples
    if getattr(sys, 'frozen', False):
        # Running as a bundled exe (e.g., bitwise.exe)
        invocation_cmd = os.path.basename(sys.executable)
    else:
        # Running as a .py script
        invocation_cmd = f"python {os.path.basename(sys.argv[0])}"

    # To use device names, create a 'devices.json' file in the same directory:
    # {
    #   "mc-51": { "ip": "192.0.2.51", "port": 7124 },
    #   "mc-58": { "ip": "192.168.0.58", "port": 7124 }
    # }
    parser = argparse.ArgumentParser(
        description="A versatile tool for device communication and log decoding. The execution mode is determined automatically. Parsing is enabled by default.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=f"""
Examples:
  # Run commands over HTTP by specifying a device name from devices.json
  {invocation_cmd} my_commands.txt --ip mc-51

  # Run commands over HTTP by specifying a raw IP address and port
  {invocation_cmd} my_commands.txt --ip 192.168.0.59:7124

  # Run commands over Serial
  {invocation_cmd} my_commands.txt --port COM3

  # Decode a local file (parsing is always enabled for this mode)
  {invocation_cmd} --file captured_data.log
""",
    )

    # Core arguments that determine mode
    parser.add_argument(
        "command_file",
        nargs="?",
        help="Path to the command file to execute (required for http/serial modes).",
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--ip",
        help="Use http mode. Provide a device name from devices.json or a direct IP:PORT.",
    )
    mode_group.add_argument(
        "--port",
        help="Use serial mode with the specified COM port (e.g., COM3 or /dev/ttyUSB0).",
    )
    mode_group.add_argument(
        "--file", help="Use decode-only mode on a local file of register data."
    )

    # Ancillary arguments
    parser.add_argument(
        "--no-parse",
        dest="parse",
        action="store_false",
        help="Disable register value parsing and bit-field decoding.",
    )
    parser.add_argument(
        "--dir",
        default="./register_maps/",
        help="Directory to search for register map files. Defaults to './register_maps/'.",
    )
    parser.add_argument(
        "--mc-version", help="Specify an exact MC version to use (e.g., '0.8.0')."
    )
    parser.add_argument(
        "--lc-version", help="Specify an exact LC version to use (e.g., '0.11.0')."
    )
    parser.set_defaults(parse=True)

    args = parser.parse_args()

    # Mode Detection and Argument Validation
    mode = "http"  # Default mode
    if args.port:
        mode = "serial"
    elif args.file:
        mode = "decode"
    elif args.ip:
        mode = "http"

    if mode == "http" and not args.ip:
        parser.error(
            "An --ip argument is required for http mode. Please provide a device name or a raw IP:PORT."
        )

    if mode in ["serial", "http"]:
        if not args.command_file:
            parser.error(
                f"A positional 'command_file' argument is required for {mode} mode."
            )
    elif mode == "decode":
        if args.command_file:
            parser.error(
                "A 'command_file' positional argument cannot be used with --file (decode mode)."
            )
        if not args.parse:
            print(
                "INFO: The --no-parse flag is ignored in 'decode' mode as parsing is required."
            )
        args.parse = True

    print("BitWise - v1.0")

    # Decoder Setup
    decoder = None
    mc_file, lc_file = None, None
    if args.parse:
        if not DECODER_AVAILABLE:
            print(
                "\nWARNING: Parsing is disabled because 'parse_register.py' could not be imported.\n"
            )
        else:
            print("INFO: Parsing is enabled.")
            search_dir = args.dir
            mc_file = (
                os.path.join(search_dir, f"QBgMap_MC_{args.mc_version}.csv")
                if args.mc_version
                else find_latest_file("QBgMap_MC_", search_dir)
            )
            lc_file = (
                os.path.join(search_dir, f"QBgMap_LC_{args.lc_version}.csv")
                if args.lc_version
                else find_latest_file("QBgMap_LC_", search_dir)
            )
            if not mc_file or not lc_file:
                print(
                    "\nWARNING: Parsing is disabled. Could not find required MC/LC register map files.\n"
                )
            else:
                decoder = RegisterDecoder(mc_file_path=mc_file, lc_file_path=lc_file)
    else:
        print("INFO: Parsing is disabled by user.")
    print()

    # Mode Execution
    if mode == "serial":
        print(f"Running in SERIAL mode (File: {args.command_file}, Port: {args.port})")
        print()
        sender = None
        try:
            sender = SerialCommandSender(args.port, decoder=decoder)
            if mc_file and lc_file and decoder:
                perform_version_check(sender, mc_file, lc_file)
            sender.process_file(args.command_file)
        except Exception as e:
            print(f"An error occurred during serial execution: {e}")
        finally:
            if sender:
                sender.close()
        print("Serial mode finished.")

    elif mode == "http":
        try:
            ip_address = get_ip_config(args.ip)
        except ValueError as e:
            parser.error(f"IP Configuration Error: {e}")

        print(f"Running in HTTP mode (File: {args.command_file}, Target: {ip_address})")
        print()
        try:
            with open(args.command_file, "r") as f:
                lines = f.readlines()
            parser_obj = CommandParsing(ip=ip_address, decoder=decoder)
            if mc_file and lc_file and decoder:
                perform_version_check(parser_obj.reg_interface, mc_file, lc_file)
            parser_obj.parse(lines)
        except Exception as e:
            print(f"An error occurred during HTTP execution: {e}")
        print("HTTP mode finished.")

    elif mode == "decode":
        print(f"Running in DECODE-ONLY mode (Input File: {args.file})")
        print()
        if not decoder:
            print(
                "Error: Parsing is required for decode mode, but the decoder could not be initialized."
            )
            print(
                "Please ensure 'parse_register.py' and the required register map files are available."
            )
            sys.exit(1)

        line_pattern = re.compile(r"^(0x[0-9a-fA-F]+)[\s:]+(0x[0-9a-fA-F]+)")
        try:
            with open(args.file, "r") as f:
                for line in f:
                    match = line_pattern.match(line.strip())
                    if match:
                        decoder.decode(match.group(1), match.group(2), do_print=True)
        except FileNotFoundError:
            print(f"Error: Input file not found: {args.file}")
            sys.exit(1)
        print("Decode-only mode finished.")


if __name__ == "__main__":
    main()
