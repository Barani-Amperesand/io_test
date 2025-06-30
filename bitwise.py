import argparse
import json
import os
import re
import sys
import time
import struct
import logging
from datetime import datetime
from urllib.parse import urlencode
from abc import ABC, abstractmethod

# Attempt to import dependencies, handle failure gracefully
try:
    import register_pb2
    import requests
    import serial
except ImportError as e:
    print(f"Error: Missing dependency -> {e}. Please install requirements.", file=sys.stderr)
    sys.exit(1)

try:
    from parse_register import RegisterDecoder, find_latest_file
    DECODER_AVAILABLE = True
except ImportError:
    DECODER_AVAILABLE = False


# ==============================================================================
# Helper Functions & Core Classes (Unchanged from previous version)
# Omitted for brevity, but they are included in the final script below.
# Includes: _print_warning_banner, perform_version_check, parse_file_commands,
# SerialCommandSender, ReadRegisterInterface, CommandParsing, MCSRecord,
# FirmwareBlock, MCSParser, FwUpdateCommunicator (and its subclasses),
# DeviceConnection, SPIController, FlashMemory, FirmwareTransmitter.
# ==============================================================================

def _print_warning_banner(messages):
    """Prints a highly visible warning banner."""
    print("\n" + "*" * 80)
    print("*" + " " * 78 + "*")
    for msg in messages:
        print(f"* {'!! WARNING !!':<15} {msg:<60} *")
    print("*" + " " * 78 + "*")
    print("*" * 80 + "\n")

# ... (All other classes and functions from the previous response go here) ...
# The following is the full set of required classes and functions.

def perform_version_check(comm_interface, mc_filepath, lc_filepath):
    print("Performing hardware and file version integrity check...")
    mc_match = re.search(r"(\d+)\.(\d+)\.(\d+)", os.path.basename(mc_filepath))
    lc_match = re.search(r"(\d+)\.(\d+)\.(\d+)", os.path.basename(lc_filepath))
    if not mc_match or not lc_match:
        print("WARNING: Could not parse version numbers from register map filenames. Skipping check.")
        return
    mc_file_ver = tuple(map(int, mc_match.groups()))
    lc_file_ver = tuple(map(int, lc_match.groups()))
    mc_hw_val = comm_interface.read_single_register("A00080A4")
    if mc_hw_val is None: print("WARNING: Failed to read MC hardware revision register. Skipping check.")
    elif mc_hw_val == 0: print("WARNING: MC hardware revision is 0x0. Device may be uninitialized. Skipping check.")
    else:
        hw_major, hw_minor, hw_patch = ((mc_hw_val >> 24) & 0xFF, (mc_hw_val >> 16) & 0xFF, (mc_hw_val >> 8) & 0xFF)
        if (hw_major, hw_minor, hw_patch) != mc_file_ver:
            _print_warning_banner([
                "Master Controller (MC) version mismatch!",
                f"  Hardware reported: {hw_major}.{hw_minor}.{hw_patch}",
                f"  Register map file is for: {mc_file_ver[0]}.{mc_file_ver[1]}.{mc_file_ver[2]}",
                "Parsing results may be incorrect."])
    lc_hw_val = comm_interface.read_single_register("A00088A8")
    if lc_hw_val is None: print("WARNING: Failed to read LC hardware revision register. Skipping check.")
    elif lc_hw_val == 0: print("WARNING: LC hardware revision is 0x0. Device may be uninitialized. Skipping check.")
    else:
        hw_major, hw_minor, hw_patch = ((lc_hw_val >> 24) & 0xFF, (lc_hw_val >> 16) & 0xFF, (lc_hw_val >> 8) & 0xFF)
        if (hw_major, hw_minor, hw_patch) != lc_file_ver:
            _print_warning_banner([
                "Local Controller (LC) version mismatch!",
                f"  Hardware reported: {hw_major}.{hw_minor}.{hw_patch}",
                f"  Register map file is for: {lc_file_ver[0]}.{lc_file_ver[1]}.{lc_file_ver[2]}",
                "Parsing results may be incorrect."])
    print("Version integrity check complete.\n")

def parse_file_commands(lines):
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if not line: i += 1; continue
        comment_pos = line.find("#")
        if comment_pos != -1:
            if comment_pos == 0: print(">> " + line[comment_pos + 1 :])
            line = line[:comment_pos].strip()
            if not line: i += 1; continue
        if line.startswith("LOOP "):
            try:
                iteration_count = int(line.split()[1])
                loop_commands = []
                i += 1
                while i < len(lines):
                    loop_line = lines[i].strip()
                    comment_pos = loop_line.find("#")
                    if comment_pos != -1:
                        if comment_pos == 0: print(">> " + loop_line[comment_pos + 1 :])
                        loop_line = loop_line[:comment_pos].strip()
                    if loop_line == "LOOP END": break
                    elif loop_line: loop_commands.append(loop_line)
                    i += 1
                if i >= len(lines) and (i == 0 or lines[i - 1].strip() != "LOOP END"): raise ValueError("LOOP END not found")
                print(f">> Starting loop with {iteration_count} iterations")
                for iteration in range(iteration_count):
                    print(f">> Iteration {iteration + 1}/{iteration_count}")
                    for cmd in loop_commands: yield cmd
                print(">> Loop completed")
            except (ValueError, IndexError) as e: print(f"Error in loop syntax: {e}")
        else:
            yield line
        i += 1

class VirtualPort:
    def __init__(self):
        self.is_open, self._buffer = True, b""

    def write(self, data):
        # This is a simplified mock. You can expand it to simulate more responses.
        if data.startswith(b"R-A00080A4"):
            self._buffer += b"Reading 4 bytes from address 0xA00080A4:\r\n00 08 00 14 \r\n>\r\n"
        elif data.startswith(b"R-"):
            self._buffer += b"Reading 4 bytes from address 0x...:\r\nAA BB CC DD \r\n>\r\n"
        elif data.startswith(b"W-"):
            self._buffer += b"Writing bytes to address 0x...\r\nOK\r\n>\r\n"
        else:
            self._buffer += b"OK\r\n>\r\n"

    def read(self, size=1):
        if not self._buffer:
            return b""
        result = self._buffer[:size]
        self._buffer = self._buffer[size:]
        return result

    def read_until(self, expected=b'>'):
        # A simple implementation for read_until to work with the mock buffer
        try:
            index = self._buffer.index(expected) + len(expected)
            result = self._buffer[:index]
            self._buffer = self._buffer[index:]
            return result
        except ValueError:
            # If expected char is not found, return whatever is in the buffer
            result = self._buffer
            self._buffer = b""
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
            print("Using VirtualPort for testing.")
            self.ser = VirtualPort()
            return

        try:
            self.ser = serial.Serial(port=port, baudrate=baudrate, timeout=timeout, bytesize=serial.EIGHTBITS, parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE)
        except serial.SerialException as e:
            print(f"Error opening serial port {port}: {e}", file=sys.stderr); sys.exit(1)
    def get_response(self):
        try:
            line = self.ser.read_until(b'>').decode(errors="ignore"); return line.strip('>').strip()
        except serial.SerialException as e:
            print(f"Error during serial read: {e}", file=sys.stderr); return ""
    def send_command(self, command, silent=False):
        command_to_send = command.replace(" ", "-") + "\r\n"
        if not silent: print(f">> {command}")
        logging.info(f"Req: {command_to_send.strip()}")
        self.ser.write(command_to_send.encode())
        response = self.get_response()
        logging.info(f"Res: {response}")
        return response
    def read_single_register(self, address):
        response_text = self.send_command(f"R {address} 4")
        hex_bytes = re.findall(r"[0-9A-Fa-f]{2}", response_text)
        if len(hex_bytes) >= 4: return int("".join(hex_bytes[:4]), 16)
        return None
    def _parse_and_decode_read_response(self, response_text, base_address_str):
        base_addr_int = int(base_address_str, 16)
        try: data_payload = response_text.split(":", 1)[1]
        except IndexError: print("No data found in serial response."); return
        hex_bytes = re.findall(r"[0-9A-Fa-f]{2}", data_payload)
        if not hex_bytes: print("No data found to parse."); return
        for i in range(0, len(hex_bytes), 4):
            chunk = hex_bytes[i : i + 4]
            if len(chunk) < 4: continue
            word_int, word_addr = int("".join(chunk), 16), base_addr_int + i
            self.decoder.decode(word_addr, word_int, do_print=True)
    def process_file(self, filename):
        try:
            with open(filename, "r") as file: lines = file.readlines()
            for command in parse_file_commands(lines):
                response = self.send_command(command)
                if command.startswith("R ") and self.decoder: self._parse_and_decode_read_response(response, command.split()[1])
                elif command.startswith("W ") and self.decoder:
                    parts, byte_payload = command.split(), command.split()[2:]
                    base_addr_int = int(parts[1], 16)
                    print(f"Parsing Write Payload for Base Address: {parts[1]}")
                    for i in range(0, len(byte_payload), 4):
                        chunk = byte_payload[i : i + 4]
                        if len(chunk) < 4: continue
                        word_int, word_addr = int("".join(chunk), 16), base_addr_int + i
                        self.decoder.decode(word_addr, word_int, do_print=True)
                    print(response + "\n")
                else: print(response + "\n")
        except Exception as e: print(f"Error during serial processing: {e}")
    def close(self):
        if self.ser and self.ser.is_open: self.ser.close()

class ReadRegisterInterface:
    def __init__(self, base_url, decoder=None):
        self.base_url, self.decoder = base_url, decoder
    def read(self, address, count):
        query = urlencode({"address": address, "count": count})
        url = f"{self.base_url}/register/read?{query}"
        try:
            response = requests.get(url); response.raise_for_status()
            data, register_interface = response.content, register_pb2.RegisterInterface()
            register_interface.ParseFromString(data)
            for i, value in enumerate(register_interface.result[: int(count)]):
                addr_offset = register_interface.address + (i * 4)
                if self.decoder: self.decoder.decode(addr_offset, value, do_print=True)
                else: print(f"0x{addr_offset:08X} 0x{value:08X}")
        except (requests.exceptions.RequestException, Exception) as e: print(f"Error during HTTP read: {e}")
    def read_single_register(self, address):
        query = urlencode({"address": address, "count": 1})
        url = f"{self.base_url}/register/read?{query}"
        try:
            response = requests.get(url, timeout=5); response.raise_for_status()
            data = response.content; register_interface = register_pb2.RegisterInterface()
            register_interface.ParseFromString(data)
            if register_interface.result: return register_interface.result[0]
        except (requests.exceptions.RequestException, Exception) as e:
            logging.error(f"HTTP read failed for {address}: {e}")
        return None
    def write(self, address, payload_ints):
        count = len(payload_ints)
        register_interface = register_pb2.RegisterInterface(address=int(address, 16), count=count, payload=payload_ints + [0] * (64-count), operation=register_pb2.RegisterOperation.RO_WRITE)
        url = f"{self.base_url}/register/write"
        try:
            response = requests.post(url, data=register_interface.SerializeToString(), headers={"Content-Type": "application/octet-stream"}, timeout=10)
            response.raise_for_status()
        except requests.exceptions.RequestException as e: print(f"Error sending HTTP write request: {e}", file=sys.stderr); raise

class CommandParsing:
    pattern = r"^\s*([RW])\s+([0-9A-Fa-f]+)\s+(.*)$"
    def __init__(self, ip=None, decoder=None):
        self.ip = ip if ip.startswith("http") else f"http://{ip}"
        self.reg_interface = ReadRegisterInterface(self.ip, decoder=decoder)
    def parse(self, lines):
        for command_line in parse_file_commands(lines):
            if command_line.startswith("D "):
                try:
                    milliseconds = int(command_line.split()[1]); time.sleep(milliseconds / 1000.0)
                    print(f">> Delaying for {milliseconds} milliseconds...")
                except (ValueError, IndexError): print(f"Error: Invalid delay format: '{command_line}'.")
                continue
            match = re.match(self.pattern, command_line)
            if match:
                operation, address, payload_str = match.groups()
                if operation == "R":
                    self.reg_interface.read(address, int(payload_str.strip()) // 4)
                    print()
                elif operation == "W":
                    payload_parts = payload_str.strip().split()
                    if not payload_parts: print(f"Error: Write command has no payload: '{command_line}'"); continue
                    try:
                        payload = []
                        if len(payload_parts[0]) == 8:
                            for word_string in payload_parts: payload.append(int(word_string, 16))
                        elif len(payload_parts[0]) == 2:
                            if len(payload_parts) % 4 != 0: raise ValueError(f"Byte count must be a multiple of 4. Got {len(payload_parts)}.")
                            for i in range(0, len(payload_parts), 4):
                                payload.append(int("".join(payload_parts[i : i + 4]), 16))
                        else: raise ValueError("Payload must be space-separated 8-char words OR 2-char bytes.")
                        if self.reg_interface.decoder:
                            base_addr_int = int(address, 16)
                            for i, word in enumerate(payload): self.reg_interface.decoder.decode(base_addr_int + (i * 4), word, do_print=True)
                        else: print(f"Writing: address={address}, values=[{', '.join([f'0x{v:08X}' for v in payload])}]")
                        self.reg_interface.write(address, payload)
                    except ValueError as e: print(f"Error processing write command: '{command_line}'\n  -> {e}")
                    print()
            else: print(f"Skipping non-matching command: '{command_line}'")

class MCSRecord:
    def __init__(self, line: str):
        if not line.startswith(':'): raise ValueError("Invalid record format")
        self.byte_count = int(line[1:3], 16)
        self.address = int(line[3:7], 16)
        self.record_type = int(line[7:9], 16)
        self.data = [int(line[i:i + 2], 16) for i in range(9, 9 + self.byte_count * 2, 2)]
    def is_data(self): return self.record_type == 0x00
    def is_eof(self): return self.record_type == 0x01
    def is_ext_addr(self): return self.record_type == 0x04

class FirmwareBlock:
    def __init__(self, address: int, data: list[int]):
        self.address, self.data = address, data
    def to_bytes(self) -> bytes: return bytearray(self.data)

class MCSParser:
    def __init__(self, filepath: str): self.filepath, self.blocks = filepath, []
    def parse(self):
        ext_addr = 0
        with open(self.filepath, 'r') as file:
            for line in file:
                record = MCSRecord(line.strip())
                if record.is_ext_addr(): ext_addr = (record.data[0] << 8) | record.data[1]
                elif record.is_data(): self.blocks.append(FirmwareBlock((ext_addr << 16) | record.address, record.data))
                elif record.is_eof(): break
        return self.blocks

class FwUpdateCommunicator(ABC):
    @abstractmethod
    def write_register(self, addr: int, values: bytes): pass
    @abstractmethod
    def read_register(self, addr: int) -> bytes: pass
    def close(self): pass

class SerialFwUpdateCommunicator(FwUpdateCommunicator):
    def __init__(self, port: str, baudrate: int):
        self.sender = SerialCommandSender(port, baudrate, timeout=0.1)
    def write_register(self, addr: int, values: bytes):
        self.sender.send_command(f"W {addr:08X} {' '.join(f'{b:02X}' for b in values)}", silent=True)
    def read_register(self, addr: int) -> bytes:
        response = self.sender.send_command(f"R {addr:08X} 4", silent=True)
        try:
            data_line = response.split(':')[-1]
            return bytes(int(h, 16) for h in re.findall(r'[0-9a-fA-F]{2}', data_line))
        except (ValueError, IndexError): logging.warning(f"Failed to parse serial read: {response}"); return None
    def close(self): self.sender.close()

class HttpFwUpdateCommunicator(FwUpdateCommunicator):
    def __init__(self, ip_address: str):
        self.reg_interface = ReadRegisterInterface(ip_address if ip_address.startswith("http") else f"http://{ip_address}")
    def write_register(self, addr: int, values: bytes):
        if len(values) % 4 != 0: values += b'\x00' * (4 - len(values) % 4)
        payload_ints = [struct.unpack('>I', values[i:i+4])[0] for i in range(0, len(values), 4)]
        self.reg_interface.write(f"{addr:08X}", payload_ints)
    def read_register(self, addr: int) -> bytes:
        result_int = self.reg_interface.read_single_register(f"{addr:08X}")
        return struct.pack('>I', result_int) if result_int is not None else None

class DeviceConnection:
    device_offsets = {'LV': 0x800, 'MV1': 0xA00, 'MV2': 0xC00}
    def __init__(self, connection: dict):
        self.connection = connection
        link, device = connection['link'], connection['device']
        base_offset = self.device_offsets['LV']
        self.lv_device_memory_offset = (link - 1) * 0x800 + base_offset
        if device == 'LV': self.device_memory_offset = self.lv_device_memory_offset
        elif device == 'MV1': self.device_memory_offset = self.lv_device_memory_offset + 0x200
        elif device == 'MV2': self.device_memory_offset = self.lv_device_memory_offset + 0x400
        else: raise ValueError(f"Unknown device type: {device}")
    def config_device_link(self, comm: FwUpdateCommunicator):
        reg_base, reg_end_address = 0xA0000000, 0x5B
        reg_link = (self.connection['link'] - 1) * 4 + reg_base
        val_to_write = ((0x01 << 24) | (0xA0 << 16) | (reg_end_address << 8) | 0x00).to_bytes(4, 'big')
        comm.write_register(reg_link, val_to_write)
        reg_dev_link = 0x104
        for idx in range(len(self.device_offsets)):
            addr = self.lv_device_memory_offset + idx * 0x200 + reg_base + reg_dev_link
            comm.write_register(addr, val_to_write)

class SPIController:
    BASE_REGISTERS = {'REG_COMMIT_ID': 0xA00080AC, 'REG_FPGA_REV': 0xA00080A8, 'REG_STATUS': 0xA0008144, 'REG_CTL': 0xA0000144, 'REG_R_DATA': 0xA0008148, 'REG_WR_DATA_0': 0xA0000148}
    def __init__(self, comm: FwUpdateCommunicator, connection: DeviceConnection):
        self.comm, self.connection = comm, connection
        for name, base_addr in self.BASE_REGISTERS.items():
            setattr(self, name, base_addr + connection.device_memory_offset)
    def read_register(self, addr): return self.comm.read_register(addr)
    def write_register(self, addr, values):
        self.comm.write_register(addr, struct.pack('>I', values) if isinstance(values, int) else values)

class FlashMemory:
    WIP_BIT, WEL_BIT = 0, 1
    def __init__(self, spi_controller: SPIController):
        self.spi = spi_controller; self.seq_num = self.read_seq_num()
    def update_seq_num(self): self.seq_num = (self.seq_num + 1) % 256; return self.seq_num
    def wait_for_seq_num(self):
        while self.read_seq_num() != self.seq_num: time.sleep(0.001)
    def update_data_len(self, length): self.spi.write_register(self.spi.REG_CTL, (length << 8) | self.update_seq_num())
    def read_seq_num(self):
        response = self.spi.read_register(self.spi.REG_STATUS)
        return response[3] if response and len(response) >= 4 else 0
    def read_id(self):
        self.spi.write_register(self.spi.REG_WR_DATA_0, 0x9F000000); self.update_data_len(4)
        response = self.spi.read_register(self.spi.REG_R_DATA)
        if response is None: return "Read Failed"
        return f"Man. ID: {hex(response[1])}, Mem. Type: {hex(response[2])}, Capacity: {hex(response[3])}"
    def read_status(self):
        self.spi.write_register(self.spi.REG_WR_DATA_0, 0x05000000); self.update_data_len(2); self.wait_for_seq_num()
        response = self.spi.read_register(self.spi.REG_R_DATA)
        return response[3] if response and len(response) >= 4 else None
    def write_enable(self):
        while not (self.read_status() == (1 << self.WEL_BIT)):
            self.spi.write_register(self.spi.REG_WR_DATA_0, 0x06000000); self.update_data_len(1); time.sleep(0.001)
    def erase_sector(self, address):
        address &= 0x00FFFFFF; logging.info(f"Sector Erase: addr={hex(address)}"); self.write_enable()
        self.spi.write_register(self.spi.REG_WR_DATA_0, (0x20 << 24) | address); self.update_data_len(4)
    def page_program(self, address: int, data: bytes):
        address &= 0x00FFFFFF; logging.info(f"Page program: addr={hex(address)}"); self.write_enable()
        full_payload = ((0x02 << 24) | address).to_bytes(4, 'big') + data
        self.spi.write_register(self.spi.REG_WR_DATA_0, full_payload); self.update_data_len(len(full_payload))
    def wait_WIP(self):
        logging.info("Wait WIP")
        delay = 0.01 if isinstance(self.spi.comm, HttpFwUpdateCommunicator) else 0.005
        while self.read_status() & (1 << self.WIP_BIT): time.sleep(delay)

class FirmwareTransmitter:
    def __init__(self, comm: FwUpdateCommunicator, connection: DeviceConnection):
        self.connection = connection; self.connection.config_device_link(comm)
        self.spi = SPIController(comm, connection); self.flash = FlashMemory(self.spi)
    def erase_memory(self, addr_begin, addr_end):
        print(f"Erasing memory from 0x{addr_begin:08X} to 0x{addr_end:08X}...")
        for addr in range(addr_begin, addr_end + 1, 0x1000):
            self.flash.erase_sector(addr); self.flash.wait_WIP()
        print("Erase complete.")
    def transmit(self, blocks: list[FirmwareBlock]):
        print("Transmitting firmware...")
        if not blocks: return
        total_blocks = len(blocks)
        for i in range(0, total_blocks, 2):
            chunk = blocks[i:i + 2]
            combined_data = b''.join(b.to_bytes() for b in chunk)
            self.flash.page_program(chunk[0].address, combined_data); self.flash.wait_WIP()
            progress = (i + 2) / total_blocks
            print(f"  Progress: {min(progress, 1.0):.1%}", end='\r')
        print("\nTransmission complete.")

def get_ip_config(device_identifier, config_file="devices.json"):
    if os.path.exists(config_file):
        try:
            with open(config_file, "r") as f: devices = json.load(f)
            if device_identifier in devices:
                device_info = devices[device_identifier]
                return f"{device_info['ip']}:{device_info['port']}"
        except (json.JSONDecodeError, KeyError) as e:
            raise ValueError(f"Error reading or parsing {config_file}: {e}")
    return device_identifier

def setup_decoder(args):
    decoder = None
    if args.parse:
        if not DECODER_AVAILABLE:
            print("\nWARNING: Parsing is disabled because 'parse_register.py' could not be imported.\n")
        else:
            print("INFO: Parsing is enabled.")
            search_dir = args.dir
            mc_file = (os.path.join(search_dir, f"QBgMap_MC_{args.mc_version}.csv") if args.mc_version else find_latest_file("QBgMap_MC_", search_dir))
            lc_file = (os.path.join(search_dir, f"QBgMap_LC_{args.lc_version}.csv") if args.lc_version else find_latest_file("QBgMap_LC_", search_dir))
            if not mc_file or not lc_file:
                print("\nWARNING: Parsing is disabled. Could not find required MC/LC register map files.\n")
            else:
                decoder = RegisterDecoder(mc_file_path=mc_file, lc_file_path=lc_file)
                decoder.mc_file, decoder.lc_file = mc_file, lc_file
    else:
        print("INFO: Parsing is disabled by user.")
    print()
    return decoder


# ==============================================================================
# Main Execution Logic
# ==============================================================================
def main():
    invocation_cmd = os.path.basename(sys.executable) if getattr(sys, 'frozen', False) else f"python {os.path.basename(sys.argv[0])}"

    parser = argparse.ArgumentParser(
        description="A versatile tool for device communication, firmware updates, and log decoding. The mode is determined by the arguments provided.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=f"""
Examples:
  # Run commands over HTTP from a file
  {invocation_cmd} my_commands.txt --ip mc-51

  # Run commands over Serial from a file
  {invocation_cmd} my_commands.txt --port COM3

  # Decode a local log file
  {invocation_cmd} --file captured_data.log

  # Update firmware over Serial
  {invocation_cmd} --mcs fw.mcs --port COM9 --link 1 --device LV

  # Update firmware over HTTP
  {invocation_cmd} --mcs fw.mcs --ip mc-51 --link 1 --device LV
"""
    )

    # Positional argument for command file
    parser.add_argument("command_file", nargs="?", help="Path to the command file to execute (for http/serial modes).")
    
    # Mode-defining arguments
    mode_group = parser.add_argument_group('Mode Selection (choose one)')
    mode_group.add_argument("--ip", help="Use HTTP mode or specify HTTP transport for fw-update.")
    mode_group.add_argument("--port", help="Use Serial mode or specify Serial transport for fw-update.")
    mode_group.add_argument("--file", help="Use decode-only mode.")
    mode_group.add_argument("--mcs", help="Use firmware update mode.")

    # Firmware update specific arguments
    fw_group = parser.add_argument_group('Firmware Update Arguments (used with --mcs)')
    fw_group.add_argument("--link", type=int, choices=range(1, 13), help="Link number (1-12) for fw-update.")
    fw_group.add_argument("--device", choices=['LV', 'MV1', 'MV2'], help="Target device type for fw-update.")
    fw_group.add_argument('--baudrate', type=int, default=921600, help='Baud rate for serial communication.')

    # Ancillary arguments for parsing
    parse_group = parser.add_argument_group('Parsing Control (for http, serial, decode modes)')
    parse_group.add_argument("--no-parse", dest="parse", action="store_false", help="Disable register value parsing.")
    parse_group.add_argument("--dir", default="./register_maps/", help="Directory for register map files.")
    parse_group.add_argument("--mc-version", help="Specify an exact MC version (e.g., '0.8.0').")
    parse_group.add_argument("--lc-version", help="Specify an exact LC version (e.g., '0.11.0').")
    parser.set_defaults(parse=True)
    
    args = parser.parse_args()

    # --- Mode Detection and Validation ---
    mode = None
    if args.mcs:
        mode = 'fw-update'
        if not (args.link and args.device):
            parser.error("--mcs mode requires --link and --device arguments.")
        if not (args.port or args.ip):
            parser.error("--mcs mode requires a transport argument: --port or --ip.")
        if args.port and args.ip:
            parser.error("For --mcs mode, specify either --port or --ip, not both.")
        if args.command_file:
            parser.error("--mcs mode cannot be used with a command_file.")
    elif args.file:
        mode = 'decode'
        if any([args.ip, args.port, args.command_file, args.link, args.device, args.mcs]):
            parser.error("--file mode cannot be used with other mode-defining or command arguments.")
    elif args.port:
        mode = 'serial'
        if not args.command_file:
            parser.error("--port mode requires a command_file argument.")
    elif args.ip:
        mode = 'http'
        if not args.command_file:
            parser.error("--ip mode requires a command_file argument.")
    
    if not mode:
        parser.error("No mode selected. Please specify one of --mcs, --file, --port, or --ip.")

    print(f"BitWise - v1.3 (Simplified CLI)")

    # --- Mode Execution ---
    if mode == 'fw-update':
        transport_mode = 'Serial' if args.port else 'HTTP'
        print(f"Running in FIRMWARE-UPDATE mode via {transport_mode}")
        start_time = datetime.now()
        log_filename = start_time.strftime(f"fw_update_L{args.link}_{args.device}_%Y%m%d_%H%M%S.log")
        logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', force=True)
        print(f"Logging to {log_filename}")

        communicator = None
        try:
            if args.port:
                communicator = SerialFwUpdateCommunicator(args.port, args.baudrate)
            else: # args.ip must be present due to validation
                ip_address = get_ip_config(args.ip)
                communicator = HttpFwUpdateCommunicator(ip_address)
            
            blocks = MCSParser(args.mcs).parse()
            if not blocks: sys.exit(f"Error: No data blocks found in {args.mcs}.")
            print(f"Parsed {len(blocks)} firmware blocks.")

            connection = DeviceConnection({'link': args.link, 'device': args.device})
            transmitter = FirmwareTransmitter(communicator, connection)
            print("Device connection configured. Flash ID: " + str(transmitter.flash.read_id()))
            
            transmitter.erase_memory(blocks[0].address, blocks[-1].address)
            transmitter.transmit(blocks)
        except Exception as e:
            print(f"\nAn error occurred during firmware update: {e}", file=sys.stderr)
            logging.error("Firmware update failed.", exc_info=True)
        finally:
            if communicator: communicator.close()
        print(f"Firmware update finished. Total time: {datetime.now() - start_time}")

    elif mode == 'serial':
        print(f"Running in SERIAL mode (File: {args.command_file}, Port: {args.port})")
        decoder = setup_decoder(args)
        sender = None
        try:
            sender = SerialCommandSender(args.port, args.baudrate, decoder=decoder)
            if decoder and hasattr(decoder, 'mc_file'):
                perform_version_check(sender, decoder.mc_file, decoder.lc_file)
            sender.process_file(args.command_file)
        except Exception as e:
            print(f"An error occurred during serial execution: {e}")
        finally:
            if sender: sender.close()
        print("Serial mode finished.")

    elif mode == 'http':
        try:
            ip_address = get_ip_config(args.ip)
        except ValueError as e:
            parser.error(f"IP Configuration Error: {e}")
        print(f"Running in HTTP mode (File: {args.command_file}, Target: {ip_address})")
        decoder = setup_decoder(args)
        try:
            with open(args.command_file, "r") as f: lines = f.readlines()
            parser_obj = CommandParsing(ip=ip_address, decoder=decoder)
            if decoder and hasattr(decoder, 'mc_file'):
                perform_version_check(parser_obj.reg_interface, decoder.mc_file, decoder.lc_file)
            parser_obj.parse(lines)
        except Exception as e:
            print(f"An error occurred during HTTP execution: {e}")
        print("HTTP mode finished.")

    elif mode == 'decode':
        print(f"Running in DECODE-ONLY mode (Input File: {args.file})")
        args.parse = True # Force parsing on
        decoder = setup_decoder(args)
        if not decoder: sys.exit("Error: Decoder initialization failed, cannot proceed.")
        line_pattern = re.compile(r"^(0x[0-9a-fA-F]+)[\s:]+(0x[0-9a-fA-F]+)")
        try:
            with open(args.file, "r") as f:
                for line in f:
                    match = line_pattern.match(line.strip())
                    if match: decoder.decode(match.group(1), match.group(2), do_print=True)
        except FileNotFoundError:
            sys.exit(f"Error: Input file not found: {args.file}")
        print("Decode-only mode finished.")


if __name__ == "__main__":
    main()