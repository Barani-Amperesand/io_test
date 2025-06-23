import serial
import time
import sys
import re
import argparse
from urllib.parse import urlencode
import memory_pb2
import register_pb2
import requests
import struct
import os

try:
    from parse_register import RegisterDecoder, find_latest_file
    DECODER_AVAILABLE = True
except ImportError:
    DECODER_AVAILABLE = False

def parse_file_commands(lines):
    """
    A generator that parses file lines, handles comments and LOOP constructs,
    and yields individual, clean commands.
    """
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if not line:
            i += 1
            continue
        comment_pos = line.find('#')
        if comment_pos != -1:
            if comment_pos == 0:
                print(">> " + line[comment_pos+1:])
            line = line[:comment_pos].strip()
            if not line:
                i += 1
                continue
        if line.startswith('LOOP '):
            try:
                iteration_count = int(line.split()[1])
                loop_commands = []
                i += 1
                while i < len(lines):
                    loop_line = lines[i].strip()
                    comment_pos = loop_line.find('#')
                    if comment_pos != -1:
                        if comment_pos == 0:
                            print(">> " + loop_line[comment_pos+1:])
                        loop_line = loop_line[:comment_pos].strip()
                    if loop_line == 'LOOP END':
                        break
                    elif loop_line:
                        loop_commands.append(loop_line)
                    i += 1
                if i >= len(lines) and (i == 0 or lines[i-1].strip() != 'LOOP END'):
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
        self.is_open = True
        self._buffer = b''
    def write(self, data):
        # Simulate C code output for R command
        if data.startswith(b'R-'):
            parts = data.strip().split(b'-')
            addr_str = parts[1].decode()
            count = int(parts[2])
            self._buffer += f"Reading {count} bytes from address 0x{addr_str}:\r\n".encode()
            for i in range(count):
                self._buffer += f"{0xAA+i:02X} ".encode()
                if (i + 1) % 16 == 0: self._buffer += b"\r\n"
            self._buffer += b"\r\n>\r\n"
        elif data.strip() == b'V':
            self._buffer += b'VirtualPort v1.0\r\n>\r\n'
        else:
            self._buffer += b'OK\r\n>\r\n'
    def read(self, size=1):
        if not self._buffer: return b''
        result = self._buffer[:size]; self._buffer = self._buffer[size:]; return result
    @property
    def in_waiting(self): return len(self._buffer)
    def close(self): self.is_open = False

class SerialCommandSender:
    def __init__(self, port, baudrate=115200, timeout=1, decoder=None):
        self.decoder = decoder
        if port =='COM3':
            print("Using VirtualPort for testing")
            self.ser = VirtualPort()
        else:
            try:
                self.ser = serial.Serial(port=port, baudrate=baudrate, timeout=timeout, bytesize=serial.EIGHTBITS, parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE)
            except serial.SerialException as e:
                print(f"Error opening serial port {port}: {e}"); sys.exit(1)

    def get_response(self):
        response = ""
        while True:
            if self.ser.in_waiting:
                char = self.ser.read().decode(errors='ignore')
                if '>' in char: break
                response += char
            time.sleep(0.0001)
        return response.strip()

    def send_command(self, command):
        command_to_send = command.replace(' ', '-') + '\r\n'
        print(f">> {command}")
        self.ser.write(command_to_send.encode())
        return self.get_response()

    def _parse_and_decode_read_response(self, response_text, base_address_str):
        base_addr_int = int(base_address_str, 16)
        # Find all 2-character hex strings in the response
        hex_bytes = re.findall(r'[0-9A-Fa-f]{2}', response_text)
        
        if not hex_bytes:
            print("No data found in serial response to parse.")
            return

        # Group bytes into 32-bit words
        for i in range(0, len(hex_bytes), 4):
            chunk = hex_bytes[i:i+4]
            if len(chunk) < 4: continue # Skip incomplete words
            
            # The C code prints big-endian, so we assemble it that way
            word_str = "".join(chunk)
            word_int = int(word_str, 16)
            word_addr = base_addr_int + i
            
            self.decoder.decode(word_addr, word_int, do_print=True)

    def process_file(self, filename):
        try:
            with open(filename, 'r') as file:
                lines = file.readlines()
            for command in parse_file_commands(lines):
                response = self.send_command(command)
                
                # If it's a read command and parsing is enabled, process the response
                if command.startswith('R ') and self.decoder:
                    base_address_str = command.split()[1]
                    self._parse_and_decode_read_response(response, base_address_str)
                else:
                    # Otherwise, just print the raw response
                    print(response + "\n")
        except Exception as e:
            print(f"Error during serial processing: {e}")

    def close(self):
        if self.ser.is_open: self.ser.close()

class ReadRegisterInterface:
    def __init__(self, base_url, decoder=None):
        self.base_url = base_url
        self.decoder = decoder

    def read(self, address, count):
        query = urlencode({"address": address, "count": count})
        url = f"{self.base_url}/register/read?{query}"
        try:
            response = requests.get(url)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"Error sending request: {e}"); return
        data = response.content
        message = memory_pb2.MemoryResponse()
        try:
            message.ParseFromString(data)
        except Exception as e:
            print(f"Error decoding protobuf: {e}"); return
        for i, value in enumerate(message.register_interface.result[: int(count)]):
            addr_offset = message.register_interface.address + (i * 4)
            if self.decoder:
                self.decoder.decode(addr_offset, value, do_print=True)
            else:
                print(f"0x{addr_offset:08X}: 0x{value:08X}")

    def write(self, address, payload):
        count = len(payload)
        payload = payload + [0] * (64 - count)
        register_interface = register_pb2.RegisterInterface(handshake=0, address=int(address, 16), count=int(count), payload=payload, result=[], operation=register_pb2.RegisterOperation.RO_WRITE)
        url = f"{self.base_url}/register/write"
        try:
            response = requests.post(url, data=register_interface.SerializeToString(), headers={"Content-Type": "application/octet-stream"}, timeout=10)
            response.raise_for_status()
        except requests.exceptions.RequestException as e: print(f"Error sending request: {e}"); return
        data = response.content
        message = memory_pb2.MemoryResponse()
        try: message.ParseFromString(data)
        except Exception as e: print(f"Error decoding protobuf: {e}"); return

class CommandParsing:
    pattern = r"^\s*([RW])\s+([0-9A-Fa-f]+)\s+(.*)$"

    def __init__(self, ip=None, decoder=None):
        if not ip.startswith('http'): self.ip = f"http://{ip}"
        else: self.ip = ip
        self.reg_interface = ReadRegisterInterface(self.ip, decoder=decoder)

    def parse(self, lines):
        for command_line in parse_file_commands(lines):
            if command_line.startswith('D '):
                try:
                    milliseconds = int(command_line.split()[1])
                    seconds = milliseconds / 1000.0
                    print(f">> Delaying for {milliseconds} milliseconds...")
                    time.sleep(seconds)
                except (ValueError, IndexError):
                    print(f"Error: Invalid delay format: '{command_line}'.")
                continue 
            match = re.match(self.pattern, command_line)
            if match:
                operation, address, payload_str = match.groups()
                if operation == 'R':
                    count = int(payload_str.strip()) // 4
                    print(f">> Reading: address={address}, count={count}")
                    self.reg_interface.read(address, count)
                    print()
                elif operation == 'W':
                    payload_parts = payload_str.strip().split()
                    if not payload_parts: print(f"Error: Write command has no payload: '{command_line}'"); continue
                    try:
                        payload = []
                        if len(payload_parts[0]) == 8:
                            if not all(len(p) == 8 for p in payload_parts): raise ValueError("If using 8-char words, all must be 8 chars long.")
                            for word_string in payload_parts: payload.append(int(word_string, 16))
                        elif len(payload_parts[0]) == 2:
                            if len(payload_parts) % 4 != 0: raise ValueError(f"Byte count must be a multiple of 4. Got {len(payload_parts)}.")
                            for i in range(0, len(payload_parts), 4):
                                chunk = payload_parts[i:i+4]; full_hex_string = "".join(chunk); payload.append(int(full_hex_string, 16))
                        else: raise ValueError("Payload must be space-separated 8-char words OR 2-char bytes.")
                        if self.reg_interface.decoder:
                            print(f">> Writing Parsed Payload to Base Address: {address}")
                            base_addr_int = int(address, 16)
                            for i, word in enumerate(payload):
                                word_addr = base_addr_int + (i * 4)
                                self.reg_interface.decoder.decode(word_addr, word, do_print=True)
                        else:
                            hex_values_str = ', '.join([f"0x{v:08X}" for v in payload])
                            print(f"Writing: address={address}, values=[{hex_values_str}]")
                        self.reg_interface.write(address, payload)
                    except ValueError as e: print(f"Error processing write command: '{command_line}'\n  -> {e}"); continue
                    print()
            else:
                print(f"Skipping non-matching command: '{command_line}'")

def main():
    parser = argparse.ArgumentParser(description="Send commands to a device via Serial or HTTP.", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("filename", help="Path to the command file to execute.")
    parser.add_argument("--mode", choices=['serial', 'http'], default='http', help="Execution mode (default: http).")
    parser.add_argument("--ip", default='192.168.0.59:7124', help="IP address and port for HTTP mode.")
    parser.add_argument("--port", default='COM3', help="COM port for serial mode.")
    parser.add_argument('--parse', action='store_true', help="Enable register value parsing and bit-field decoding (default: disabled).")
    parser.add_argument("--dir", default=".", help="Directory to search for register map files (default: current directory).")
    parser.add_argument("--mc-version", help="Specify an exact MC version to use (e.g., '0.8.0').")
    parser.add_argument("--lc-version", help="Specify an exact LC version to use (e.g., '0.11.0').")
    args = parser.parse_args()

    if not os.path.isfile(args.filename):
        print(f"Error: File '{args.filename}' not found."); sys.exit(1)

    print("IO Tool Serial & HTTP - v1.0")

    decoder = None
    if args.parse:
        if not DECODER_AVAILABLE:
            print("\nWARNING: Register parsing disabled because 'parse_register.py' could not be imported.\n")
        else:
            search_dir = args.dir
            mc_file = os.path.join(search_dir, f"QBgMap_MC_{args.mc_version}.xlsx") if args.mc_version else find_latest_file("QBgMap_MC_", search_dir)
            lc_file = os.path.join(search_dir, f"QBgMap_LC_{args.lc_version}.xlsx") if args.lc_version else find_latest_file("QBgMap_LC_", search_dir)
            if not mc_file or not lc_file:
                print("\nWARNING: Register parsing disabled. Could not find required MC/LC register map files.\n")
            else:
                decoder = RegisterDecoder(mc_file_path=mc_file, lc_file_path=lc_file)
    print()

    if args.mode == 'serial':
        print(f"Running in SERIAL mode (File: {args.filename}, Port: {args.port})")
        print()
        sender = None
        try:
            # Pass the decoder instance to the sender
            sender = SerialCommandSender(args.port, decoder=decoder)
            sender.send_command('V')
            sender.process_file(args.filename)
        except Exception as e: print(f"An error occurred during serial execution: {e}")
        finally:
            if sender: sender.close()
        print("Serial mode finished.")

    elif args.mode == 'http':
        print(f"Running in HTTP mode (File: {args.filename}, IP: {args.ip})")
        try:
            with open(args.filename, 'r') as f:
                lines = f.readlines()
            # Pass the decoder instance to the command parser
            parser_obj = CommandParsing(ip=args.ip, decoder=decoder)
            parser_obj.parse(lines)
        except Exception as e:
            print(f"An error occurred during HTTP execution: {e}")
        print("HTTP mode finished.")

if __name__ == "__main__":
    main()
