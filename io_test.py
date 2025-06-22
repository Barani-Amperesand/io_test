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

def parse_file_commands(lines):
    """
    A generator that parses file lines, handles comments and LOOP constructs,
    and yields individual, clean commands.
    """
    i = 0
    while i < len(lines):
        line = lines[i].strip()

        # Skip empty lines
        if not line:
            i += 1
            continue

        # Handle comment lines (both full-line and in-line)
        comment_pos = line.find('#')
        if comment_pos != -1:
            if comment_pos == 0:
                print(">> " + line[comment_pos+1:])
            # This strips the comment from the line
            line = line[:comment_pos].strip()
            if not line:  # Skip if the line only contained a comment
                i += 1
                continue

        # Handle LOOP start
        if line.startswith('LOOP '):
            try:
                iteration_count = int(line.split()[1])
                loop_commands = []
                i += 1
                
                # Collect commands until LOOP END
                while i < len(lines):
                    loop_line = lines[i].strip()
                    # Also handle comments inside the loop block
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
                
                # Instead of executing, YIELD the commands from the expanded loop
                print(f">> Starting loop with {iteration_count} iterations")
                for iteration in range(iteration_count):
                    print(f">> Iteration {iteration + 1}/{iteration_count}")
                    for cmd in loop_commands:
                        yield cmd
                print(">> Loop completed")
            
            except (ValueError, IndexError) as e:
                print(f"Error in loop syntax: {e}")
        
        else:
            # Yield any other command line (R, W, D, etc.) as-is
            yield line
        
        i += 1
class VirtualPort:
    def __init__(self):
        self.is_open = True
        self._buffer = b''

    def write(self, data):
        print(f"Virtual write: {data!r}")
        if data.strip() == b'V':
            self._buffer += b'VirtualPort v1.0\r\n>\r\n'
        else:
            self._buffer += b'OK\r\n>\r\n'

    def read(self, size=1):
        if not self._buffer:
            return b''
        result = self._buffer[:size]
        self._buffer = self._buffer[size:]
        return result

    @property
    def in_waiting(self):
        return len(self._buffer)

    def close(self):
        self.is_open = False
        

class SerialCommandSender:
    def __init__(self, port, baudrate=115200, timeout=1):
        """Initialize serial connection."""
        if port =='COM3': # Keep virtual port for easy testing
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
                    stopbits=serial.STOPBITS_ONE
                )
            except serial.SerialException as e:
                print(f"Error opening serial port {port}: {e}")
                sys.exit(1)

    def get_response(self):
        """Wait for and collect response."""
        response = ""
        while True:
            if self.ser.in_waiting:
                char = self.ser.read().decode(errors='ignore')
                if '>' in char:  # Command prompt indicates end of response
                    break
                response += char
            time.sleep(0.0001)  # Small delay to prevent CPU hogging
        print(f"{response.strip()}\r\n")
        return response
        
    def send_command(self, command):
        """Send command and wait for response."""
        # Replace spaces with hyphens
        command = command.replace(' ', '-')
        
        # Add newline to command
        command = command + '\r\n'
        
        # Send command
        print(f"{command.strip().replace('-', ' ')}")
        self.ser.write(command.encode())
        self.get_response()

    def execute_commands(self, commands):
        """Execute a list of commands."""
        for command in commands:
            self.send_command(command)

    def process_file(self, filename):
        """Process command file by consuming from the central command generator."""
        try:
            with open(filename, 'r') as file:
                lines = file.readlines()
            # Use the generator to get each clean command
            for command in parse_file_commands(lines):
                self.send_command(command)
        except Exception as e:
            print(f"Error: {e}")

    def close(self):
        """Close serial connection."""
        if self.ser.is_open:
            self.ser.close()

class ReadRegisterInterface:
    def __init__(self, base_url):
        self.base_url = base_url #creates the base url for requests 

    def read(self, address, count):
        query = urlencode({"address": address, "count": count})  #we form the url within the function 
        url = f"{self.base_url}/register/read?{query}"
        try: #normal code to send the request 
            response = requests.get(url)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"Error sending request: {e}")
            return

        data = response.content
        message = memory_pb2.MemoryResponse()
        try:
            message.ParseFromString(data)
        except Exception as e:
            print(f"Error decoding protobuf: {e}")
            return

        for i, value in enumerate(message.register_interface.result[: int(count)]):
            addr_offset = message.register_interface.address + (i * 4)
            print(f"0x{addr_offset:08X}: 0x{value:08X}")

    def write(self, address, payload):
        #create a MemoryRequest for writing register interface value 
        count = len(payload)
        payload = payload + [0] * (64 - count)

        register_interface = register_pb2.RegisterInterface(
            handshake = 0, 
            address = int(address, 16),
            count = int(count),
            payload = payload,
            result = [],
            operation = register_pb2.RegisterOperation.RO_WRITE,
        )
        url = f"{self.base_url}/register/write"
        try:
            response = requests.post(
                url,
                data=register_interface.SerializeToString(),
                headers={"Content-Type": "application/octet-stream"},
                timeout=10
            )
            response.raise_for_status() #Raises an exception for 4xx/5xx codes
        except requests.exceptions.RequestException as e:
            print(f"Error sending request: {e}")
            return

        data = response.content
        message = memory_pb2.MemoryResponse()
        try:
            message.ParseFromString(data)
        except Exception as e:
            print(f"Error decoding protobuf: {e}")
            return

class CommandParsing:
    pattern = r"^\s*([RW])\s+([0-9A-Fa-f]+)\s+(.*)$"

    def __init__(self, ip=None): # No longer takes 'lines' here
        if not ip.startswith('http'):
            self.ip = f"http://{ip}"
        else:
            self.ip = ip
        # Create the interface object once
        self.reg_interface = ReadRegisterInterface(self.ip)

    def parse(self, lines):
        """Process commands from the generator for HTTP mode."""
        for command_line in parse_file_commands(lines):
            
            if command_line.startswith('D '):
                try:
                    milliseconds = int(command_line.split()[1])
                    seconds = milliseconds / 1000.0
                    print(f">> Delaying for {milliseconds} milliseconds...")
                    time.sleep(seconds)
                except (ValueError, IndexError):
                    print(f"Error: Invalid delay format: '{command_line}'. Expected 'D <milliseconds>'.")
                # After handling the delay, move to the next command
                continue 

            match = re.match(self.pattern, command_line)
            if match:
                operation, address, payload_str = match.groups()
                if operation == 'R':
                    # For backward compatibility, consider count given as bytes divided by 4
                    count = int(payload_str.strip()) // 4
                    print(f"Reading: address={address}, count={count}")
                    self.reg_interface.read(address, count)
                    print()
                elif operation == 'W':
                    payload_parts = payload_str.strip().split()
                    
                    if not payload_parts:
                        print(f"Error: Write command has no payload data for line: '{command_line}'")
                        continue

                    try:
                        payload = []
                        if len(payload_parts[0]) == 8:
                            if not all(len(p) == 8 for p in payload_parts):
                                raise ValueError("If using 8-char words, all must be 8 chars long.")
                            for word_string in payload_parts:
                                payload.append(int(word_string, 16))
                        elif len(payload_parts[0]) == 2:
                            if len(payload_parts) % 4 != 0:
                                raise ValueError(f"Byte count must be a multiple of 4. Got {len(payload_parts)}.")
                            for i in range(0, len(payload_parts), 4):
                                chunk = payload_parts[i:i+4]
                                full_hex_string = "".join(chunk)
                                payload.append(int(full_hex_string, 16))
                        else:
                            raise ValueError("Payload must be space-separated 8-char words OR 2-char bytes.")

                        hex_values_str = ', '.join([f"0x{v:08X}" for v in payload])
                        print(f"Writing: address={address}, values=[{hex_values_str}]")
                        self.reg_interface.write(address, payload)

                    except ValueError as e:
                        print(f"Error processing write command for line: '{command_line}'\n  -> {e}")
                        continue
                    print()
            else:
                print(f"Skipping non-matching command: '{command_line}'")

def main():
    # Setup command-line argument parsing
    parser = argparse.ArgumentParser(
        description="Send commands to a device via Serial or HTTP.",
        formatter_class=argparse.RawTextHelpFormatter # For better help text formatting
    )
    
    parser.add_argument(
        "filename", 
        help="Path to the command file to execute."
    )
    
    parser.add_argument(
        "--mode", 
        choices=['serial', 'http'], 
        default='http',
        help="Execution mode:\n"
             "'serial': for general commands sent over a COM port (supports LOOP).\n"
             "'http': for specific 'R/W address payload' commands sent over HTTP (default)."
    )

    parser.add_argument(
        "--ip", 
        default='192.168.0.59:7124', 
        help="IP address and port for HTTP mode (default: 192.168.0.59:7124)."
    )
    
    parser.add_argument(
        "--port", 
        default='COM3', 
        help="COM port for serial mode (e.g., COM3 on Windows, /dev/ttyUSB0 on Linux)."
    )

    args = parser.parse_args()

    # Check if the input file exists
    if not os.path.isfile(args.filename):
        print(f"Error: File '{args.filename}' not found.")
        sys.exit(1)

    print("IO Tool Serial & HTTP - v1.0")

    if args.mode == 'serial':
        print(f"Running in SERIAL mode (File: {args.filename}, Port: {args.port})")
        print()
        sender = None
        try:
            # Instantiate the sender with the specified port
            sender = SerialCommandSender(args.port)
            # Optional: send a version command to check connection
            sender.send_command('V')
            # Process the entire command file
            sender.process_file(args.filename)
        except Exception as e:
            print(f"An error occurred during serial execution: {e}")
        finally:
            if sender:
                sender.close()
        print("Serial mode finished.")

    elif args.mode == 'http':
        print(f"Running in HTTP mode (File: {args.filename}, IP: {args.ip})")
        print()
        try:
            with open(args.filename, 'r') as f:
                lines = f.readlines()
            # Adjust the call to match the new class structure
            parser_obj = CommandParsing(ip=args.ip)
            parser_obj.parse(lines)
        except Exception as e:
            print(f"An error occurred during HTTP execution: {e}")
        print("HTTP mode finished.")


if __name__ == "__main__":
    main()