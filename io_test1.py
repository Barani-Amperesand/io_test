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
        """Process command file and send commands."""
        try:
            with open(filename, 'r') as file:
                lines = file.readlines()
                
            i = 0
            while i < len(lines):
                line = lines[i].strip()
                
                # Skip empty lines
                if not line:
                    i += 1
                    continue
                
                # Handle comment lines
                comment_pos = line.find('#')
                if comment_pos != -1:
                    if comment_pos == 0:
                        print(">> ", line[comment_pos+1:])
                    line = line[:comment_pos].strip()
                    if not line:  # Skip if line only contained comment
                        i += 1
                        continue

                # Check for loop start
                if line.startswith('LOOP '):
                    try:
                        iteration_count = int(line.split()[1])
                        loop_commands = []
                        i += 1
                        
                        # Collect commands until LOOP END
                        while i < len(lines):
                            loop_line = lines[i].strip()
                            
                            # Handle comments in loop
                            comment_pos = loop_line.find('#')
                            if comment_pos != -1:
                                if comment_pos == 0:
                                    print(">> ", loop_line[comment_pos+1:])
                                loop_line = loop_line[:comment_pos].strip()
                                
                            if loop_line == 'LOOP END':
                                break
                            elif loop_line:  # Add non-empty lines to loop commands
                                loop_commands.append(loop_line)
                            i += 1
                            
                        if i >= len(lines):
                            raise ValueError("LOOP END not found")
                            
                        # Execute the loop
                        print(f">> Starting loop with {iteration_count} iterations")
                        for iteration in range(iteration_count):
                            print(f">> Iteration {iteration + 1}/{iteration_count}")
                            self.execute_commands(loop_commands)
                        print(">> Loop completed")
                            
                    except (ValueError, IndexError) as e:
                        print(f"Error in loop syntax: {e}")
                        
                else:
                    # Process normal command
                    self.send_command(line)
                    
                i += 1
                    
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
            return  #no sys.exit cause there might be other commands to process 

        data = response.content
        message = memory_pb2.MemoryResponse()
        try:
            message.ParseFromString(data)
        except Exception as e:
            print(f"Error decoding protobuf: {e}")
            return  #no sys.exit cause there might be other commands to process 

        for i, value in enumerate(message.register_interface.result[: int(count)]):
            print(f"Address {hex(message.register_interface.address+i*4)}: {value}")

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

   

    def validate_hex(value):
        """Validate if the value is a 32 bit hex number (8 characters)"""

        try:
            #Check if it starts with 0x or not, remove prefix if present 
            if value.startswith("0x") or value.startswith("0x"):
                value = value[2:]
            #Ensure it's 8 characters long and valid hex 
            if len(value) != 8 or not all (c in "0123456789abcdefABCDEF" for c in value):
                raise ValueError
            #Convert to int to validate it's 32 bit number 
            num = int(value, 16)
            if num < 0 or num > 0xFFFFFFFF:
                raise ValueError 
            return value 
        except ValueError:
            raise argparse.ArgumentTypeError(f"'{value}' is not a valid 32-bit hex number")
        
    def hex_to_little_endian(hex_str):
        """Convert a big-endian hex string to little-endian integer."""
        if hex_str.startswith("0x") or hex_str.startswith("0X"):
            hex_str = hex_str[2:]
        #Convert to int from big endian hex
        big_endian = int(hex_str, 16)
        #Comvert to little-endian by swapping bytes 
        little_endian = int.from_bytes(
            big_endian.to_bytes(4, byteorder="big"), byteorder="little"
        )
        return little_endian

class CommandParsing:
    pattern = r"^\s*([RW])\s+([0-9A-Fa-f]+)\s+(.*)$"

    def __init__(self, lines, ip=None):
        self.lines = lines
        if not ip.startswith('http'):
            self.ip = f"http://{ip}"
        else:
            self.ip = ip

    def parse(self):
        reg = ReadRegisterInterface(self.ip) #calling the class here 
        for line in self.lines:
            clean_line = line.strip()
            if not clean_line or clean_line.startswith('#'):
                continue

            match = re.match(self.pattern, clean_line)
            if match:
                operation, address, payload_str = match.groups()
                if operation == 'R':
                    count = int(payload_str.strip())
                    
                    print(f"Reading: base_url={self.ip}, address={address}, count={count}")
                    reg.read(address, count)
                elif operation == 'W':
                    byte_list = payload_str.strip().split()
                    little_endian_values = [ReadRegisterInterface.hex_to_little_endian(v) for v in byte_list] #from the main function
                    
                    print(f"Writing: base_url={self.ip}, address={address}, values={little_endian_values}")
                    reg.write(address, little_endian_values)
                print("-" * 20)
            else:
                print(f"Skipping non-matching command: '{clean_line}'\n" + "-"*20)

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

    if args.mode == 'serial':
        print(f"Running in SERIAL mode (File: {args.filename}, Port: {args.port})")
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
        print("Serial mode finished")

    elif args.mode == 'http':
        print(f"Running in HTTP mode (File: {args.filename}, IP: {args.ip})")
        try:
            # Read all lines from the file
            with open(args.filename, 'r') as f:
                lines = f.readlines()
            # Instantiate the parser with the lines and IP
            parser_obj = CommandParsing(lines, ip=args.ip)
            parser_obj.parse()
        except Exception as e:
            print(f"An error occurred during HTTP execution: {e}")
        print("HTTP mode finished")

if __name__ == "__main__":
    main()