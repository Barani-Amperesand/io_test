# This script sends a GET request to <base_url>/signal/read?signal=<signal_name>,
# receives a protobuf message in the response (octet stream),
# decodes it using the MemoryResponse message from memory.proto,
# and prints the message in human-readable format.
#
# Requirements:
# - Python 3
# - requests library (pip install requests)
# - protobuf library (pip install protobuf)
# - memory_pb2.py generated from memory.proto using protoc

import argparse
import sys
from urllib.parse import urlencode

import memory_pb2
import register_pb2
import requests


def read_register_interface(url, count):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raises an exception for 4xx/5xx codes
    except requests.exceptions.RequestException as e:
        print(f"Error sending request: {e}")
        sys.exit(1)

    data = response.content

    message = memory_pb2.MemoryResponse()
    try:
        message.ParseFromString(data)
    except Exception as e:
        print(f"Error decoding protobuf: {e}")
        sys.exit(1)

    for i, value in enumerate(message.register_interface.result[: int(count)]):
        print(
            f"Address {hex(message.register_interface.address+i*4)}: {hex_to_big_endian(hex(value))}"
        )


def write_register_interface(url, address, payload):
    # Create a MemoryRequest for reading register interface values
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
    try:
        response = requests.post(
            url,
            data=register_interface.SerializeToString(),
            headers={"Content-Type": "application/octet-stream"},
        )
        response.raise_for_status()  # Raises an exception for 4xx/5xx codes
    except requests.exceptions.RequestException as e:
        print(f"Error sending request: {e}")
        sys.exit(1)

    data = response.content

    message = memory_pb2.MemoryResponse()
    try:
        message.ParseFromString(data)
    except Exception as e:
        print(f"Error decoding protobuf: {e}")
        sys.exit(1)


def validate_hex(value):
    """Validate if the value is a 32-bit hex number (8 characters)."""
    try:
        # Check if it starts with 0x or not, remove prefix if present
        if value.startswith("0x") or value.startswith("0X"):
            value = value[2:]
        # Ensure it's 8 characters long and valid hex
        if len(value) != 8 or not all(c in "0123456789abcdefABCDEF" for c in value):
            raise ValueError
        # Convert to int to validate it's a 32-bit number
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
    # Convert to int from big-endian hex
    big_endian = int(hex_str, 16)
    # Convert to little-endian by swapping bytes
    little_endian = int.from_bytes(
        big_endian.to_bytes(4, byteorder="big"), byteorder="little"
    )
    return little_endian


def hex_to_big_endian(hex_str):
    """Convert a little-endian hex string to big-endian integer."""
    if hex_str.startswith("0x") or hex_str.startswith("0X"):
        hex_str = hex_str[2:]
    # Convert to int from big-endian hex
    little_endian = int(hex_str, 16)
    # Convert to little-endian by swapping bytes
    big_endian = int.from_bytes(
        little_endian.to_bytes(4, byteorder="little"), byteorder="big"
    )
    return hex(big_endian)


def main():
    parser = argparse.ArgumentParser(description="Register read/write operations")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Read command parser
    read_parser = subparsers.add_parser("read", help="Read from register")
    read_parser.add_argument("base_url", help="Base URL for the operation")
    read_parser.add_argument("address", help="Register address")
    read_parser.add_argument("count", type=int, help="Number of registers to read")

    # Write command parser
    write_parser = subparsers.add_parser("write", help="Write to register")
    write_parser.add_argument("base_url", help="Base URL for the operation")
    write_parser.add_argument("address", help="Register address")
    write_parser.add_argument(
        "values",
        nargs="+",
        type=validate_hex,
        help="32-bit hex values in big-endian (e.g., 1234abcd)",
    )

    args = parser.parse_args()

    if args.command == "read":
        print(
            f"Reading: base_url={args.base_url}, address={args.address}, count={args.count}"
        )
        query = urlencode({"address": args.address, "count": args.count})
        url = f"{args.base_url}/register/read?{query}"
        read_register_interface(url, args.count)
    elif args.command == "write":
        # Convert values to little-endian integers
        little_endian_values = [hex_to_little_endian(value) for value in args.values]
        print(
            f"Writing: base_url={args.base_url}, address={args.address}, "
            f"values={little_endian_values}"
        )
        url = f"{args.base_url}/register/write"
        write_register_interface(url, args.address, little_endian_values)


if __name__ == "__main__":
    main()
