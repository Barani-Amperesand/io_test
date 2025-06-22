# IO Tool: Serial & HTTP Command Sender (`io_test.py`)

## 1. Overview

This script is a versatile command-line utility for interacting with hardware devices. It provides two primary modes of operation:

1.  **HTTP Mode:** Sends structured Read/Write commands to a device's REST API endpoint. This mode uses pre-compiled Protocol Buffer (Protobuf) files for reliable data communication.
2.  **Serial Mode:** Sends general-purpose string commands to a device over a standard serial (COM) port.

The script reads commands from a text file, allowing for complex, repeatable, and automated testing or configuration sequences. It supports advanced scripting features like loops, delays, and comments.

## 2. Key Features

*   **Dual-Mode Operation:** Seamlessly switch between HTTP and Serial communication.
*   **Command File Processing:** Execute a series of commands from an input text file.
*   **Looping Construct:** Use `LOOP <count> ... LOOP END` to repeat a block of commands.
*   **HTTP-Specific Delays:** Use `D <milliseconds>` to pause execution, perfect for waiting for hardware operations to complete.
*   **Rich Commenting:** Supports both full-line (`#`) and in-line comments for well-documented command files.
*   **Intelligent HTTP Write Payloads:** Accepts data in multiple convenient formats (e.g., space-separated bytes or full 32-bit words).
*   **Robust Command-Line Interface:** Uses clear and flexible arguments to control script execution.
*   **Simplified Setup:** Comes with all necessary Protobuf definitions, requiring no compilation by the user.

## 3. Setup

### 3.1. Prerequisites

*   Python 3.6+ and `pip`.

### 3.2. File Structure

To run the script, ensure all the required files are located in the **same directory**. The pre-compiled Protobuf files (`_pb2.py`) must be present alongside the main script.

Your directory should look like this:

```
your_project/
├── io_test.py                # The main script
├── memory_pb2.py             # Required Protobuf file
├── register_pb2.py           # Required Protobuf file
├── nanopb_pb2.py             # Required Protobuf file
└── control_inputs_pb2.py     # Required Protobuf file
# ... and any other necessary _pb2.py files
```

### 3.3. Install Python Libraries

Install the required Python packages using a single `pip` command:

```bash
pip install requests pyserial protobuf
```

Your script is now ready to run.

## 4. How to Run the Script

The script is controlled via command-line arguments from your terminal.

### 4.1. General Syntax

```bash
python io_test.py [filename] [--mode MODE] [--ip IP_ADDRESS] [--port COM_PORT]
```

### 4.2. Arguments

*   `filename` (Positional, Required): The path to the command file you want to execute.
*   `--mode` (Optional): The execution mode.
    *   `http` (Default): For Read/Write commands over REST.
    *   `serial`: For general string commands over a COM port.
*   `--ip` (Optional): The IP address and port for HTTP mode. (Default: `192.168.0.59:7124`)
*   `--port` (Optional): The COM port for serial mode (e.g., `COM3` on Windows, `/dev/ttyUSB0` on Linux). (Default: `COM3`)

### 4.3. Usage Examples

**HTTP Mode (Default)**

```bash
# Run with a command file, using the default IP address
python io_test.py commands.txt

# Run with a specific IP address
python io_test.py commands.txt --ip 10.0.0.50:8000
```

**Serial Mode**

```bash
# Run in serial mode, using the default COM port
python io_test.py serial_commands.txt --mode serial

# Run in serial mode with a specific COM port
python io_test.py serial_commands.txt --mode serial --port COM5
```

## 5. Command File Syntax

Create a `.txt` file with one command per line.

### 5.1. Comments

Use the `#` symbol for comments. They can be on their own line or at the end of a command line.

```
# This is a full-line comment
W A000091C 00000010   # This is an in-line comment
```

### 5.2. HTTP Read (`R`)

Reads one or more 32-bit registers.

*   **Syntax:** `R <address_hex> <count_decimal>`
*   **Example:**
    ```
    # Read 4 registers starting from address A00088F0
    R A00088F0 4
    ```

### 5.3. HTTP Write (`W`)

Writes one or more 32-bit values. The payload can be specified in two formats.

*   **Syntax 1: Space-separated Bytes**
    The number of bytes must be a multiple of 4.

    ```
    # Write one word (0x01020304) to address 60000000
    W 60000000 01 02 03 04

    # Write two words (0xAABBCCDD and 0xDEADBEEF) to 60000004
    W 60000004 AA BB CC DD DE AD BE EF
    ```

*   **Syntax 2: Space-separated Words**
    Each part of the payload must be a full 8-character hex string.

    ```
    # Write one word
    W 60000008 05060708

    # Write two words
    W 6000000C AABBCCDD DEADBEEF
    ```

### 5.4. Delay (`D`)

Pauses the execution of the script for a specified duration. 

*   **Syntax:** `D <milliseconds>`
*   **Example:**
    ```
    # Wait for 5 seconds
    D 5000

    # Wait for 100 milliseconds
    D 100
    ```

### 5.5. Loop (`LOOP`)

Repeats a block of commands a specified number of times. Loops can contain any other valid commands.

*   **Syntax:**
    ```
    LOOP <count_decimal>
      ... commands to repeat ...
    LOOP END
    ```
*   **Example:**
    ```
    # Toggle a pin 5 times with a delay
    LOOP 5
      W A0000000 00000001  # Set pin high
      D 500                 # Wait 500ms
      W A0000000 00000000  # Set pin low
      D 500                 # Wait 500ms
    LOOP END
    ```

### 5.6. Serial Commands

In `serial` mode, any line that is not a comment is treated as a string command to be sent to the device. Spaces are automatically converted to hyphens (`-`).

*   **Example `serial_commands.txt`:**
    ```
    # Check version
    V

    # Set some parameter
    set-parameter-A 100
    ```

## 6. Troubleshooting

*   **`ModuleNotFoundError: No module named '..._pb2'`**: The required Protobuf file (e.g., `memory_pb2.py`) is missing from the directory. Ensure all necessary `_pb2.py` files are in the same folder as `io_test.py`.
*   **`serial.SerialException: could not open port ...`**: The COM port is incorrect, already in use by another application, or you do not have permission to access it.
*   **`requests.exceptions.ConnectionError`**: The script cannot connect to the specified IP address. Check that the device is on the network, the IP is correct, and there are no firewall issues.