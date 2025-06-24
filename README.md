# BitWise: Device Interaction & Register Decoding Tool (`bitwise.py`)

## 1. Overview

**BitWise** is a powerful, versatile command-line utility for interacting with hardware devices and analyzing data. It supports three primary modes of operation, determined automatically by the arguments you provide:

1.  **HTTP Mode:** Sends structured Read/Write commands to a device's REST API endpoint. This mode uses Protocol Buffers for reliable communication.
2.  **Serial Mode:** Sends string-based commands to a device over a standard serial (COM) port.
3.  **Decode Mode:** Parses and decodes local log files containing address-value pairs, providing human-readable bit-field analysis without needing a device connection.

By default, BitWise automatically parses register data for HTTP and Serial modes, providing detailed bit-field decoding on-the-fly. It reads commands from a text file, allowing for complex, repeatable, and automated testing or configuration sequences with advanced features like loops, delays, and comments.

## 2. Key Features

*   **Multi-Mode Operation:** Seamlessly use HTTP, Serial, or offline Decode modes.
*   **Automatic Mode Detection:** The script intelligently selects the mode based on your command-line flags (`--ip`, `--port`, or `--file`).
*   **Intelligent Register Parsing (Default):** Automatically decodes register values into human-readable bit-fields using Excel-based register maps. An opt-out flag (`--no-parse`) is available for raw output.
*   **Offline Log File Decoding:** Analyze captured data logs to debug issues without connecting to live hardware.
*   **Hardware Version Verification:** Compares register map versions against hardware-reported versions to prevent data misinterpretation.
*   **Command File Processing:** Execute a series of commands from an input text file.
*   **Advanced Scripting:** Use `LOOP` and `D` (delay) commands to create sophisticated test sequences.
*   **Centralized Device Configuration:** Use an optional `devices.json` file to manage connection details for multiple devices with easy-to-remember names.
*   **Flexible Write Payloads:** Accepts data in multiple formats (e.g., space-separated bytes or full 32-bit words).

## 3. Setup

### 3.1. Prerequisites

*   Python 3.6+ and `pip`.

### 3.2. File Structure

To run the script with all features, your project directory should be organized as follows. The `bitwise.py` script, `_pb2.py` files, and `parse_register.py` must be in the same directory.

```
your_project/
├── bitwise.py                # The main script
├── devices.json              # (Optional) For storing device IP addresses
│
├── parse_register.py         # Required for all parsing features
├── memory_pb2.py             # Required Protobuf file
├── register_pb2.py           # Required Protobuf file
# ... and any other necessary _pb2.py files
│
└── register_maps/            # (Recommended) A directory for map files
    ├── QBgMap_MC_0.8.0.xlsx  # Example MC register map
    └── QBgMap_LC_0.11.0.xlsx # Example LC register map
```

### 3.3. Install Python Libraries

Install the required Python packages using `pip`. `pandas` and `openpyxl` are necessary for the register parsing feature.

```bash
pip install requests pyserial protobuf pandas openpyxl
```

Your script is now ready to run.

## 4. How to Run the Script

The script is controlled via command-line arguments. The mode is chosen automatically based on the flags you provide.

### 4.1. General Syntax

```bash
# For HTTP or Serial modes
python bitwise.py <command_file> [--ip DEVICE | --port PORT] [OPTIONS]

# For Decode-only mode
python bitwise.py --file <log_file> [OPTIONS]
```

### 4.2. Arguments

*   `command_file` (Positional): The path to the command file to execute. **Required for HTTP and Serial modes.**
*   `--ip <DEVICE>`: **Enables HTTP mode.** The target device. Can be a name from `devices.json` (e.g., `mc-51`) or a raw IP address and port (e.g., `192.168.0.59:7124`).
*   `--port <PORT>`: **Enables Serial mode.** The COM port to use (e.g., `COM3` on Windows, `/dev/ttyUSB0` on Linux).
*   `--file <LOG_FILE>`: **Enables Decode mode.** The local data log file to parse.
*   `--no-parse`: (Optional) Disables the default behavior of parsing register values into bit-fields.
*   `--dir <PATH>`: (Optional) Specifies the directory to search for register map (`.xlsx`) files. (Default: current directory).
*   `--mc-version <VER>` / `--lc-version <VER>`: (Optional) Specify an exact register map version (e.g., `0.8.0`) to use, overriding the automatic "latest file" search.

### 4.3. Usage Examples

**HTTP Mode**

```bash
# Run against a device named 'mc-51' in devices.json (with default parsing)
python bitwise.py my_commands.txt --ip mc-51

# Run against a raw IP address and disable parsing
python bitwise.py my_commands.txt --ip 192.168.0.59:7124 --no-parse
```

**Serial Mode**

```bash
# Run in serial mode on COM5 (with default parsing)
python bitwise.py serial_commands.txt --port COM5
```

**Decode Mode**

```bash
# Decode a local log file. Parsing is always enabled for this mode.
python bitwise.py --file captured_data.log

# Use register maps from a specific directory
python bitwise.py --file captured_data.log --dir ./register_maps
```

## 5. Command File Syntax

Create a `.txt` file with one command per line. When parsing is enabled (the default), the output of Read/Write commands will be decoded into bit-fields.

### 5.1. Comments

Use the `#` symbol for comments.

```
# This is a full-line comment
W A000091C 00000010   # This is an in-line comment
```

### 5.2. HTTP/Serial Read (`R`)

Reads one or more 32-bit registers.

*   **Syntax:** `R <address_hex> <count_decimal>`
*   **Example:** `R A00088F0 4`

### 5.3. HTTP/Serial Write (`W`)

Writes one or more 32-bit values. The payload can be space-separated bytes (must be a multiple of 4) or full 8-character hex words.

*   **Example (Bytes):** `W 60000000 01 02 03 04`
*   **Example (Words):** `W 60000008 05060708`

### 5.4. Delay (`D`)

Pauses script execution. Useful in command files for HTTP/Serial modes.

*   **Syntax:** `D <milliseconds>`
*   **Example:** `D 500`

### 5.5. Loop (`LOOP`)

Repeats a block of commands.

*   **Syntax:** `LOOP <count>` ... `LOOP END`
*   **Example:**
    ```
    LOOP 5
      W 60000000 00000001
      D 500
      W 60000000 00000000
      D 500
    LOOP END
    ```
