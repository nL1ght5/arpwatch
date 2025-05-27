# arpwatch

A minimal user-space ARP monitoring tool for Linux.  
**arpwatch** listens for ARP reply packets on a specified network interface, prints detailed information about ARP activity, and updates neighbor (ARP) table entries via Netlink. This tool is useful for debugging network issues, monitoring for suspicious ARP activity, or learning about ARP on Linux systems.

---

## Features

- Captures and logs ARP replies on a chosen network interface in real time.
- Updates the system’s neighbor table with observed ARP replies using Netlink.
- Verbose and debug logging modes for deep diagnostics.
- Runtime toggle for debug logging via stdin.
- Minimal dependencies, runs as a single C binary.

---

## Usage

### Prerequisites

- Linux system
- Root privileges or appropriate capabilities (`CAP_NET_RAW`, `CAP_NET_ADMIN`)
- Build tools: `gcc`, `make` (if compiling from source)

### Building

Clone the repository and build:

```sh
git clone https://github.com/nL1ght5/arpwatch.git
cd arpwatch
gcc -o arpwatch main.c -lpthread -lcap
```

### Running

**Basic usage:**

```sh
sudo ./arpwatch -i <interface>
```

**Options:**

- `-i, --interface <interface>` : Network interface to listen on (required)
- `-v, --verbose` : Enable verbose output (prints detailed ARP info)
- `--debug` : Enable debug output at program startup
- `-h, --help` : Show help message and exit

**Examples:**

Listen for ARP replies on interface `eth0`:
```sh
sudo ./arpwatch -i eth0
```

Verbose mode (prints ARP sender/target addresses):
```sh
sudo ./arpwatch -i eth0 -v
```

Debug mode at startup:
```sh
sudo ./arpwatch -i eth0 --debug
```

Toggle debug output at runtime by typing into stdin:
```
debug on
debug off
```

---

## How it works

- Opens a raw packet socket on the specified interface.
- Attaches a BPF filter to capture only ARP packets.
- Parses ARP replies and prints sender/target MAC and IP addresses.
- Updates the Linux neighbor table with the observed mappings using Netlink RTM_NEWNEIGH messages.
- Logs events. Debug and verbose output can be enabled at startup or toggled at runtime.

---

## Troubleshooting

- **Permission denied / Socket errors:**  
  Run as root or grant the binary `CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities:
  ```sh
  sudo setcap cap_net_raw,cap_net_admin=eip ./arpwatch
  ```

- **Nothing happens / No ARP traffic:**  
  Ensure the interface is up and active. Use `arping` or connect/disconnect a device to trigger ARP replies.

- **Debugging at runtime:**  
  While running, type `debug on` or `debug off` and press Enter to enable or disable debug logs.

---

## License

MIT License

---

## Disclaimer

This is a security and network debugging tool. Use with caution and only on networks you are authorized to monitor.
