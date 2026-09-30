# vlanview

List heard 802.1Q VLAN IDs on a Linux interface — without `tcpdump`.

`vlanview` listens on a trunk/monitor port via `AF_PACKET` and prints each new
VLAN ID **live** as it appears. It handles NIC VLAN offload stripping
(`PACKET_AUXDATA`) and stacked tags (Q-in-Q: `0x8100`/`0x88a8`/`0x9100`).

Current version: **0.2.0** (`vlanview --version`)

## Features

- No `tcpdump` / libpcap dependency (single static-ish binary, only `libc`)
- Live streaming of new VLAN IDs (no waiting for the timeout)
- Wait-for-targets mode: exit early once expected VLANs are heard
- Export heard VLANs to text or JSON
- Per-VLAN packet counts (`--counts`)
- Promiscuous mode on/off (on by default, restored on exit)

## Requirements

- Linux with `AF_PACKET` (any modern distro; verified on Ubuntu 22.04 and 24.04)
- `CAP_NET_RAW` — run with `sudo` or grant the capability:
  ```bash
  sudo setcap cap_net_raw+ep ./vlanview
  ```
- The interface must see tagged traffic (switch port in trunk/mirror mode)

## Install (from GitHub release)

```bash
# download the vlanview binary from the release page, then:
chmod +x vlanview
sudo ./vlanview -i ens18 -t 30
```

## Usage

```
Usage: vlanview -i <iface> [-t <secs>] [--target <ids>]... [-o <file> [--format text|json]] [--counts] [--no-promisc] [-v]

List 802.1Q VLAN IDs heard on <iface> live as they appear (no tcpdump needed).
New VLAN IDs stream to stdout immediately; no need to wait for timeout.

Options:
  -i, --interface <iface>  interface to listen on (required)
  -t, --timeout <secs>     listen duration, default 30 (0 = until Ctrl-C)
  --target <ids>           target VLAN(s) to wait for; repeatable. Accepts "10", "10,20,30", "10-20", "10,20-25,30".
                           Exits early once all targets heard; exit 3 if timeout with targets missing.
  -o, --output <file>      save final sorted list to file
      --format <fmt>       text|json|auto (default auto: .json -> json, else text)
      --counts             live-stream new VIDs to stderr, print final "count VID" sorted to stdout
      --no-promisc         don't enable promiscuous mode
  -v, --verbose            log every packet to stderr
  -V, --version            show version and exit
  -h, --help               show this help

Examples:
  vlanview -i ens18 -t 30
  vlanview -i ens18 --target 10,20 --target 30-32 -t 60
  vlanview -i ens18 -t 30 -o vlans.txt
  vlanview -i ens18 -t 30 -o vlans.json --format json
```

With no arguments, `vlanview` prints this help (exit code 2).

## Examples

```bash
# 1. List VLANs heard in 30 s (one VID per line, live)
sudo ./vlanview -i ens18 -t 30

# 2. Wait up to 60 s until VLANs 10, 20 and 30-32 are all seen
sudo ./vlanview -i ens18 --target 10,20 --target 30-32 -t 60
echo $?   # 0 = all found, 3 = timeout with missing VLANs

# 3. Save results to text / JSON
sudo ./vlanview -i ens18 -t 30 -o vlans.txt
sudo ./vlanview -i ens18 -t 30 -o vlans.json --format json

# 4. Show packet counts per VLAN
sudo ./vlanview -i ens18 -t 30 --counts

# 5. Listen until Ctrl-C, verbose per-packet log
sudo ./vlanview -i ens18 -t 0 -v
```

JSON export shape:

```json
{
  "interface": "ens18",
  "vlans": [10, 20],
  "counts": {"10": 5, "20": 2},
  "targets": [10, 20],
  "missing": [],
  "found_all_targets": true
}
```

## Exit codes

| Code | Meaning |
| ---- | ------- |
| 0 | OK (and, with `--target`, all targets heard) |
| 1 | Runtime error (bad interface, permission denied, write failed) |
| 2 | Usage error (missing/invalid arguments; also shown with no args) |
| 3 | Timeout with one or more `--target` VLANs still missing |

## Equivalent tcpdump

```bash
sudo timeout 30 tcpdump -i ens18 -nn -e -l vlan \
  | grep -o 'vlan [0-9]\+' | awk '{print $2}' | sort -nu
```

## Building from source

Prerequisites: Rust 1.85+ (edition 2024). Ubuntu 22.04 stock `apt` rustc is
older, so install via `rustup`:

```bash
# 1. Install Rust (if needed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustc --version   # should be 1.85+

# 2. Clone and build
git clone https://github.com/SUM354/vlanview.git
cd vlanview
cargo test
cargo build --release

# 3. Run it
./target/release/vlanview --version
sudo ./target/release/vlanview -i ens18 -t 30
```

The binary needs at most `GLIBC_2.34`, so a build on Ubuntu 24.04 also runs
on Ubuntu 22.04 (glibc 2.35) with no rebuild.

## How it works

- Opens an `AF_PACKET` / `SOCK_RAW` socket bound to the interface (`ETH_P_ALL`)
- Enables `PACKET_AUXDATA` so VLAN IDs stripped by NIC offload are still seen
- Parses inline `0x8100` / `0x88a8` / `0x9100` tags (up to 2 levels for Q-in-Q)
- Enables promiscuous mode like `tcpdump`, restores flags on exit
- Prints each new VID immediately (`stdout`, flushed); `--counts` prints the
  final table at the end

## License

MIT — see [LICENSE](LICENSE).
