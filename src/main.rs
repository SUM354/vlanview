//! vlanview — list heard 802.1Q VLAN IDs on an interface without tcpdump.
//!
//! Equivalent of:
//!   sudo timeout 30 tcpdump -i eth0 -nn -e -l vlan | grep -o 'vlan [0-9]*' | sort -nu
//!
//! Method: AF_PACKET SOCK_RAW with ETH_P_ALL + PACKET_AUXDATA (handles NIC
//! VLAN offload stripping), inline 0x8100/0x88a8/0x9100 parsing for Q-in-Q.

use std::collections::HashMap;
use std::env;
use std::ffi::CString;
use std::io::{self, Write};
use std::mem;
use std::os::unix::io::RawFd;
use std::process::ExitCode;
use std::time::{Duration, Instant};

const SOL_PACKET: i32 = 263;
const PACKET_AUXDATA: i32 = 8;
// ioctl request takes c_ulong on glibc, c_int on musl
#[cfg(target_env = "musl")]
type IoctlRequest = libc::c_int;
#[cfg(not(target_env = "musl"))]
type IoctlRequest = libc::c_ulong;
const SIOCGIFFLAGS: IoctlRequest = 0x8913 as IoctlRequest;
const SIOCSIFFLAGS: IoctlRequest = 0x8914 as IoctlRequest;
const IFF_PROMISC: i16 = 0x100;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct TpacketAuxdata {
    tp_status: u32,
    tp_len: u32,
    tp_snaplen: u32,
    tp_mac: u16,
    tp_net: u16,
    tp_vlan_tci: u16,
    tp_vlan_tpid: u16,
}

fn htons(u: u16) -> u16 {
    u.to_be()
}

fn usage(prog: &str) {
    eprintln!(
        "Usage: {prog} -i <iface> [-t <secs>] [--target <ids>]... [-o <file> [--format text|json]] [--counts] [--no-promisc] [-v]\n\nList 802.1Q VLAN IDs heard on <iface> live as they appear (no tcpdump needed).\nNew VLAN IDs stream to stdout immediately; no need to wait for timeout.\n\nOptions:\n  -i, --interface <iface>  interface to listen on (required)\n  -t, --timeout <secs>     listen duration, default 30 (0 = until Ctrl-C)\n  --target <ids>           target VLAN(s) to wait for; repeatable. Accepts \"10\", \"10,20,30\", \"10-20\", \"10,20-25,30\".\n                           Exits early once all targets heard; exit 3 if timeout with targets missing.\n  -o, --output <file>      save final sorted list to file\n      --format <fmt>       text|json|auto (default auto: .json -> json, else text)\n      --counts             live-stream new VIDs to stderr, print final \"count VID\" sorted to stdout\n      --no-promisc         don't enable promiscuous mode\n  -v, --verbose            log every packet to stderr\n  -V, --version            show version and exit\n  -h, --help               show this help\n\nExamples:\n  {prog} -i ens18 -t 30\n  {prog} -i ens18 --target 10,20 --target 30-32 -t 60\n  {prog} -i ens18 -t 30 -o vlans.txt\n  {prog} -i ens18 -t 30 -o vlans.json --format json"
    );
}

fn cmsg_align(len: usize) -> usize {
    let a = std::mem::size_of::<usize>();
    (len + a - 1) & !(a - 1)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
}

struct Args {
    iface: String,
    timeout: u64,
    counts: bool,
    promisc: bool,
    verbose: bool,
    targets: Vec<u16>,
    output: Option<String>,
    format: Option<OutputFormat>,
}

/// Parse "10", "10,20", "10-20", "10,20-25,30" into sorted unique VIDs 1..=4094.
fn parse_vlan_list(s: &str) -> Result<Vec<u16>, String> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            let lo: u16 = a
                .trim()
                .parse()
                .map_err(|_| format!("invalid VLAN '{part}'"))?;
            let hi: u16 = b
                .trim()
                .parse()
                .map_err(|_| format!("invalid VLAN '{part}'"))?;
            if lo < 1 || lo > 4094 || hi < 1 || hi > 4094 || lo > hi {
                return Err(format!("invalid VLAN range '{part}' (want 1-4094, lo<=hi)"));
            }
            out.extend(lo..=hi);
        } else {
            let vid: u16 = part
                .parse()
                .map_err(|_| format!("invalid VLAN '{part}'"))?;
            if vid < 1 || vid > 4094 {
                return Err(format!("invalid VLAN '{part}' (want 1-4094)"));
            }
            out.push(vid);
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

fn parse_format_opt(s: &str) -> Result<Option<OutputFormat>, String> {
    match s.to_ascii_lowercase().as_str() {
        "text" | "txt" | "list" => Ok(Some(OutputFormat::Text)),
        "json" => Ok(Some(OutputFormat::Json)),
        "auto" => Ok(None), // sniff .json extension later
        _ => Err(format!("invalid --format '{s}' (want text|json|auto)")),
    }
}

/// Resolve effective format: explicit text/json wins, auto/None uses .json extension.
fn resolve_format(explicit: Option<OutputFormat>, path: &str) -> OutputFormat {
    if let Some(fmt) = explicit {
        return fmt;
    }
    if path.to_ascii_lowercase().ends_with(".json") {
        OutputFormat::Json
    } else {
        OutputFormat::Text
    }
}

fn parse_args() -> Result<Args, String> {
    let argv: Vec<String> = env::args().collect();
    let prog = argv.first().cloned().unwrap_or_else(|| "vlanview".into());
    if argv.len() == 1 {
        usage(&prog);
        std::process::exit(2);
    }
    let mut iface: Option<String> = None;
    let mut timeout: u64 = 30;
    let mut counts = false;
    let mut promisc = true;
    let mut verbose = false;
    let mut targets: Vec<u16> = Vec::new();
    let mut output: Option<String> = None;
    let mut format: Option<OutputFormat> = None;

    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "-i" | "--interface" => {
                i += 1;
                if i >= argv.len() {
                    return Err(format!("{prog}: -i needs an interface name"));
                }
                iface = Some(argv[i].clone());
            }
            "-t" | "--timeout" => {
                i += 1;
                if i >= argv.len() {
                    return Err(format!("{prog}: -t needs seconds"));
                }
                timeout = argv[i]
                    .parse::<u64>()
                    .map_err(|_| format!("{}: invalid timeout '{}'", prog, argv[i]))?;
            }
            "--target" | "--targets" | "-T" => {
                i += 1;
                if i >= argv.len() {
                    return Err(format!("{prog}: --target needs VLAN id(s)"));
                }
                targets.extend(parse_vlan_list(&argv[i])?);
            }
            "-o" | "--output" => {
                i += 1;
                if i >= argv.len() {
                    return Err(format!("{prog}: -o needs a file path"));
                }
                output = Some(argv[i].clone());
            }
            "--format" => {
                i += 1;
                if i >= argv.len() {
                    return Err(format!("{prog}: --format needs text|json|auto"));
                }
                format = parse_format_opt(&argv[i])?;
            }
            "--counts" => counts = true,
            "--no-promisc" => promisc = false,
            "-v" | "--verbose" => verbose = true,
            "-V" | "--version" => {
                println!("vlanview {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-h" | "--help" => {
                usage(&prog);
                std::process::exit(0);
            }
            other => return Err(format!("{prog}: unknown arg '{other}' (try --help)")),
        }
        i += 1;
    }
    let iface = iface.ok_or_else(|| format!("{prog}: missing -i <iface> (try --help)"))?;
    targets.sort_unstable();
    targets.dedup();
    // normalize "auto" marker: keep format_raw for resolve_format
    Ok(Args {
        iface,
        timeout,
        counts,
        promisc,
        verbose,
        targets,
        output,
        format,
    })
}

/// Toggle IFF_PROMISC via ioctl on an AF_INET datagram socket.
/// Returns previous flags so the caller can restore.
fn set_promisc(iface: &str, enable: bool) -> io::Result<i16> {
    unsafe {
        let fd: RawFd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        struct Guard(RawFd);
        impl Drop for Guard {
            fn drop(&mut self) {
                unsafe { libc::close(self.0) };
            }
        }
        let _g = Guard(fd);

        // struct ifreq: 16-byte name + flags + padding (40 bytes total on Linux)
        let mut ifr = [0u8; 40];
        let bytes = iface.as_bytes();
        if bytes.len() >= libc::IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name too long",
            ));
        }
        ifr[..bytes.len()].copy_from_slice(bytes);
        if libc::ioctl(fd, SIOCGIFFLAGS as IoctlRequest, ifr.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        let old_flags = i16::from_ne_bytes([ifr[16], ifr[17]]);
        let new_flags = if enable {
            old_flags | IFF_PROMISC
        } else {
            old_flags & !IFF_PROMISC
        };
        let nb = new_flags.to_ne_bytes();
        ifr[16] = nb[0];
        ifr[17] = nb[1];
        if libc::ioctl(fd, SIOCSIFFLAGS as IoctlRequest, ifr.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(old_flags)
    }
}

fn open_packet_socket(ifindex: u32) -> io::Result<RawFd> {
    unsafe {
        let fd = libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            htons(libc::ETH_P_ALL as u16) as i32,
        );
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Ask kernel for VLAN TCI in ancillary data (NICs that strip 802.1Q).
        let one: i32 = 1;
        libc::setsockopt(
            fd,
            SOL_PACKET,
            PACKET_AUXDATA,
            &one as *const i32 as *const libc::c_void,
            mem::size_of::<i32>() as libc::socklen_t,
        );

        // Short recv timeout so we can enforce the overall deadline.
        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 200_000,
        };
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            mem::size_of::<libc::timeval>() as libc::socklen_t,
        );

        let mut sll: libc::sockaddr_ll = mem::zeroed();
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = htons(libc::ETH_P_ALL as u16);
        sll.sll_ifindex = ifindex as i32;
        let ret = libc::bind(
            fd,
            &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        );
        if ret != 0 {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        Ok(fd)
    }
}

/// Extract VLAN IDs from one Ethernet frame (supports stacked 802.1Q/Q-in-Q).
/// Returns list so double-tagged frames contribute both IDs.
fn inline_vlans(frame: &[u8]) -> Vec<u16> {
    let mut out = Vec::new();
    if frame.len() < 14 {
        return out;
    }
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let mut offset = 14usize;
    for _ in 0..2 {
        if ethertype == 0x8100 || ethertype == 0x88a8 || ethertype == 0x9100 {
            if frame.len() < offset + 4 {
                break;
            }
            let tci = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
            let vid = tci & 0x0FFF;
            if vid != 0 {
                out.push(vid);
            }
            ethertype = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
            offset += 4;
        } else {
            break;
        }
    }
    out
}

/// Record a VID and stream it live on first sight.
/// Default mode: new VID -> stdout immediately (flushed).
/// --counts mode: new VID -> stderr immediately, final table goes to stdout.
fn record_vid(counts: &mut HashMap<u16, u64>, vid: u16, show_counts: bool) {
    let is_new = !counts.contains_key(&vid);
    *counts.entry(vid).or_insert(0) += 1;
    if is_new {
        if show_counts {
            eprintln!("new vlan {vid}");
        } else {
            println!("{vid}");
            let _ = io::stdout().flush();
        }
    }
}

/// True when every target VID has been heard at least once.
fn targets_met(counts: &HashMap<u16, u64>, targets: &[u16]) -> bool {
    targets.iter().all(|t| counts.contains_key(t))
}

fn listen(args: &Args) -> io::Result<HashMap<u16, u64>> {
    let cname = CString::new(args.iface.as_str()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "bad interface name")
    })?;
    let ifindex = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if ifindex == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no such interface: {}", args.iface),
        ));
    }

    let fd = open_packet_socket(ifindex)?;
    struct FdGuard(RawFd);
    impl Drop for FdGuard {
        fn drop(&mut self) {
            unsafe { libc::close(self.0) };
        }
    }
    let _fdg = FdGuard(fd);

    // Promiscuous mode (tcpdump does this by default); restore on exit.
    let old_flags: Option<i16> = if args.promisc {
        match set_promisc(&args.iface, true) {
            Ok(f) => Some(f),
            Err(e) => {
                eprintln!("vlanview: warning: cannot set promiscuous mode: {e}");
                None
            }
        }
    } else {
        None
    };
    struct PromiscGuard {
        iface: String,
        old_flags: Option<i16>,
    }
    impl Drop for PromiscGuard {
        fn drop(&mut self) {
            if let Some(old) = self.old_flags {
                unsafe {
                    let fd2 = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
                    if fd2 >= 0 {
                        let mut ifr = [0u8; 40];
                        let b = self.iface.as_bytes();
                        if b.len() < libc::IFNAMSIZ {
                            ifr[..b.len()].copy_from_slice(b);
                            // read current, restore only PROMISC bit
                            if libc::ioctl(fd2, SIOCGIFFLAGS as IoctlRequest, ifr.as_mut_ptr()) == 0
                            {
                                let cur = i16::from_ne_bytes([ifr[16], ifr[17]]);
                                let restored = if old & IFF_PROMISC != 0 {
                                    cur | IFF_PROMISC
                                } else {
                                    cur & !IFF_PROMISC
                                };
                                let nb = restored.to_ne_bytes();
                                ifr[16] = nb[0];
                                ifr[17] = nb[1];
                                libc::ioctl(fd2, SIOCSIFFLAGS as IoctlRequest, ifr.as_mut_ptr());
                            }
                        }
                        libc::close(fd2);
                    }
                }
            }
        }
    }
    let _pg = PromiscGuard {
        iface: args.iface.clone(),
        old_flags,
    };

    let deadline = if args.timeout == 0 {
        None
    } else {
        Some(Instant::now() + Duration::from_secs(args.timeout))
    };
    if args.verbose || !args.targets.is_empty() {
        match deadline {
            Some(_) => eprintln!(
                "vlanview: listening on {} for {}s (promisc={}) targets={:?} ...",
                args.iface, args.timeout, args.promisc, args.targets
            ),
            None => eprintln!(
                "vlanview: listening on {} until Ctrl-C (promisc={}) targets={:?} ...",
                args.iface, args.promisc, args.targets
            ),
        }
    }

    let mut counts: HashMap<u16, u64> = HashMap::new();

    let mut pktbuf = vec![0u8; 65536];
    let mut cbuf = vec![0u8; 256];

    loop {
        if let Some(d) = deadline {
            if Instant::now() >= d {
                break;
            }
        }
        // recvmsg with ancillary buffer for PACKET_AUXDATA.
        // cmsg_len_out holds the actual control length returned by the kernel.
        let (nread, cmsg_len_out): (isize, usize) = unsafe {
            let mut iov = libc::iovec {
                iov_base: pktbuf.as_mut_ptr() as *mut libc::c_void,
                iov_len: pktbuf.len(),
            };
            let mut hdr: libc::msghdr = mem::zeroed();
            hdr.msg_iov = &mut iov;
            hdr.msg_iovlen = 1;
            hdr.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
            hdr.msg_controllen = cbuf.len() as _;
            let n = libc::recvmsg(fd, &mut hdr as *mut libc::msghdr, 0);
            (n, hdr.msg_controllen as usize)
        };
        if nread < 0 {
            let e = io::Error::last_os_error();
            // timeout / interrupt: just re-check deadline
            if e.kind() == io::ErrorKind::WouldBlock
                || e.kind() == io::ErrorKind::TimedOut
                || e.raw_os_error() == Some(libc::EAGAIN)
                || e.raw_os_error() == Some(libc::EINTR)
            {
                continue;
            }
            return Err(e);
        }
        if nread == 0 {
            continue;
        }
        let frame = &pktbuf[..nread as usize];

        // 1) VLAN stripped by NIC offload -> tp_vlan_tci in auxdata
        let mut aux_vid: Option<u16> = None;
        unsafe {
            let mut off = 0usize;
            while off + mem::size_of::<libc::cmsghdr>() <= cmsg_len_out {
                let ch = &*(cbuf.as_ptr().add(off) as *const libc::cmsghdr);
                if ch.cmsg_len == 0 {
                    break;
                }
                if ch.cmsg_level == SOL_PACKET && ch.cmsg_type == PACKET_AUXDATA {
                    let data_ptr = cbuf.as_ptr().add(
                        off + cmsg_align(mem::size_of::<libc::cmsghdr>()),
                    )
                        as *const TpacketAuxdata;
                    let aux = *data_ptr;
                    let tci = aux.tp_vlan_tci;
                    if tci & 0x0FFF != 0 {
                        aux_vid = Some(tci & 0x0FFF);
                    }
                    break;
                }
                let next = cmsg_align(ch.cmsg_len as usize);
                if next == 0 {
                    break;
                }
                off += next;
                if off >= cbuf.len() {
                    break;
                }
            }
        }

        if let Some(vid) = aux_vid {
            record_vid(&mut counts, vid, args.counts);
            if args.verbose {
                eprintln!("vlanview: heard vlan {vid} (auxdata)");
            }
            if !args.targets.is_empty() && targets_met(&counts, &args.targets) {
                eprintln!("vlanview: all targets heard: {:?}", args.targets);
                break;
            }
            continue;
        }

        for vid in inline_vlans(frame) {
            record_vid(&mut counts, vid, args.counts);
            if args.verbose {
                eprintln!("vlanview: heard vlan {vid}");
            }
            if !args.targets.is_empty() && targets_met(&counts, &args.targets) {
                eprintln!("vlanview: all targets heard: {:?}", args.targets);
                break;
            }
        }
        if !args.targets.is_empty() && targets_met(&counts, &args.targets) {
            break;
        }
    }

    Ok(counts)
}

fn build_text_export(vids: &[u16], counts: &HashMap<u16, u64>, show_counts: bool) -> String {
    let mut s = String::new();
    for vid in vids {
        if show_counts {
            s.push_str(&format!("{} {}\n", counts.get(vid).copied().unwrap_or(0), vid));
        } else {
            s.push_str(&format!("{vid}\n"));
        }
    }
    s
}

fn build_json_export(
    iface: &str,
    vids: &[u16],
    counts: &HashMap<u16, u64>,
    targets: &[u16],
    missing: &[u16],
) -> String {
    let mut s = String::new();
    s.push_str("{\n");
    s.push_str(&format!("  \"interface\": \"{iface}\",\n"));
    s.push_str("  \"vlans\": [");
    for (n, v) in vids.iter().enumerate() {
        if n > 0 {
            s.push_str(", ");
        }
        s.push_str(&v.to_string());
    }
    s.push_str("],\n  \"counts\": {");
    for (n, v) in vids.iter().enumerate() {
        if n > 0 {
            s.push_str(", ");
        }
        s.push_str(&format!("\"{v}\": {}", counts.get(v).copied().unwrap_or(0)));
    }
    s.push_str("},\n  \"targets\": [");
    for (n, v) in targets.iter().enumerate() {
        if n > 0 {
            s.push_str(", ");
        }
        s.push_str(&v.to_string());
    }
    s.push_str("],\n  \"missing\": [");
    for (n, v) in missing.iter().enumerate() {
        if n > 0 {
            s.push_str(", ");
        }
        s.push_str(&v.to_string());
    }
    s.push_str("],\n");
    s.push_str(&format!(
        "  \"found_all_targets\": {}\n",
        if missing.is_empty() { "true" } else { "false" }
    ));
    s.push_str("}\n");
    s
}

fn write_export(path: &str, content: &str) -> io::Result<()> {
    std::fs::write(path, content)
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    match listen(&args) {
        Ok(counts) => {
            // Default mode already streamed each new VID live to stdout.
            // --counts mode streamed "new vlan X" to stderr; print final table now.
            if args.counts {
                let mut vids: Vec<u16> = counts.keys().cloned().collect();
                vids.sort_unstable();
                for vid in vids {
                    println!("{} {}", counts[&vid], vid);
                }
            }
            let mut vids: Vec<u16> = counts.keys().cloned().collect();
            vids.sort_unstable();
            let missing: Vec<u16> = args
                .targets
                .iter()
                .cloned()
                .filter(|t| !counts.contains_key(t))
                .collect();
            if !args.targets.is_empty() {
                if missing.is_empty() {
                    eprintln!("vlanview: targets found: {:?}", args.targets);
                } else {
                    eprintln!("vlanview: targets missing: {missing:?}");
                }
            }
            if let Some(path) = &args.output {
                let fmt = resolve_format(args.format, path);
                let content = match fmt {
                    OutputFormat::Text => build_text_export(&vids, &counts, args.counts),
                    OutputFormat::Json => {
                        build_json_export(&args.iface, &vids, &counts, &args.targets, &missing)
                    }
                };
                if let Err(e) = write_export(path, &content) {
                    eprintln!("vlanview: failed to write '{path}': {e}");
                    return ExitCode::from(1);
                }
                eprintln!("vlanview: wrote {} vlan(s) to {path} ({fmt:?})", vids.len());
            }
            if !missing.is_empty() {
                return ExitCode::from(3);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            if e.raw_os_error() == Some(libc::EPERM) || e.raw_os_error() == Some(libc::EACCES) {
                eprintln!(
                    "vlanview: permission denied opening raw socket on '{}': {e}\n\
                     hint: run with sudo or `sudo setcap cap_net_raw+ep $(readlink -f /proc/self/exe)`",
                    args.iface
                );
            } else {
                eprintln!("vlanview: error on '{}': {e}", args.iface);
            }
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untagged_has_no_vlan() {
        let mut f = vec![0u8; 14];
        f[12] = 0x08;
        f[13] = 0x00;
        assert!(inline_vlans(&f).is_empty());
    }

    #[test]
    fn single_tag() {
        // dst(6) src(6) 8100 tci=0x000a inner 0800
        let mut f = vec![0u8; 18];
        f[12] = 0x81;
        f[13] = 0x00;
        f[14] = 0x00;
        f[15] = 0x0a;
        f[16] = 0x08;
        f[17] = 0x00;
        assert_eq!(inline_vlans(&f), vec![10]);
    }

    #[test]
    fn double_tag_qinq() {
        let mut f = vec![0u8; 22];
        f[12] = 0x88;
        f[13] = 0xa8;
        f[14] = 0x00;
        f[15] = 0x14; // 20
        f[16] = 0x81;
        f[17] = 0x00;
        f[18] = 0x00;
        f[19] = 0x1e; // 30
        f[20] = 0x08;
        f[21] = 0x00;
        assert_eq!(inline_vlans(&f), vec![20, 30]);
    }

    #[test]
    fn vid_mask() {
        // tci with priority bits set: 0xe064 -> vid 100
        let mut f = vec![0u8; 18];
        f[12] = 0x81;
        f[13] = 0x00;
        f[14] = 0xe0;
        f[15] = 0x64;
        f[16] = 0x08;
        f[17] = 0x00;
        assert_eq!(inline_vlans(&f), vec![100]);
    }

    #[test]
    fn parse_single_and_list() {
        assert_eq!(parse_vlan_list("10").unwrap(), vec![10]);
        assert_eq!(parse_vlan_list("10,20,30").unwrap(), vec![10, 20, 30]);
        assert_eq!(parse_vlan_list(" 10 , 10 , 20 ").unwrap(), vec![10, 20]);
    }

    #[test]
    fn parse_range() {
        assert_eq!(parse_vlan_list("10-12").unwrap(), vec![10, 11, 12]);
        assert_eq!(
            parse_vlan_list("10,20-22,30").unwrap(),
            vec![10, 20, 21, 22, 30]
        );
    }

    #[test]
    fn parse_rejects_bad() {
        assert!(parse_vlan_list("0").is_err());
        assert!(parse_vlan_list("4095").is_err());
        assert!(parse_vlan_list("20-10").is_err());
        assert!(parse_vlan_list("abc").is_err());
    }

    #[test]
    fn targets_met_logic() {
        let mut m = HashMap::new();
        m.insert(10u16, 1u64);
        assert!(!targets_met(&m, &[10, 20]));
        m.insert(20u16, 2u64);
        assert!(targets_met(&m, &[10, 20]));
        assert!(targets_met(&m, &[]));
    }

    #[test]
    fn json_export_shape() {
        let mut m = HashMap::new();
        m.insert(10u16, 2u64);
        let j = build_json_export("eth0", &[10], &m, &[10, 20], &[20]);
        assert!(j.contains("\"interface\": \"eth0\""));
        assert!(j.contains("\"vlans\": [10]"));
        assert!(j.contains("\"10\": 2"));
        assert!(j.contains("\"missing\": [20]"));
        assert!(j.contains("\"found_all_targets\": false"));
    }

    #[test]
    fn text_export_counts() {
        let mut m = HashMap::new();
        m.insert(10u16, 5u64);
        assert_eq!(build_text_export(&[10], &m, false), "10\n");
        assert_eq!(build_text_export(&[10], &m, true), "5 10\n");
    }

    #[test]
    fn format_resolve() {
        assert_eq!(
            resolve_format(None, "out.json"),
            OutputFormat::Json
        );
        assert_eq!(resolve_format(None, "out.txt"), OutputFormat::Text);
        assert_eq!(
            resolve_format(Some(OutputFormat::Text), "out.json"),
            OutputFormat::Text
        );
    }
}
