-------------------------------------------------------------------------------
DOMAIN SCANNER AND PING UTILITY (dns_test.py)
-------------------------------------------------------------------------------

A comprehensive Python script designed for validating domain list formats, checking
DNS resolution status, and performing ICMP ping tests with advanced control features
like rate limiting and specialized IP handling. The script now provides detailed
statistics on the DNS resolvers used during testing.

--- METADATA ---

Author: Gemini AI
Email: ai@google.com
Version: 1.2.5
Date: 2025-12-15

--- PREREQUISITES ---

This script requires the following Python libraries:
1. requests
2. colorama (Highly recommended, especially for Windows, to ensure correct ANSI color rendering)
3. dnspython (Required for accurate DNS resolver detection and the --showdns feature)

Installation:
pip install requests colorama dnspython

--- INPUT FILE FORMATS ---

The script accepts lines from files or URLs in two distinct formats. Lines starting
with '#' are always treated as comments and ignored.

1. IP/Domain Format (e.g., standard hosts file):
   IP_ADDRESS SPACE DOMAIN_NAME
   Example: 0.0.0.0 malicious-ad.net

2. Domain Only Format (e.g., a simple list):
   DOMAIN_NAME
   Example: example.com

Lines that do not match either of these two formats are counted as errors.

-------------------------------------------------------------------------------
--- USAGE ---
-------------------------------------------------------------------------------

python dns_test.py <Source Option> [<Action Option>] [Global Options]

-------------------------------------------------------------------------------
1. SOURCE OPTIONS (Choose one)
-------------------------------------------------------------------------------

-i <filename>         Load the domain list from a local file.
-u <url>              Load the domain list from a remote HTTP/HTTPS URL.
--list <file>         Load a local file containing a list of URLs (one URL per line). The script processes each remote list sequentially.

-------------------------------------------------------------------------------
2. ACTION OPTIONS (Choose one, or use --check alone)
-------------------------------------------------------------------------------

-p <n>                Perform 'n' ICMP ping attempts to the resolved IP address of each valid domain. Displays average response time or "NO RESPONSE". Provides comprehensive statistics.
-d                    Check only DNS resolution (Domain Name to IP address). Provides status ("RESOLVED", "NO DNS NAME", or "BLOCKED").
--check [stat]        Only validate the structure of the loaded domain list. If the optional 'stat' argument is included (i.e., `--check stat`), a detailed report is shown (comments, valid lines, format breakdown, and errors).

-------------------------------------------------------------------------------
3. OUTPUT AND CONTROL OPTIONS
-------------------------------------------------------------------------------

-w <file>             Write the complete scanning output (live results and statistics) to the specified file.
--overwrite           Use with -w to automatically overwrite the output file if it already exists, without prompting the user.
-b, --batch           Execute the entire process in batch mode. Suppresses all console output (except critical errors) and implicitly sets --overwrite if -w is used.

--live                Used primarily with -p. Shows the result of each ping test immediately. (This behavior is implied and default for the -d DNS check).

--rate <x[s/m]>       Limit the query rate to X queries per time unit.
                      - X without suffix defaults to queries per second (e.g., 12 is 12 q/s).
                      - Use 's' for queries per second (e.g., 12s).
                      - Use 'm' for queries per minute (e.g., 720m).
                      - If rate limiting is active, the script displays the *Expected Test Duration*.

--noip                Modifies the DNS resolution counting. By default, domains resolving to '0.0.0.0' are considered BLOCKED/unresolved for utility purposes. Using this flag forces the script to count '0.0.0.0' as a successful DNS resolution.

--showdns             Display the IP address of the DNS server (resolver) that provided the resolution for each query, in a separate column.

--color               Enable ANSI color output for enhanced readability in supported terminals.

-h, --help            Display help messages (use --help for this detailed output).

--- BEHAVIOR NOTES ---

* **0.0.0.0 Handling:** By default, if the resolved IP is `0.0.0.0`, the script reports it as "BLOCKED (0.0.0.0)" and treats it as a non-successful resolution for statistics. Use `--noip` to override this.
* **Resolver Statistics:** Regardless of the action used (-p or -d), the script summarizes the usage of all DNS resolver IPs detected during the test, showing the count and percentage of queries handled by each, upon completion or interruption (Ctrl+C).
* **Dependency for Resolver IP:** The `--showdns` feature relies on the `dnspython` library for accurate resolver detection. If `dnspython` is missing, the script will fall back to showing "System Default" or an empty string.

--- EXAMPLES ---

# 1. Ping domains and show the responding DNS server IP:
python dns_test.py -i list.txt -p 4 --showdns --color

# 2. Check DNS resolution for a remote file at a rate of 30 queries per minute:
python dns_test.py -u https://example.com/domains.txt -d --rate 30m --color

# 3. Run a full ping test on a list of remote sources silently in the background:
python dns_test.py --list remote_lists.txt -p 2 -w final_report.txt --batch

-------------------------------------------------------------------------------