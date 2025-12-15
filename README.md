# DNS Test Script

## Overview

This Python script is a command-line utility for testing and validating domain lists, commonly used with DNS-based ad-blockers like Pi-hole or AdGuard. It can fetch domain lists from local files or remote URLs, validate their format, and perform DNS resolution and ICMP ping tests.

## Features

- **Multiple Domain List Sources**: Load domains from a local file (`-i`), a single remote URL (`-u`), or a file containing a list of URLs (`--list`).
- **File Validation**: Check the syntax of domain lists (`--check`), with an option for detailed statistics (`--check stat`). It supports common formats like `0.0.0.0 example.com` and `example.com`.
- **DNS Resolution Tests**: Quickly check which domains can be resolved to an IP address (`-d`). It correctly interprets `0.0.0.0` as a blocked domain by default.
- **Ping Tests**: Perform a specified number of ICMP pings (`-p <n>`) to each resolved domain and report the average response time.
- **Rate Limiting**: Control the query rate to avoid overwhelming DNS servers or triggering anti-abuse mechanisms (`--rate <x>[s/m]`).
- **Flexible Output**: 
    - Display results live on the console (`--live`).
    - Write results to a log file (`-w <filename>`).
    - Suppress console output for background operations (`-b`, `--batch`).
    - Enhanced readability with optional color-coded output (`--color`).

## Dependencies

- **Python 3.x**
- **requests**: For fetching domain lists from URLs.
- **colorama** (optional): For colored terminal output on Windows.

You can install the required Python libraries using pip:

```bash
pip install requests colorama
```

## Usage

The script is controlled via command-line arguments. You must provide one source option and at least one action option.

### Syntax

```
python dnstest.py <Source> [Action] [Options]
```

### Source Options (Choose one)

| Option | Argument | Description |
|---|---|---|
| `-i` | `<filename>` | Load domains from a local file. |
| `-u` | `<url>` | Load domains from a remote URL. |
| `--list` | `<filename>` | Load a file containing multiple URLs to domain lists. |

### Action Options

| Option | Argument | Description |
|---|---|---|
| `--check` | `[stat]` | Validate the structure of the domain list. Use `stat` for a detailed report. |
| `-d` | | Perform only DNS resolution tests. |
| `-p` | `<n>` | Perform `n` ping attempts for each resolved domain. |

### Global Options

| Option | Description |
|---|---|
| `-w <file>` | Write results to the specified file. |
| `--overwrite` | Overwrite the output file without prompting. |
| `-b`, `--batch` | Batch mode: suppress all console output. |
| `--live` | Show live results for each domain during ping tests. |
| `--rate <n>[s/m]` | Limit queries to `n` per second (s) or minute (m) (e.g., `10s` or `600m`). |
| `--noip` | Count `0.0.0.0` as a successful DNS resolution. |
| `--color` | Enable ANSI color-coded output. |
| `-h`, `--help` | Display a simple or detailed help message. |

### Examples

**1. Validate a local domain list and show detailed stats:**
```bash
python dnstest.py -i /path/to/your/domains.txt --check stat
```

**2. Perform DNS resolution tests on a remote list and save the output:**
```bash
python dnstest.py -u https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts -d -w dns_results.txt --color
```

**3. Ping each domain from a list 3 times, with a rate limit of 10 queries per second:**
```bash
python dnstest.py -i domains.txt -p 3 --rate 10s --live
```

**4. Process a file containing multiple URLs, running 2 pings per domain and saving all results:**
```bash
python dnstest.py --list /path/to/url_list.txt -p 2 -w combined_results.log --overwrite
```
