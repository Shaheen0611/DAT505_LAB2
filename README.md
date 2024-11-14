# Network Evasion Project

## Overview

This project demonstrates various network evasion techniques using Scapy to bypass detection by the Snort Intrusion Detection System (IDS). The objective is to execute and analyze attacks such as fragmented packet attacks, slow port scans, obfuscated payload injections, and ICMP tunneling to assess Snort’s detection capabilities.

## Project Structure

- **attacker**: Contains Scapy scripts for performing evasion techniques.
- **victim**: Contains a script for monitoring ICMP traffic, useful for observing covert ICMP tunneling.
- **captures**: Contains packet captures and logs showing the results of each attack. This folder also includes Snort configuration files used to detect basic attacks.

## Attacks and Evasion Techniques

### 1. Packet Fragmentation

- **Objective**: Bypass Snort by fragmenting packets in a SYN flood attack.
- **Script**: `fragment_attack.py` in the attacker folder.
- **Expected Outcome**: Snort may fail to reassemble the fragments, allowing the attack to go undetected.

### 2. Slow Port Scan (Timing-Based Evasion)

- **Objective**: Evade detection by performing a slow port scan with random delays between packets.
- **Script**: `slow_port_scan.py`.
- **Expected Outcome**: Snort's rate-based detection should miss the slow scan due to the low frequency.

### 3. Obfuscated Payload

- **Objective**: Avoid signature detection by embedding malicious payloads within benign-looking HTTP GET requests.
- **Script**: `obfuscate_payload.py`.
- **Expected Outcome**: Snort may not flag the HTTP traffic as suspicious, allowing the obfuscated payload to pass undetected.

### 4. ICMP Tunneling for Covert Communication

- **Objective**: Create a covert channel by embedding data within ICMP packets.
- **Script**: `icmp_tunnel_attack.py` (attacker) and `sniff_icmp.py` (victim) to capture ICMP payloads.
- **Expected Outcome**: Standard Snort rules typically overlook ICMP payloads, allowing the covert communication to proceed undetected.

## Snort Configuration

- **File**: `snort_rules.conf` in the captures folder.
- This configuration includes rules for detecting SYN floods, port scans, ICMP flooding, and obfuscated HTTP payloads.
- Rules have been designed to trigger alerts on high rates of SYN packets, frequent port scans, unusual ICMP payload sizes, and suspicious HTTP content.

## Logs and Evidence

- **Snort Alerts**: The `snort_alerts.log` file in the captures folder shows that many of the attacks either went undetected or triggered minimal alerts, indicating the effectiveness of these evasion techniques.
- **Packet Captures**: The `fragmented_attack_representation.csv` provides a structured view of what the fragmented attack packets would look like in a packet capture.
- **Tcpdump Outputs**: The `tcpdump_outputs` archive contains output files for each evasion technique, captured via tcpdump with the commands listed above.

## Usage

1. **Set up Snort** on the victim VM with the provided configuration file (`snort_rules.conf`).
2. **Run the attack scripts** from the attacker VM to test each evasion technique.
3. **Analyze Snort logs** to verify detection or evasion success.

## Notes

This project is for educational purposes, demonstrating the limitations of standard IDS configurations against advanced evasion techniques.
