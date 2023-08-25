## 🌐 Network Scanner Tool

The Network Scanner Tool 🛠️ is a command-line utility that enables you to perform various network scans, including ARP ping, TCP port scanning, and UDP port scanning. This tool is designed to help you unveil information about devices and their ports within a given network. 🌐🔍

https://github.com/calc1f4r/Multithreaded-Network-Scanner/assets/74751675/cc9e9f1e-90a7-4446-adba-29d30736d93c



### Introduction

The Network Scanner Tool is a versatile utility written in Python that utilizes various network scanning techniques to identify active hosts and open ports. It harnesses the power of the socket library for creating sockets, the scapy library for ARP ping, and the concurrent.futures library for multithreaded port scanning. 🚀

#### Features

- ARP Ping Scan 🌐: Discover active hosts and their corresponding MAC addresses on the network.
- TCP Port Scan 🛠️: Identify open TCP ports on a target host using multithreading for accelerated scanning.
- UDP Port Scan 🛰️: Identify open UDP ports on a target host using multithreading for swifter scanning.
- Customizable Port Range and Threads ⚙️: Tailor your scans with adjustable port ranges and thread counts

#### Installation

Clone the Repository 📂:

```bash
git clone git@github.com:calc1f4r/Multithreaded-Network-Scanner.git
cd Multithreaded-Network-Scanner
```

##### Requirements

Install Required Dependencies ⚡️:

```bash
pip install scapy
```

#### Command-line Arguments

The tool supports the following command-line arguments:

target: Target URL or IP address (required).

- `-arp`: Use this for ARP ping (optional).
- `-pT`: Perform TCP port scanning (optional).
- `-pU`: Perform UDP port scanning (optional).
- `-p` or `--ports`: Port range to scan (default: 1-65535).
- `-t` or `--threads`: Number of threads for speed (default: 100).

##### Examples

1. Perform an ARP ping scan on a specific IP address range:

```python
python network_scanner.py 192.168.1.0/24 -arp
```

2. Perform a TCP port scan on a target IP address with a custom port range and 50 threads:

```python
python network_scanner.py 192.168.1.100 -pT -p 1-100 -t 50
```

3. Perform a UDP port scan on a target IP address with a default port range and 75 threads:

```python
python network_scanner.py 10.0.0.1 -pU -t 75
```

#### Contributing

Contributions to the Network Scanner Tool are welcome! Feel free to submit issues and pull requests on the GitHub repository.
