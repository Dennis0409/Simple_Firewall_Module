# Simple Firewall Module

## 📅 Overview

The **Simple Firewall Module** is a Linux Kernel module designed to manage basic firewall rules through user-space interactions. It allows users to **add**, **delete**, and **list** firewall rules via a custom CLI tool (`main`). This project demonstrates the integration of **Netfilter** in the Linux kernel for packet filtering and provides a simple interface for rule management through the `/proc` filesystem.

---

## 📊 Features

- **Add Firewall Rules:** Block on IP, port, and protocol.
- **Delete Rules:** Remove specific firewall rules dynamically.
- **List Rules:** Display all currently active firewall rules.
- **Supports TCP, UDP, and ICMP Protocols.**

---

## ⚙️ Compilation & Installation

### Build Instructions

```bash
make            # Compile kernel module and user-space programs
sudo insmod firewall.ko  # Insert the firewall kernel module
```

### Clean Build Files

```bash
make clean      # Clean up compiled files
```

---

## 🚀 Usage

### 1️⃣ Add a Firewall Rule

```bash
./main add <IP> <PORT> <PROTO>
```

- **IP:** Target IP address (e.g., `192.168.1.1`)
- **PORT:** Target port number (e.g., `80`)
- **PROTO:** Protocol (TCP, UDP, ICMP)

**Example:**
```bash
./main add 192.168.1.1 80 TCP
```

---

### 2️⃣ List All Rules

```bash
./main ls
```

**Example Output:**

```bash
IP: 192.168.1.1, Protocol: TCP, Port: 80
IP: 10.0.0.5, Protocol: ICMP, Port: 0
```

---

### 3️⃣ Delete a Rule

```bash
./main del <IP> <PORT> <PROTO>
```

**Example:**
```bash
./main del 192.168.1.1 80 TCP
```

---

## 👀 Debugging

View kernel logs:

```bash
dmesg | tail
```

Expected log outputs:

```bash
add rule: IP=192.168.1.1, Port=80, Protocol=TCP
Del rule: IP=192.168.1.1, Port=80, Protocol=TCP
```

---

## 🛡️ Kernel Module Details

- **Packet Filtering:** Integrated with Netfilter hooks.
- **Rule Storage:** Uses linked lists for dynamic rule management.
- **/proc Interface:** Exposes `/proc/fw_rules` for user-space interaction.


