# Network Attacks via Malicious Application (Docker Demonstration)

This research demonstrates practical network attacks performed by an **unprivileged malicious application** running on the same host as a victim, in collaboration with an **Attacker Remote Node (ARN)**.

The environment is fully containerized and simulates a controlled local network in which modern TCP and DNS defenses are bypassed using side channels and operating system behavior.

---

## Overview

Modern network protocols rely on randomness, such as TCP sequence numbers and DNS source ports, to prevent off-path attacks.

This research shows that:

- A local unprivileged application can infer security-sensitive protocol fields of connections established by other users or applications
- An ARN can use this information to inject packets
- Core assumptions behind TCP and DNS security can be broken in the scenario of off-path on-victim unprivileged application

All experiments are executed inside Docker containers in an isolated virtual LAN.

**Note:**
In this demonstration, the ARN is located **within the same LAN** as the victim, while still logically off-path, to simplify the setup.

---

## Network Topology

```text
Victim (192.0.2.10)
 ├── victim_user (unprivileged)
 └── malicious_user (unprivileged, runs malicious application)

ARN (192.0.2.49)
 → injects crafted packets
 → captures ISNs in the IP Options scenario

HTTP Server (192.0.2.123)
 → target for TCP hijacking

Recursive Resolver (192.0.2.220)

Authoritative NS (example.com)
 → container IP: 192.0.2.200
 → resolves example.com to 192.0.2.124

Authoritative NS (attacker.test)
 → container IP: 192.0.2.70
 → resolves attacker.test to 192.0.2.70
```

**Note:**
The victim container runs in `privileged` mode and mounts `/sys/fs/cgroup` to enable `systemd-resolved` inside the container, ensuring that the resolver behavior matches a standard host configuration as required for the experiments. This configuration does not grant additional privileges to the users inside the container, which remain unprivileged.

## Environment Requirements

These requirements apply to the **host machine** (not the containers).

- Ubuntu 24.04.4 LTS
- Linux Kernel 6.6.136 LTS
- Docker Engine 29.4.1
- systemd-resolved (systemd DNS stub resolver) 255

**Note:** Other versions will likely work, but correct behavior is not guaranteed.

### Kernel

If installing this kernel using the `mainline` tool:

```bash
sudo apt install mainline
sudo mainline install 6.6.136
```

After installation:

- A reboot is required
- Select kernel `6.6.136` from the boot menu

Additional notes:

- Installing a kernel requires root privileges
- Other installation methods may be used

### Install Docker

Install Docker according to the official documentation:  
https://docs.docker.com/engine/install/ubuntu/

### Configure permissions

```bash
sudo usermod -aG docker $USER
newgrp docker
chmod -R 777 ./victim ./arn
```

- The first two commands allow running Docker without `sudo`
- The `chmod` ensures proper access for bind-mounted directories between host and containers

Reboot the system (or log out and back in) for the changes to take effect.

### Assumptions

We assume default system configuration. In particular, we assume that TCP ephemeral ports are assigned in the range `32768–60999`, and that only even ports are selected when using `connect()`. This behavior matches the default configuration and is used to reduce preprocessing time.

---

## Setup

### Download

Download the repository as a ZIP archive from:

https://anonymous.4open.science/r/artifacts_32489asadads1-12321asd-323sad123-08E3

Extract the archive and enter the artifacts directory:

```bash
cd artifacts
chmod +x ./run.sh
```

### Build

```bash
sudo ./run.sh build
```

Builds the Docker images and starts all containers using `docker compose up`.

This command:

- Builds all components (images for each service)
- Creates and starts the containers defined in `docker-compose.yml` with their configured processes
- Initializes the virtual LAN environment

### Command Execution

To run the experiments, we use multiple terminals on the host machine. Each terminal represents interaction with a different entity (container and user).

To simplify running the experiments across the different containers, we provide a `run.sh` script that wraps all required Docker commands.

All commands are executed via:

```bash
sudo ./run.sh COMMAND
```

This wrapper automatically:

- Runs inside the correct container
- Uses the correct user (in the victim: `victim_user` or `malicious_user`, as required)
- Displays the active username at runtime

To see all available commands:

```bash
sudo ./run.sh help
```

---

## Attacks

---

## 1. TCP Hijacking (cBPF)

### Pre-processing

Terminal 1 (victim container, `malicious_user`):

```bash
sudo ./run.sh cbpf
```

Builds a preprocessing table:

```text
port -> ISN, timestamp
```

The malicious application uses cBPF leakage to infer ISNs and associate them with source ports and timestamps. This step should take around 5 minutes.

---

### Attack Flow

Terminal 2 (victim container, `victim_user`):

```bash
sudo ./run.sh http_client
```

Runs the HTTP client as `victim_user` in the victim container.

The client sends an HTTP GET request to `192.0.2.123` (the HTTP server).  
If the malicious application or the ARN are not running, you should see the regular `index.html` page.

Terminal 1 (victim container, `malicious_user`):

```bash
sudo ./run.sh tcp_main_cbpf
```

Runs the victim-side malicious logic as `malicious_user` in the victim container.

This process detects the victim connection source port, infers the expected ISN using the preprocessing table, and sends the required connection details to the ARN so it can inject forged packets.

Terminal 3 (ARN container):

```bash
sudo ./run.sh tcp_inject
```

Runs the ARN application that injects crafted TCP packets into the connection.

Terminal 2 (victim container, `victim_user`):

```bash
sudo ./run.sh http_client
```

Triggers the HTTP request again.

**Success:**
You should see in terminal 2 (victim container, `victim_user`):

```text
hello from attacker
```

---

### Statistics

Terminal 2 (victim container, `victim_user`):

```bash
sudo ./run.sh http_client N
```

Runs the HTTP client `N` times (loop) as `victim_user` in the victim container.

Use this to automatically repeat the attack and observe success rate statistics over multiple runs.

---

## 2. TCP Hijacking (IP Options)

### Pre-processing

Terminal 1 (ARN container):

```bash
sudo ./run.sh capture
```

Runs ISN capture from the ARN container.

The ARN captures SYN packets sent by the malicious application, extracts the ISN, and sends it back to the malicious application.

Terminal 2 (victim container, `malicious_user`):

```bash
sudo ./run.sh ipoptions
```

Runs IP Options preprocessing as `malicious_user` on the victim machine.

The malicious application sends SYN packets with IP options so they traverse the ARN container. The ARN extracts the ISNs, sends them back to the malicious application, and the preprocessing table is built as:

```text
port -> ISN, timestamp
```

This step should take around 40 seconds.

### Attack Flow

Terminal 3 (victim container, `victim_user`):

```bash
sudo ./run.sh http_client
```

Runs the HTTP client as `victim_user`.

The client sends an HTTP GET request to `192.0.2.123` (the HTTP server).  
If the malicious application or the ARN are not running, you should see the regular `index.html` page.

Terminal 2 (victim container, `malicious_user`):

```bash
sudo ./run.sh tcp_main_ipoptions
```

Runs the victim-side malicious logic as `malicious_user` in the victim container.

This process detects the victim connection source port, infers the expected ISN using the preprocessing table, and sends the required connection details to the ARN so it can inject forged packets.

Terminal 1 (ARN container):

```bash
sudo ./run.sh tcp_inject
```

Runs the ARN application that injects crafted TCP packets into the connection.

Terminal 3 (victim container, `victim_user`):

```bash
sudo ./run.sh http_client
```

Triggers the HTTP request again.

**Success:**
You should see in terminal 3 (victim container, `victim_user`):

```text
hello from attacker
```

---

## 3. DNS Cache Poisoning

### Attack Flow

Terminal 1 (victim container, `victim_user`):

```bash
sudo ./run.sh resolve
```

Resolves `example.com` from `victim_user` in the victim container.

Before the attack, it should resolve to:

```text
192.0.2.124
```

Terminal 2 (ARN container)::

```bash
sudo ./run.sh dns_inject
```

Runs the ARN application that injects forged DNS responses by brute-forcing the TXID.

Terminal 3 (victim container, `malicious_user`):

```bash
sudo ./run.sh dns_main
```

Runs the victim-side DNS cache poisoning logic as `malicious_user` in the victim container.

The malicious application triggers a DNS query, detects the source port used by the resolver using the `/procfs` method, and sends this information to the ARN so it can attack with forged DNS responses. **Note:** In the paper, the second observed port corresponds to the stub resolver’s outbound query. In this Docker environment, the desired port is the third one, because the containers’ internal DNS resolver introduces an additional local query that occupies an extra port. This extra port is due to internal container networking behavior and is not relevant to the attack itself.

Terminal 1 (victim container, `victim_user`):

```bash
sudo ./run.sh resolve
```

Resolves `example.com` again.

**Success:**
You should see resolution to:

```text
6.6.6.X
```

---

### Statistics

Terminal 3 (victim container, `malicious_user`):

```bash
sudo ./run.sh dns_main N
```

Runs the DNS cache poisoning logic `N` times (loop) as `malicious_user` in the victim container.

Use this to automatically repeat the attack and observe success rate statistics over multiple runs.

**Note:** This code runs as `malicious_user` in the victim container. A run is considered successful if a DNS query from `malicious_user` resolves the domain to the forged IP injected by the ARN. Ideally, verification would be performed from `victim_user`; however, since the DNS cache is shared between users, poisoning it via `malicious_user` also affects `victim_user`, making this a valid indication of success. This criterion is used only for statistics; the manual experiment above provides the accurate validation of the attack.

---

## Key Insight

A local unprivileged application can:

- infer security-sensitive protocol fields of other users' connections
- assist an ARN
- enable practical TCP hijacking and DNS poisoning

---

## Reference

Cross User/App Network Attacks — Hijacking TCP Connections and DNS Cache Poisoning via a Malicious User/Application

---

## Confidentiality Notice

The content and insights presented in this artifact relate to vulnerabilities that are unpatched (yet).

Please treat this material as confidential and avoid sharing or distributing it beyond the intended audience.

---

## Disclaimer

For research and educational use only.
Do not use outside controlled environments which you own.
