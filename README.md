# Low-Level Packet Sniffer in C

A small libpcap-based packet sniffer plus a local Docker test stack for generating traffic to observe.

## Minimal bootstrap

### 1. Install dependencies

On Debian/Ubuntu:

```sh
sudo apt update
sudo apt install -y build-essential libpcap-dev docker.io
```

Make sure Docker is available in your shell:

```sh
docker --version
```

### 2. Build the sniffer

From the project root:

```sh
make
```

Run it with a network interface:

```sh
sudo ./sniffer -i eth0
```

If the program expects a different interface or flags, check the source in `src/sniffer.c`.

### 3. Start the test environment

From the project root:

```sh
cd test
docker compose up -d --build
```

To follow logs:

```sh
docker compose logs -f
```

### 4. Optional convenience script

This repo includes a simple bootstrap script:

```sh
./init.sh
```

It checks for `libpcap-dev`, builds the C project if needed, and starts the Compose stack.

## Notes

- The Docker stack is only for local testing.
- This project is meant for a controlled lab environment, not production use.
- Use the local test services to generate traffic while the sniffer runs in capture mode.


```sh
docker compose down
docker compose build --no-cache
docker compose up -d
```

### Telnet cannot allocate a PTY or will not start

Confirm that the host is Linux and that Docker is allowed to use the configured capabilities, `/dev/ptmx`, `/dev/pts`, and AppArmor setting. Check:

```sh
docker compose logs telnet-server
docker inspect telnet_server --format '{{json .HostConfig.CapAdd}} {{json .HostConfig.SecurityOpt}}'
```

On hosts with stricter security policy, `apparmor:unconfined` or the requested capabilities may be denied. Update the host policy or use a disposable Linux VM; do not blindly broaden privileges on a production machine.

### Client tools are missing

The tools are installed while building the client image. Rebuild if the Dockerfile changed or an earlier package installation failed:

```sh
docker compose build --no-cache client
docker compose up -d client
docker compose exec client command -v telnet ping tcpdump tmux
```

### The host cannot reach Flask on port 8080

By default, the checked-in Compose file does not publish Flask to the host. Use the internal check instead:

```sh
docker compose exec client curl -fsS http://flask:8080/health
```

If host access is required, add the `8080:8080` mapping described in [Networking](#networking), then recreate the Flask container.

### Docker permissions or capture permissions fail

Use a user that can access the Docker daemon, commonly by adding the user to the `docker` group and starting a new login session. Packet capture may also require root or additional Linux capabilities. Restrict captures to interfaces and traffic you are authorized to inspect.

## Useful Commands

Run these from `test/`:

```sh
docker compose config          # Validate and render the Compose configuration
docker compose images          # List images used by the project
docker compose top             # Show processes inside the services
docker compose restart         # Restart without rebuilding
docker compose down --volumes  # Remove containers, network, and named volumes
```

Return to the repository root before using native build commands:

```sh
cd ..
make clean
make
```