# Low-Level Packet Sniffer in C

A small C/libpcap packet-sniffing project with a Docker Compose test environment. The test stack provides a Flask login application, a deliberately exposed Telnet service, and a browser-equipped diagnostics client on one isolated Docker bridge network. It is intended for local network-observation and credential-sniffing experiments in an environment you control.

> **Security notice**
>
> This repository is a lab environment, not a production deployment. The Telnet service sends credentials in cleartext, the Flask application contains demo credentials, and the Compose configuration deliberately relaxes container security for PTY and diagnostic testing. Run it only on a disposable or trusted host, and stop it when you are finished.

## Architecture

The Compose project is defined in [`test/docker-compose.yml`](test/docker-compose.yml). All services join the user-defined bridge network `docker_net` and can address one another by service hostname.

| Service | Container | Purpose | Ports |
| --- | --- | --- | --- |
| `flask` | `web_server` | Python 3.12 Flask login UI and health endpoint | `8080` inside the network; publish to the host as described below |
| `telnet-server` | `telnet_server` | Ubuntu `inetd`/`telnetd` service for connectivity and cleartext traffic tests | `23` inside the network |
| `client` | `client` | Brave browser GUI plus Telnet, ping, traceroute, DNS, `tcpdump`, `iptables`, and `tmux` | `3000` for the browser interface |

The C executable is built separately with the root [`Makefile`](Makefile). The Docker services are test fixtures for generating traffic that can be observed by the sniffer.

## Prerequisites

Install the following on a Linux host:

- Docker Engine with permission to run containers.
- Docker Compose v2, available as the `docker compose` plugin.
- Git and a POSIX-compatible shell.
- For the native sniffer: GCC, GNU Make, and the libpcap development package. On Debian or Ubuntu:

	```sh
	sudo apt update
	sudo apt install -y build-essential libpcap-dev
	```

The Compose stack downloads Linux images and packages during the first build. Internet access is therefore required for the initial `docker compose build`.

## Quick Start

### 1. Clone the repository

Replace the placeholder URL with the repository URL:

```sh
git clone <repository-url> _low_level_packet_sniffer_in_C
cd _low_level_packet_sniffer_in_C
```

### 2. Build the native sniffer (optional)

```sh
make
./sniffer
```

The exact capture interface and options depend on the implementation in `src/sniffer.c`. Capturing packets on a host interface may require root privileges or Linux capabilities.

### 3. Build and start the Compose environment

The Compose file lives under `test/`, so run Compose from that directory:

```sh
cd test
docker compose up -d --build
```

To follow startup logs:

```sh
docker compose logs -f flask telnet-server client
```

The first build can take several minutes because the client image installs a browser and diagnostic packages.

## Verify the Stack

Check service state and health summaries:

```sh
docker compose ps
docker compose ps --format 'table {{.Name}}\t{{.State}}\t{{.Health}}'
```

The `flask` and `telnet-server` services should report `healthy`. The client has no Compose health check, so it should be `running`.

Inspect the health-check results directly when a service is not healthy:

```sh
docker inspect --format '{{json .State.Health}}' web_server
docker inspect --format '{{json .State.Health}}' telnet_server
```

Test the Flask endpoint from the host and from the client network:

```sh
# Requires the optional 8080:8080 mapping described below.
curl -fsS http://localhost:8080/health
docker compose exec client curl -fsS http://flask:8080/health
```

Test Telnet from the client container:

```sh
docker compose exec client telnet telnet-server 23
```

Log in with the test account `telnetusr` / `telnet`. Press `Ctrl-]`, then enter `quit` to leave the Telnet client.

## Service Access and Usage

### Flask web application

After adding the host mapping described in [Networking](#networking), open [http://localhost:8080](http://localhost:8080) in a host browser. The application also exposes:

```text
GET /health  -> {"status":"healthy"}
GET /        -> login page
POST /login  -> success or error page
```

The current demo login is `admin` / `supersecret`, as defined in `test/web-server/app.py`. Do not reuse these credentials outside this lab.

### Client browser interface

Open [http://localhost:3000](http://localhost:3000). This is the browser/GUI endpoint provided by the LinuxServer Brave image. If the interface is unavailable, inspect the client logs and confirm that port `3000` is not already in use.

### Interactive diagnostics

Open a shell in the client container:

```sh
docker compose exec client bash
```

Useful commands from that shell include:

```sh
telnet telnet-server 23
ping -c 4 telnet-server
traceroute telnet-server
getent hosts flask telnet-server
curl -v http://flask:8080/health
tcpdump -D
tcpdump -i any -nn -A 'tcp port 23'
tmux
```

Use the service names `flask` and `telnet-server` instead of assuming container IP addresses. Docker may assign different IP addresses after a restart.

To leave the shell, run `exit`. To stop the environment while preserving containers and images:

```sh
docker compose stop
```

To stop and remove the containers and Compose network:

```sh
docker compose down
```

Add `--rmi local` when removing locally built images is also desired.

## Configuration and Security

### Environment variables

The current Compose file does not load a `.env` file and does not define runtime variable substitutions. Image-level settings include:

- `DEBIAN_FRONTEND=noninteractive` in the Ubuntu-based client and Telnet images, so package installation does not prompt during builds.
- `PYTHONDONTWRITEBYTECODE=1` and `PYTHONUNBUFFERED=1` in the Flask image, keeping container logs immediate and avoiding Python bytecode files.
- `PYTHONPATH=/app/local/lib/python3.12/site-packages` so the Flask runtime can use packages installed by the builder stage.

The Flask demo credentials and Telnet user password are source-controlled test values, not secrets. Change them in the application and image setup before using the project for any non-demo purpose.

### Networking

- Runtime traffic uses the user-defined bridge network `docker_net`.
- `flask` listens on container port `8080`; `telnet-server` listens on container port `23`.
- The Compose file currently publishes only the client port `3000`. To access Flask from the host, publish it explicitly in `test/docker-compose.yml`:

	```yaml
	ports:
		- "8080:8080"
	```

	Then recreate the stack with `docker compose up -d`.
- `network: host` under each `build` section controls the network used while building images. It does **not** switch the running services to host networking. Runtime services remain attached to `docker_net`.
- `docker compose exec client ...` is the preferred way to reach internal services without exposing their ports on the host.

### Deliberate security options

The Telnet container adds `SYS_ADMIN`, `AUDIT_WRITE`, `SETUID`, and `SETGID`, mounts `/dev/ptmx` and `/dev/pts`, and uses `apparmor:unconfined` to support Telnet PTY allocation. The client uses `seccomp=unconfined` and a 1 GiB shared-memory segment for the browser. These settings weaken container isolation and should remain limited to a disposable test host.

## Troubleshooting

### Port already in use

Find the process using a host port:

```sh
sudo ss -ltnp | grep -E ':(3000|8080|23)\b'
```

Stop the conflicting service, or change the host-side port mapping. The container ports and internal service names do not need to change.

### A service is unhealthy

Review the service logs and health-check output:

```sh
docker compose logs --tail=100 flask telnet-server
docker inspect --format '{{range .State.Health.Log}}{{println .ExitCode .Output}}{{end}}' web_server
docker inspect --format '{{range .State.Health.Log}}{{println .ExitCode .Output}}{{end}}' telnet_server
```

For a clean rebuild after changing a Dockerfile or package list:

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