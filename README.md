# Dokploy Swarm Security Controller

A lightweight, webhook-driven security controller for Docker Swarm applications deployed through Dokploy.

The controller automatically checks and optionally enforces container security settings after successful Dokploy deployments.

## Overview

Dokploy manages application deployments on Docker Swarm. However, some container security settings may require additional configuration after deployment.

This controller provides a post-deployment security enforcement mechanism without modifying Dokploy itself.

It receives deployment notifications, identifies the corresponding Docker Swarm service, waits for its rollout to complete, and applies a configurable security policy.

## Features

- Integration with Dokploy Custom Notifications.
- Per-application security policies.
- Two operating modes: `observe` and `enforce`.
- Automatic processing of successful application builds.
- Docker Swarm rollout verification.
- Idempotent service updates.
- Detection of concurrent service modifications.
- Per-service locking for concurrent webhook requests.
- Bearer-token authentication.
- JSON responses and systemd journal logging.

### Supported Security Settings

| Setting | Description |
|---|---|
| `user` | Run the container using a specified UID and GID. |
| `readOnly` | Enable a read-only root filesystem. |
| `capDrop` | Drop Linux capabilities. |
| `pidsLimit` | Limit the number of processes. |
| `env` | Configure environment variables required by the security policy. |

The controller also sets `NoNewPrivileges=true`.

When `readOnly` is enabled, it additionally configures a writable `/tmp` tmpfs (64 MiB).

The `/tmp` mount must not conflict with an existing mount.

## Architecture

```text
Dokploy
   |
   | Successful application build
   v
Custom Notification (HTTP Webhook)
   |
   v
Dokploy Swarm Security Controller
   |
   +-- Authenticate request
   +-- Identify application
   +-- Wait for Swarm rollout
   +-- Evaluate security policy
   |
   +-- observe: report deviations
   |
   +-- enforce: update service specification
                    |
                    v
              Docker Engine API
                    |
                    v
              Docker Swarm
```

The controller runs on a Docker Swarm manager with access to the local Docker API.

## Requirements

- Linux host running Docker Engine in Swarm manager mode.
- Docker CLI.
- Python 3 with virtual environment support.
- systemd (for the provided service unit).
- Network connectivity from the Dokploy notification sender to the controller.

The controller uses the Docker CLI for service inspection and the Docker Engine API through `/var/run/docker.sock` for service updates.

## Installation

Clone the repository:

```bash
sudo git clone \
  https://github.com/iluxaru/dokploy-swarm-security-controller.git \
  /opt/dokploy-security-controller

cd /opt/dokploy-security-controller
```

Create a Python virtual environment and install dependencies:

```bash
sudo python3 -m venv .venv

sudo .venv/bin/pip install -r requirements.txt
```

Create the application configuration:

```bash
sudo cp \
  config/applications.example.yaml \
  config/applications.yaml
```

Edit `config/applications.yaml` to match your Dokploy projects, applications, and Docker Swarm service names.

### Environment Configuration

Generate an authentication token:

```bash
openssl rand -hex 32
```

Create the environment file:

```bash
sudo cp .env.example /etc/dokploy-security-controller.env
sudo chmod 600 /etc/dokploy-security-controller.env
```

Edit `/etc/dokploy-security-controller.env`:

```ini
CONTROLLER_HOST=127.0.0.1
CONTROLLER_PORT=9877
CONTROLLER_TOKEN=REPLACE_WITH_RANDOM_TOKEN
CONTROLLER_CONFIG=/opt/dokploy-security-controller/config/applications.yaml
```

Replace `REPLACE_WITH_RANDOM_TOKEN` with the generated token.

If Dokploy sends notifications from a container, configure a reachable host interface as described in the Network Configuration section.

### systemd Integration

Install the provided service unit:

```bash
sudo cp \
  systemd/dokploy-security-controller.service \
  /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable --now dokploy-security-controller
```

Check the service:

```bash
systemctl status dokploy-security-controller

journalctl -u dokploy-security-controller -f
```

## Application Configuration

Application policies are defined in:

```text
config/applications.yaml
```

Example:

```yaml
defaults:
  security:
    user: "1000:1000"
    readOnly: true
    capDrop:
      - ALL
    pidsLimit: 256

applications:
  - project: Example-QA
    application: example-app
    service: example-qa-example-app-abc123
    mode: observe
    security:
      env:
        HOME: /home/ubuntu
        NPM_CONFIG_CACHE: /tmp/npm-cache

  - project: Example-PROD
    application: example-app
    service: example-prod-example-app-def456
    mode: enforce
    security:
      env:
        HOME: /home/ubuntu
        NPM_CONFIG_CACHE: /tmp/npm-cache
```

### Configuration Fields

| Field | Description |
|---|---|
| `project` | Dokploy project name. |
| `application` | Dokploy application name. |
| `service` | Exact Docker Swarm service name. |
| `mode` | `observe` or `enforce`. |
| `security` | Application-specific security settings. |
| `defaults.security` | Default security settings shared by applications. |

Application-specific security settings override the corresponding default settings.

The default operating mode is `observe`.

Use the exact project and application names supplied in the Dokploy webhook payload.

To find the Docker Swarm service name:

```bash
docker service ls
```

## Network Configuration

### Docker Container to Host Connectivity

By default, the controller listens on the host's loopback interface:

```ini
CONTROLLER_HOST=127.0.0.1
CONTROLLER_PORT=9877
```

**Important:** When Dokploy runs inside a Docker container, `127.0.0.1` refers to the container itself, not the Docker host.

Consequently, Dokploy may be unable to reach the controller through the host's loopback address.

### Recommended Configuration

Configure the controller to listen on an IP address assigned to a host network interface reachable from the Dokploy container.

For example:

```ini
CONTROLLER_HOST=192.168.0.7
CONTROLLER_PORT=9877
```

Configure the Dokploy webhook URL accordingly:

```text
http://192.168.0.7:9877/webhook/dokploy
```

Replace `192.168.0.7` with an appropriate IP address of your Docker host.

Do not assume that every host interface is reachable from every Docker network. Verify connectivity from the actual notification sender.

### Verify Connectivity

Inspect the Docker networks attached to Dokploy:

```bash
docker inspect dokploy \
  --format '{{json .NetworkSettings.Networks}}' | jq
```

Test connectivity from the Dokploy container:

```bash
docker exec dokploy \
  curl -v --connect-timeout 5 \
  http://192.168.0.7:9877/webhook/dokploy
```

An HTTP `501 Not Implemented` response is expected for a GET request because the controller implements only POST requests.

Connection refusal or timeout indicates a listener, routing, or firewall issue.

If `curl` is unavailable inside the container, use another HTTP client or a temporary diagnostic container attached to the same Docker network.

### Network Security

The controller can modify Docker Swarm services through the Docker API.

**Never expose the controller endpoint directly to the public internet.**

Recommended precautions:

- Bind the controller to a private host interface.
- Restrict inbound TCP port `9877` to trusted notification senders.
- Use a strong, randomly generated bearer token.
- Keep authentication tokens outside Git repositories.
- Use HTTPS when webhook traffic crosses an untrusted network.

Bearer-token authentication does not encrypt HTTP traffic.

Avoid binding to `0.0.0.0` unless all exposed interfaces are appropriately protected.

## Dokploy Webhook Configuration

In Dokploy, configure a Custom Notification provider using:

**Webhook URL**

```text
http://HOST_IP:9877/webhook/dokploy
```

**HTTP method**

```text
POST
```

**Headers**

```text
Authorization: Bearer YOUR_CONTROLLER_TOKEN
Content-Type: application/json
```

Enable the notification for successful application deployments.

The controller processes JSON events matching:

```json
{
  "type": "build",
  "status": "success",
  "applicationType": "application",
  "projectName": "Example-QA",
  "applicationName": "example-app"
}
```

Other event types and unsuccessful builds are ignored.

The project and application names must match exactly one entry in `config/applications.yaml`.

Unknown or ambiguous applications are ignored.

## Operating Modes

### Observe

```yaml
mode: observe
```

The controller checks the service against its configured security policy and reports deviations.

It does not modify the Docker Swarm service.

Note: capability-drop deviation reporting has a known issue in the current implementation.

Use this mode to evaluate compatibility before enabling enforcement.

### Enforce

```yaml
mode: enforce
```

The controller checks the service and applies the configured security settings through the Docker Engine API.

If the resulting service specification is unchanged, no update is submitted.

If changes are required, the controller updates the service specification.

**Important:** Updating a Docker Swarm service specification can trigger task replacement and application disruption.

Test security policies in a non-production environment before enabling enforcement for production applications.

## Rollout Verification

Before evaluating a policy, the controller waits for the Dokploy deployment to finish.

It checks:

- Docker Swarm update state.
- Desired replica count.
- Number of running tasks.
- Stability across three consecutive checks.

Checks are performed approximately every two seconds, with a default timeout of 120 seconds.

Paused or rolled-back deployments are rejected.

Enforcement is also refused if the service update state is not `completed`.

## Webhook Responses

Successful requests return JSON.

Possible results include:

| Status | Meaning |
|---|---|
| `ignored` | Event or application does not match the processing criteria. |
| `observed` | Security policy evaluated without modifying the service. |
| `unchanged` | Service already matches the enforced specification. |
| `updated` | A service specification update was submitted. |

The `updated` response indicates that Docker accepted the update request; it does not guarantee that the resulting rollout has completed successfully.

Possible HTTP errors include:

| HTTP status | Meaning |
|---|---|
| `401` | Missing or invalid bearer token. |
| `404` | Unknown endpoint. |
| `409` | Service is not ready or a concurrent update conflict occurred. |
| `413` | Empty or oversized request body length. |
| `500` | Configuration, Docker, or processing error. |
| `504` | Timed out waiting for the initial service rollout. |

## Monitoring and Troubleshooting

Follow controller logs:

```bash
journalctl -u dokploy-security-controller -f
```

Check the service status:

```bash
systemctl status dokploy-security-controller
```

Inspect the Docker Swarm service:

```bash
docker service inspect SERVICE_NAME
```

Check service tasks:

```bash
docker service ps SERVICE_NAME
```

Inspect container security settings:

```bash
docker service inspect SERVICE_NAME \
  --format '{{json .Spec.TaskTemplate.ContainerSpec}}' | jq
```

Inspect process limits:

```bash
docker service inspect SERVICE_NAME \
  --format '{{json .Spec.TaskTemplate.Resources.Limits}}' | jq
```

If a webhook cannot reach the controller, verify the listening address, container-to-host routing, and host firewall.

If enforcement fails, check the controller journal and Docker Swarm service update status.

## Security Considerations

The controller requires access to the Docker API and therefore operates with highly privileged access to the Docker host.

The provided systemd unit runs as root.

Protect the controller host, configuration files, and authentication token accordingly.

Additional considerations:

- Use `observe` before enabling `enforce`.
- Verify application compatibility with non-root execution.
- Ensure applications do not require writes to the root filesystem.
- Configure writable mounts for application-specific data where necessary.
- Review the consequences of dropping all Linux capabilities.
- Restrict network access to the webhook endpoint.
- Do not expose the Docker Unix socket to untrusted containers.

## Limitations

Current implementation limitations include:

- Supports Docker Swarm services using replicated mode.
- Processes successful Dokploy application build notifications only.
- Requires exact project/application mapping in the configuration.
- Requires access to a local Docker Swarm manager.
- Uses a fixed Docker Engine API version (`v1.56`).
- Uses a fixed 120-second rollout timeout.
- Does not automatically roll back failed security updates.
- Does not verify completion of the rollout triggered by enforcement.
- Does not continuously reconcile service policies between deployment events.
- Does not provide a dedicated health-check endpoint.

## License

Licensed under the Apache License, Version 2.0.

See the [LICENSE](LICENSE) file for details.
