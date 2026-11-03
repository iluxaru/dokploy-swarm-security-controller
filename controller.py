#!/usr/bin/env python3

import hmac
import json
import logging
import os
import subprocess
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml

from docker_api import enforce_security, ServiceVersionConflict, ServiceNotReady, prepare_secure_spec


CONFIG = Path(
    os.environ.get(
        "CONTROLLER_CONFIG",
        str(Path(__file__).resolve().parent / "config/applications.yaml"),
    )
)
HOST = os.environ.get("CONTROLLER_HOST", "127.0.0.1")
PORT = int(os.environ.get("CONTROLLER_PORT", "9877"))
TOKEN = os.environ.get("CONTROLLER_TOKEN", "")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("dokploy-security-controller")


SERVICE_LOCKS = {}
SERVICE_LOCKS_GUARD = threading.Lock()


def get_service_lock(service_name):
    with SERVICE_LOCKS_GUARD:
        return SERVICE_LOCKS.setdefault(
            service_name,
            threading.Lock(),
        )


def load_config():
    with CONFIG.open() as f:
        config = yaml.safe_load(f)

    if not isinstance(config, dict):
        raise ValueError("Invalid controller configuration")

    return config


def inspect_service(name):
    result = subprocess.run(
        ["docker", "service", "inspect", name],
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    return json.loads(result.stdout)[0]



def inspect_tasks(service_id):
    result = subprocess.run(
        [
            "docker", "service", "ps",
            "--filter", "desired-state=running",
            "--format", "{{.ID}}",
            service_id,
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )

    task_ids = result.stdout.splitlines()

    if not task_ids:
        return []

    result = subprocess.run(
        ["docker", "inspect", "--type", "task", *task_ids],
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )

    return json.loads(result.stdout)


def wait_for_rollout(service_name, timeout=120):
    deadline = time.monotonic() + timeout
    stable_checks = 0

    while time.monotonic() < deadline:
        service = inspect_service(service_name)
        service_id = service["ID"]

        status = service.get("UpdateStatus") or {}
        state = status.get("State")

        if state in (
            "paused",
            "rollback_started",
            "rollback_paused",
            "rollback_completed",
        ):
            raise ServiceNotReady(
                f"Service rollout failed or rolled back: {state}"
            )

        replicas = service["Spec"]["Mode"]["Replicated"]["Replicas"]
        tasks = inspect_tasks(service_id)

        running = [
            task for task in tasks
            if task.get("ServiceID") == service_id
            and task.get("DesiredState") == "running"
            and task.get("Status", {}).get("State") == "running"
        ]

        ready = state == "completed" and len(running) == replicas

        if ready:
            stable_checks += 1
        else:
            stable_checks = 0

        if stable_checks >= 3:
            log.info(
                "Rollout completed: service=%s replicas=%s running=%s",
                service_name, replicas, len(running),
            )
            return service

        time.sleep(2)

    raise TimeoutError(
        f"Timed out waiting for rollout: {service_name}"
    )


def check_security(service, policy):
    actual_spec = service["Spec"]
    expected_spec, _ = prepare_secure_spec(service, policy)

    actual_container = actual_spec["TaskTemplate"]["ContainerSpec"]
    expected_container = expected_spec["TaskTemplate"]["ContainerSpec"]

    actual_limits = (
        actual_spec["TaskTemplate"]
        .get("Resources", {})
        .get("Limits", {})
    )

    expected_limits = (
        expected_spec["TaskTemplate"]
        .get("Resources", {})
        .get("Limits", {})
    )

    deviations = {}

    checks = {
        "user": (
            actual_container.get("User", ""),
            expected_container.get("User", ""),
        ),
        "readOnly": (
            actual_container.get("ReadOnly", False),
            expected_container.get("ReadOnly", False),
        ),
        "capDrop": (
            (actual_container.get("Privileges") or {}).get(
                "CapabilityDrop", []
            ),
            (expected_container.get("Privileges") or {}).get(
                "CapabilityDrop", []
            ),
        ),
        "pidsLimit": (
            actual_limits.get("Pids"),
            expected_limits.get("Pids"),
        ),
    }

    for name, (actual, expected) in checks.items():
        if actual != expected:
            deviations[name] = {
                "expected": expected,
                "actual": actual,
            }

    actual_mounts = [
        mount
        for mount in actual_container.get("Mounts", [])
        if mount.get("Target") == "/tmp"
    ]

    expected_mounts = [
        mount
        for mount in expected_container.get("Mounts", [])
        if mount.get("Target") == "/tmp"
    ]

    if actual_mounts != expected_mounts:
        deviations["tmpfs"] = {
            "expected": expected_mounts,
            "actual": actual_mounts,
        }

    actual_env = {
        item.split("=", 1)[0]: item.split("=", 1)[1]
        for item in actual_container.get("Env", [])
        if "=" in item
    }

    for name, expected in policy.get("env", {}).items():
        actual = actual_env.get(name)

        if actual != expected:
            deviations[f"env:{name}"] = {
                "expected": "<configured>",
                "actual": "<missing>" if actual is None else "<different>",
            }

    return deviations


class Handler(BaseHTTPRequestHandler):

    def do_POST(self):
        if self.path != "/webhook/dokploy":
            self.send_error(404)
            return

        authorization = self.headers.get("Authorization", "")

        if not TOKEN or not hmac.compare_digest(
            authorization, f"Bearer {TOKEN}"
        ):
            self.send_error(401)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))

            if not 0 < length <= 65536:
                self.send_error(413)
                return

            payload = json.loads(self.rfile.read(length))

            if not isinstance(payload, dict):
                self.send_error(400)
                return

            if (
                payload.get("type") != "build"
                or payload.get("status") != "success"
                or payload.get("applicationType") != "application"
            ):
                log.info("Ignoring non-successful build event")
                self.respond(200, {"status": "ignored"})
                return

            config = load_config()

            matches = [
                app for app in config.get("applications", [])
                if app.get("project") == payload.get("projectName")
                and app.get("application") == payload.get("applicationName")
            ]

            if len(matches) != 1:
                log.warning(
                    "Unknown or ambiguous application: %s/%s",
                    payload.get("projectName"),
                    payload.get("applicationName"),
                )
                self.respond(200, {"status": "ignored"})
                return

            app = matches[0]
            service_name = app["service"]

            with get_service_lock(service_name):
                service = wait_for_rollout(service_name)

                policy = dict(config.get("defaults", {}).get("security", {}))
                policy.update(app.get("security", {}))

                deviations = check_security(service, policy)

                log.info(
                    "Application=%s/%s service=%s mode=%s "
                    "update_state=%s deviations=%s",
                    app["project"],
                    app["application"],
                    service_name,
                    app.get("mode", "observe"),
                    (service.get("UpdateStatus") or {}).get("State"),
                    json.dumps(deviations),
                )

                mode = app.get("mode", "observe")

                if mode == "observe":
                    result = {
                        "status": "observed",
                        "service": service_name,
                        "deviations": deviations,
                    }
                elif mode == "enforce":
                    result = enforce_security(service_name, policy)
                    log.info(
                        "Enforcement result: service=%s result=%s",
                        service_name,
                        result.get("status"),
                    )
                else:
                    raise ValueError(f"Unsupported mode: {mode}")

                self.respond(200, result)

        except ServiceVersionConflict:
            log.error("Concurrent Docker service modification")
            self.respond(409, {"error": "ServiceVersionConflict"})

        except TimeoutError:
            log.error("Timed out waiting for service rollout")
            self.respond(504, {"error": "RolloutTimeout"})

        except ServiceNotReady:
            log.error("Service is not ready for enforcement")
            self.respond(409, {"error": "ServiceNotReady"})

        except RuntimeError:
            log.error("Unexpected runtime error")
            self.respond(500, {"error": "RuntimeError"})

        except (
            ValueError,
            KeyError,
            subprocess.SubprocessError,
            OSError,
        ) as exc:
            log.error("Webhook processing failed")
            self.respond(500, {"error": type(exc).__name__})

    def respond(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("CONTROLLER_TOKEN must be configured")

    server = ThreadingHTTPServer((HOST, PORT), Handler)

    log.info("Listening on %s:%s", HOST, PORT)
    server.serve_forever()
