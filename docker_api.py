import http.client
import json
import socket


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path="/var/run/docker.sock", timeout=15):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


def get_service(service_name):
    connection = UnixHTTPConnection()

    try:
        connection.request(
            "GET",
            f"/v1.56/services/{service_name}",
        )

        response = connection.getresponse()
        body = response.read()

        if response.status != 200:
            raise RuntimeError(
                f"Docker API error {response.status}: "
                f"{body.decode(errors='replace')}"
            )

        return json.loads(body)

    finally:
        connection.close()


def prepare_secure_spec(service, policy):
    import copy

    spec = copy.deepcopy(service["Spec"])
    task = spec["TaskTemplate"]
    container = task["ContainerSpec"]

    container["User"] = policy["user"]
    container["ReadOnly"] = policy["readOnly"]

    if policy["readOnly"]:
        env = container.setdefault("Env", [])
        required_env = policy.get("env", {})

        for name, value in required_env.items():
            env[:] = [
                item for item in env
                if item.split("=", 1)[0] != name
            ]
            env.append(f"{name}={value}")

    if policy["readOnly"]:
        mounts = container.setdefault("Mounts", [])
        expected_tmpfs = {
            "Type": "tmpfs",
            "Target": "/tmp",
            "TmpfsOptions": {
                "SizeBytes": 64 * 1024 * 1024,
                "Mode": 0o1777,
            },
        }

        existing = [
            mount for mount in mounts
            if mount.get("Target") == "/tmp"
        ]

        if not existing:
            mounts.append(expected_tmpfs)
        elif len(existing) != 1 or existing[0] != expected_tmpfs:
            raise ValueError(
                "Existing /tmp mount conflicts with security policy"
            )

    container["CapabilityDrop"] = list(policy["capDrop"])

    privileges = container.setdefault("Privileges", {})
    privileges["NoNewPrivileges"] = True

    resources = task.setdefault("Resources", {})
    limits = resources.setdefault("Limits", {})
    limits["Pids"] = policy["pidsLimit"]

    return spec, spec != service["Spec"]


class ServiceVersionConflict(RuntimeError):
    pass


class ServiceNotReady(RuntimeError):
    pass


def update_service(service, new_spec):
    from urllib.parse import quote

    service_id = service["ID"]
    version = service["Version"]["Index"]

    connection = UnixHTTPConnection()

    try:
        body = json.dumps(new_spec).encode("utf-8")

        path = (
            f"/v1.56/services/{quote(service_id, safe='')}/update"
            f"?version={version}"
        )

        connection.request(
            "POST",
            path,
            body=body,
            headers={
                "Content-Type": "application/json",
            },
        )

        response = connection.getresponse()
        response_body = response.read()

        if response.status == 409 or (
            response.status == 500
            and b"update out of sequence" in response_body
        ):
            raise ServiceVersionConflict(
                "Docker Swarm service version conflict: "
                "service was modified concurrently"
            )

        if response.status != 200:
            raise RuntimeError(
                f"Docker API update failed (HTTP {response.status})"
            )

        return json.loads(response_body)

    finally:
        connection.close()


def enforce_security(service_name, policy):
    service = get_service(service_name)

    state = (service.get("UpdateStatus") or {}).get("State")

    if state != "completed":
        raise ServiceNotReady(
            f"Refusing to enforce during Swarm rollout: {state}"
        )

    spec, changed = prepare_secure_spec(service, policy)

    if not changed:
        return {
            "status": "unchanged",
            "service": service_name,
            "version": service["Version"]["Index"],
        }

    result = update_service(service, spec)

    return {
        "status": "updated",
        "service": service_name,
        "previous_version": service["Version"]["Index"],
        "result": result,
    }
