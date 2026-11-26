
# PunyGuard XDR - Automated Monitoring Health Check

import json
import psutil
from pathlib import Path
from datetime import datetime, timezone
from desktop_alert import send_monitoring_alert


BASE_DIR = Path(__file__).resolve().parent
STATUS_FILE = BASE_DIR / "logs" / "monitor_status.json"
HISTORY_FILE = BASE_DIR / "logs" / "health_history.jsonl"
ALERT_STATE_FILE = BASE_DIR / "logs" / "health_alert_state.json"

MAX_AGE_SECONDS = 300


def log_health_event(status, message, **details):
    """Record monitoring health history."""

    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "monitor": "PunyGuard XDR",
        "status": status,
        "message": message,
        **details
    }

    with HISTORY_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")


def monitor_is_running():
    """Check whether the PunyGuard DNS monitor is running."""

    for process in psutil.process_iter(
        ["pid", "name", "cmdline"]
    ):
        try:
            name = (process.info["name"] or "").lower()
            command = process.info["cmdline"] or []

            if name not in ("python.exe", "pythonw.exe"):
                continue

            if any(
                Path(arg).name.lower() == "dns_monitor.py"
                for arg in command
            ):
                return True

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

    return False


def update_alert_state(problem):
    """Prevent duplicate alerts and record recovery."""

    ALERT_STATE_FILE.parent.mkdir(
        parents=True, exist_ok=True
    )

    previous_problem = None

    if ALERT_STATE_FILE.exists():
        try:
            state = json.loads(
                ALERT_STATE_FILE.read_text(encoding="utf-8")
            )
            previous_problem = state.get("problem")

        except (OSError, ValueError, TypeError, AttributeError):
            pass

    if problem != previous_problem:

        if problem:
            try:
                delivered = send_monitoring_alert(problem)

                if not delivered:
                    print("[WARNING] Notification not delivered")
                    return

            except Exception as error:
                print("[ERROR] Notification failed:", error)
                return

        elif previous_problem:
            print("[RECOVERED] DNS monitor is running again")

            log_health_event(
                "RECOVERED",
                "DNS monitoring process is running again."
            )

    new_state = {
        "problem": problem,
        "last_checked": datetime.now(timezone.utc).isoformat()
    }

    ALERT_STATE_FILE.write_text(
        json.dumps(new_state, indent=4),
        encoding="utf-8"
    )


def check_health():
    """Check monitoring process and DNS capture activity."""

    print("=" * 50)
    print("PUNYGUARD XDR - HEALTH CHECK")
    print("=" * 50)

    if not monitor_is_running():

        print("[WARNING] DNS monitor is not running")

        log_health_event(
            "WARNING",
            "DNS monitoring process is not running.",
            process_running=False
        )

        update_alert_state(
            "DNS monitoring process is not running."
        )

        return False

    print("[OK] DNS monitoring process is running")

    packet_count = None
    activity_age = None
    activity_status = "UNKNOWN"

    if STATUS_FILE.exists():

        try:
            status = json.loads(
                STATUS_FILE.read_text(encoding="utf-8")
            )

            heartbeat = datetime.fromisoformat(
                status["last_heartbeat"]
            )

            if heartbeat.tzinfo is None:
                raise ValueError("Heartbeat lacks timezone")

            age = (
                datetime.now(timezone.utc) - heartbeat
            ).total_seconds()

            packet_count = status.get(
                "dns_packets_captured", 0
            )

            activity_age = round(age)

            print("DNS packets captured:", packet_count)
            print("Last DNS activity age:", activity_age, "seconds")

            if age < 0:
                activity_status = "INVALID_TIMESTAMP"
                print("[WARNING] Future activity timestamp")

            elif age <= MAX_AGE_SECONDS:
                activity_status = "RECENT"
                print("[OK] Recent DNS capture activity")

            else:
                activity_status = "QUIET"
                print("[INFO] No recent DNS activity")

        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
            AttributeError
        ) as error:

            activity_status = "UNAVAILABLE"
            print("[WARNING] Activity status unavailable:", error)

    else:
        activity_status = "NO_STATUS_FILE"
        print("[INFO] No DNS activity status file found")

    update_alert_state(None)

    log_health_event(
        "HEALTHY",
        "DNS monitoring process is running.",
        process_running=True,
        dns_packets_captured=packet_count,
        dns_activity_age_seconds=activity_age,
        dns_activity_status=activity_status
    )

    print("[OK] Health history recorded")
    print("=" * 50)

    return True


if __name__ == "__main__":

    try:
        healthy = check_health()
        raise SystemExit(0 if healthy else 1)

    except (OSError, psutil.Error) as error:

        print("[ERROR] Health check failed:", error)

        try:
            log_health_event("ERROR", str(error))
        except OSError:
            pass

        raise SystemExit(2)
