import os
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SECRET_KEY")

if not SUPABASE_URL:
    raise RuntimeError("SUPABASE_URL is not configured in .env")

if not SUPABASE_KEY:
    raise RuntimeError("SUPABASE_SECRET_KEY is not configured in .env")

supabase: Client = create_client(
    SUPABASE_URL,
    SUPABASE_KEY
)


def create_tables():
    # Tables are already created in Supabase.
    return True


# ============================================================
# USER REGISTRATION
# ============================================================
def create_user(username, password):
    try:
        existing = (
            supabase
            .table("users")
            .select("id")
            .eq("username", username)
            .limit(1)
            .execute()
        )

        if existing.data:
            print("Create user error: Username already exists")
            return False

        response = (
            supabase
            .table("users")
            .insert({
                "username": username,
                "password": password
            })
            .execute()
        )

        print("Create user response:", response.data)

        return bool(response.data)

    except Exception as e:
        print("Create user error:", repr(e))
        raise
# ============================================================
# USER LOGIN
# ============================================================

def verify_user(username, password):
    try:
        response = (
            supabase
            .table("users")
            .select("id, username")
            .eq("username", username)
            .eq("password", password)
            .limit(1)
            .execute()
        )

        if response.data:
            user = response.data[0]

            return {
                "id": user["id"],
                "username": user["username"]
            }

        return None

    except Exception as e:
        print("Verify user error:", repr(e))
        raise


# ============================================================
# SAVE SINGLE SCAN
# ============================================================

def save_scan(target, results):
    try:
        scan_type = "tcp"

        if results:
            protocol = results[0].get(
                "protocol",
                "TCP"
            )
            scan_type = protocol.lower()

        scan_response = (
            supabase
            .table("scans")
            .insert({
                "target": target,
                "total_ports": len(results),
                "scan_type": scan_type
            })
            .select("id")
            .execute()
        )

        if not scan_response.data:
            raise RuntimeError(
                "Unable to create scan record"
            )

        scan_id = scan_response.data[0]["id"]

        if results:
            scan_results = []

            for result in results:
                scan_results.append({
                    "scan_id": scan_id,
                    "port": result["port"],
                    "protocol": result["protocol"],
                    "state": result["state"],
                    "service": result["service"],
                    "version": result["version"]
                })

            (
                supabase
                .table("scan_results")
                .insert(scan_results)
                .execute()
            )

        return scan_id

    except Exception as e:
        print("Save scan error:", repr(e))
        raise


# ============================================================
# SAVE MULTIPLE TARGET SCAN
# ============================================================

def save_multiple_scan(targets, results):
    try:
        target_text = ", ".join(targets)

        scan_type = "tcp"

        if results:
            protocol = results[0].get(
                "protocol",
                "TCP"
            )
            scan_type = protocol.lower()

        scan_response = (
            supabase
            .table("scans")
            .insert({
                "target": target_text,
                "total_ports": len(results),
                "scan_type": scan_type
            })
            .select("id")
            .execute()
        )

        if not scan_response.data:
            raise RuntimeError(
                "Unable to create scan record"
            )

        scan_id = scan_response.data[0]["id"]

        if results:
            scan_results = []

            for result in results:
                scan_results.append({
                    "scan_id": scan_id,
                    "port": result["port"],
                    "protocol": result["protocol"],
                    "state": result["state"],
                    "service": result["service"],
                    "version": result["version"]
                })

            (
                supabase
                .table("scan_results")
                .insert(scan_results)
                .execute()
            )

        return scan_id

    except Exception as e:
        print(
            "Save multiple scan error:",
            repr(e)
        )
        raise


# ============================================================
# SCAN HISTORY
# ============================================================

def get_scan_history():
    try:
        response = (
            supabase
            .table("scans")
            .select(
                "id, target, scan_date, "
                "total_ports, scan_type, duration"
            )
            .order(
                "id",
                desc=True
            )
            .execute()
        )

        history = []

        for row in response.data:
            history.append({
                "id": row.get("id"),
                "target": row.get("target"),
                "scan_date": row.get("scan_date"),
                "total_ports": row.get("total_ports"),
                "scan_type": row.get("scan_type"),
                "duration": row.get("duration")
            })

        return history

    except Exception as e:
        print(
            "Get scan history error:",
            repr(e)
        )
        raise