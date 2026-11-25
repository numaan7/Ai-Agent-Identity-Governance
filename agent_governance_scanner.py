import os
import json
from datetime import datetime, timezone
import requests
from dotenv import load_dotenv

load_dotenv()

TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")

HIGH_RISK_ROLES = {
    "User.ReadWrite.All",
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "Mail.ReadWrite",
}

def get_graph_token() -> str:
    missing = [
        name
        for name, value in (
            ("TENANT_ID", TENANT_ID),
            ("CLIENT_ID", CLIENT_ID),
            ("CLIENT_SECRET", CLIENT_SECRET),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(
            f"Missing required environment variable(s): {', '.join(missing)}. "
            "Set them in the environment or in a .env file next to this script."
        )

    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    }
    resp = requests.post(url, data=payload, timeout=15)
    resp.raise_for_status()
    return resp.json()["access_token"]

def graph_get(endpoint: str, token: str) -> list:
    headers = {"Authorization": f"Bearer {token}"}
    results = []
    url = f"https://graph.microsoft.com/v1.0{endpoint}"
    while url:
        resp = requests.get(url, headers=headers, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        results.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
    return results

def get_graph_role_map(token: str) -> dict:
    """Maps Microsoft Graph App Role GUIDs to human-readable permission names (e.g., User.ReadWrite.All)."""
    sps = graph_get("/servicePrincipals?$filter=appId eq '00000003-0000-0000-c000-000000000000'", token)
    if not sps:
        return {}
    return {role["id"]: role["value"] for role in sps[0].get("appRoles", [])}

def audit_workload_identities():
    token = get_graph_token()
    now = datetime.now(timezone.utc)
    role_map = get_graph_role_map(token)

    apps = graph_get("/applications?$select=id,appId,displayName,passwordCredentials,keyCredentials", token)
    risky_sps = {
        item["id"]: item
        for item in graph_get("/identityProtection/riskyServicePrincipals", token)
    }

    findings = []

    for app in apps:
        app_id = app["appId"]
        name = app["displayName"]

        # 1. Check Application Owners (Orphan Detection)
        owners = graph_get(f"/applications/{app['id']}/owners?$select=id,userPrincipalName", token)
        owner_upns = [o.get("userPrincipalName", o["id"]) for o in owners]

        # 2. Check Secret & Certificate Hygiene
        credential_alerts = []
        for credential_type, credentials in (
            ("Secret", app.get("passwordCredentials", [])),
            ("Certificate", app.get("keyCredentials", [])),
        ):
            for cred in credentials:
                end_dt = datetime.fromisoformat(
                    cred["endDateTime"].replace("Z", "+00:00")
                )
                days_left = (end_dt - now).days
                if days_left <= 90:
                    credential_alerts.append(
                        f"{credential_type} '{cred.get('displayName')}' "
                        f"expires in {days_left} days"
                    )

        # 3. Resolve Service Principal, App Role Permissions & P2 Risk State
        sps = graph_get(f"/servicePrincipals?$filter=appId eq '{app_id}'", token)
        granted_perms = []
        p2_risk_level = "none"

        if sps:
            sp_id = sps[0]["id"]
            if sp_id in risky_sps:
                p2_risk_level = risky_sps[sp_id].get("riskLevel", "unknown")

            assignments = graph_get(f"/servicePrincipals/{sp_id}/appRoleAssignments", token)
            for a in assignments:
                perm_name = role_map.get(a["appRoleId"], a["appRoleId"])
                granted_perms.append(perm_name)

        # 4. Compute Governance Risk Score
        risk_reasons = []
        if len(owner_upns) == 0:
            risk_reasons.append("ORPHANED_NO_OWNER")
        over_priv = [p for p in granted_perms if p in HIGH_RISK_ROLES]
        if over_priv:
            risk_reasons.append(f"EXCESSIVE_PRIVILEGE({','.join(over_priv)})")
        if credential_alerts:
            risk_reasons.append("SHORT_LIVED_OR_EXPIRING_SECRET")
        if p2_risk_level not in ("none", "low"):
            risk_reasons.append(f"ENTRA_P2_RISK_{p2_risk_level.upper()}")

        severity = "CRITICAL" if len(risk_reasons) >= 2 else ("MEDIUM" if risk_reasons else "COMPLIANT")

        findings.append({
            "displayName": name,
            "appId": app_id,
            "severity": severity,
            "owners": owner_upns,
            "grantedApplicationPermissions": granted_perms,
            "credentialAlerts": credential_alerts,
            "entraP2RiskLevel": p2_risk_level,
            "riskFlags": risk_reasons,
        })

    report = {
        "generatedAtUTC": now.isoformat(),
        "tenantId": TENANT_ID,
        "totalApplicationsAudited": len(findings),
        "criticalCount": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "findings": findings,
    }

    with open("nhi_governance_audit_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[+] Audit complete! Audited {len(findings)} apps. Critical findings: {report['criticalCount']}")
    for item in findings:
        print(f" - {item['displayName']}: [{item['severity']}] Flags={item['riskFlags']}")

if __name__ == "__main__":
    audit_workload_identities()