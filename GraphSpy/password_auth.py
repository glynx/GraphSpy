import jwt
import requests
from datetime import datetime

from . import GraphSpy as core


def save_entra_credential(username, password, description="", tenant_id=""):
    con = core.get_db()
    cur = con.cursor()
    cur.execute(
        "INSERT INTO entra_credentials (stored_at, description, username, tenant_id, password) VALUES (?,?,?,?,?)",
        (
            f"{datetime.now()}".split(".")[0],
            description,
            username,
            tenant_id,
            password
        )
    )
    con.commit()
    return cur.lastrowid


def entra_credentials_to_tokens(
    username,
    password,
    client_id=None,
    resource="https://graph.microsoft.com",
    description="",
    tenant_id="common",
    store_refresh_token=False
):
    tenant = tenant_id if tenant_id else "common"
    resolved_client_id = client_id if client_id else core.DEFAULT_CLIENT_ID
    body = {
        "client_id": resolved_client_id,
        "grant_type": "password",
        "username": username,
        "password": password,
        "resource": resource
    }
    url = f"https://login.microsoftonline.com/{tenant}/oauth2/token"
    headers = {"User-Agent": core.get_user_agent()}
    response = requests.post(url, data=body, headers=headers)
    try:
        response_json = response.json()
    except ValueError:
        response_json = {}
    if response.status_code != 200 or "access_token" not in response_json:
        error_message = response_json["error_description"] if "error_description" in response_json else response_json["error"] if "error" in response_json else response.text
        raise ValueError(error_message.strip() if error_message else "Failed to obtain tokens using the provided credentials.")
    token_description = description if description else f"Created using credentials for {username}"
    access_token_id = core.save_access_token(response_json["access_token"], token_description)
    refresh_token_id = None
    foci_value = response_json["foci"] if "foci" in response_json else None
    if store_refresh_token and "refresh_token" in response_json:
        try:
            decoded_accesstoken = jwt.decode(response_json["access_token"], options={"verify_signature": False})
        except Exception:
            decoded_accesstoken = {}
        inferred_user = decoded_accesstoken["unique_name"] if "unique_name" in decoded_accesstoken else decoded_accesstoken["upn"] if "upn" in decoded_accesstoken else decoded_accesstoken["app_displayname"] if "app_displayname" in decoded_accesstoken else username
        inferred_tenant = decoded_accesstoken["tid"] if "tid" in decoded_accesstoken else tenant
        refresh_token_id = core.save_refresh_token(
            response_json["refresh_token"],
            token_description,
            inferred_user,
            inferred_tenant,
            response_json["resource"] if "resource" in response_json else resource,
            foci_value if foci_value else 0
        )
    return {
        "access_token_id": access_token_id,
        "refresh_token_id": refresh_token_id,
        "foci": foci_value
    }
