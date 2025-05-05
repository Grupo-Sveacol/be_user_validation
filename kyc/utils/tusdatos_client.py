# kyc/utils/tusdatos_client.py
import requests
import base64
from django.conf import settings

def get_background_check(document_number: str,
                         date_of_issue: str,
                         full_name: str,
                         auth_header: str = None) -> dict:
    """
    Llama a TusDatos (/api/launch/verify), usando:
     - la Basic-Auth recibida en auth_header, o
     - la Basic-Auth de settings.TUSDATOS_PRUEBAS_* si no viene.
    """
    base = settings.TUSDATOS_PRUEBAS_BASE_URL.rstrip('/')
    url = f"{base}/api/launch/verify"
    payload = {
        "cedula": int(document_number),
        "fechaE": date_of_issue,   # 'dd/mm/YYYY'
        "nombre": full_name
    }
    headers = {"Content-Type": "application/json"}

    if auth_header:
        headers["Authorization"] = auth_header
    else:
        # Genera la cabecera Basic con usuario/clave de settings
        user = 'pruebas'
        pwd  = 'password'
        creds = f"{user}:{pwd}".encode()
        token = base64.b64encode(creds).decode()
        headers["Authorization"] = f"Basic {token}"

    resp = requests.post(url, headers=headers, json=payload, timeout=10)
    resp.raise_for_status()
    return resp.json()
