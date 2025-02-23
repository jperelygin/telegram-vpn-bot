import logging
import os
from credentials import Credentials


logger = logging.getLogger(__name__)


def generate_ovpn_key_locally(name):
    credentials = Credentials()

    os.system(f'cd /{credentials.get("OPENVPN_SERVER_PATH")}/easy-rsa '
              f'&& ./easyrsa --batch --days=3650 build-client-full "{name}" nopass')
    output_file = f'{credentials.get("OPENVPN_KEYS_FOLDER")}/{name}.ovpn'

    base_config_path = f"{credentials.get('OPENVPN_SERVER_PATH')}/client.conf"
    ca_cert_path = f"{credentials.get('OPENVPN_SERVER_PATH')}/easy-rsa/pki/ca.crt"
    client_cert_path = f"{credentials.get('OPENVPN_SERVER_PATH')}/easy-rsa/pki/issued/{name}.crt"
    client_key_path = f"{credentials.get('OPENVPN_SERVER_PATH')}/easy-rsa/pki/private/{name}.key"
    tls_auth_key_path = f"{credentials.get('OPENVPN_SERVER_PATH')}/tc.key"

    with open(output_file, "w") as ovpn_file:
        with open(base_config_path, "r") as base_config:
            ovpn_file.write(base_config.read())

        ovpn_file.write("<ca>\n")
        with open(ca_cert_path, "r") as ca_cert:
            ovpn_file.write(ca_cert.read())
        ovpn_file.write("</ca>\n")

        ovpn_file.write("<cert>\n")
        with open(client_cert_path, "r") as client_cert:
            text = client_cert.readlines()
            start_index = 0
            for index, line in enumerate(text):
                if "-----BEGIN CERTIFICATE-----" in line:
                    start_index = index
                    break
            certificate = "".join(text[start_index:])
            ovpn_file.write(certificate)
        ovpn_file.write("</cert>\n")

        ovpn_file.write("<key>\n")
        with open(client_key_path, "r") as client_key:
            ovpn_file.write(client_key.read())
        ovpn_file.write("</key>\n")

        ovpn_file.write("<tls-crypt>\n")
        with open(tls_auth_key_path, "r") as tls_crypt_key:
            ovpn_file.write(tls_crypt_key.read())
        ovpn_file.write("</tls-crypt>\n")

    logger.info(f"New {output_file} file generated.")
    return output_file
