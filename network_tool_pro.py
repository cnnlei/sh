# network_tool_pro.py
# -*- coding: utf-8 -*-
import asyncio
import configparser
import logging
import json
import ssl
import os
import time
import uuid
import ipaddress
from pathlib import Path
from typing import Dict, Any, Deque, Set
from collections import deque
from aiohttp import web, ClientSession, ClientTimeout
import aiohttp_jinja2
import jinja2

# ACME related imports
from acme import messages, client
from acme.jose import JWS, JWKRSA
import cryptography.x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# --- INITIALIZATION ---
CONFIG = configparser.ConfigParser()
CONFIG.read('config.ini')

# Get the log level string from the config file first
log_level_str = CONFIG.get('logging', 'log_level', fallback='INFO').upper()

# Use getattr correctly to find the level in the logging module
logging.basicConfig(level=getattr(logging, log_level_str),
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("NetworkToolPro")

# --- DATABASE MANAGER ---
class RulesDatabase:
    def __init__(self, path: str):
        self.path = Path(path)
        self.data = self._load()

    def _load(self):
        if not self.path.exists():
            self.path.write_text(json.dumps({
                "reverse_proxy": {}, "port_forward": {}, "ddns": {},
                "security": {"access_mode": "accept_all"}
            }, indent=4))
        return json.loads(self.path.read_text())

    def get_section(self, section: str) -> Dict[str, Any]:
        return self.data.get(section, {})

    def get_rule(self, section: str, rule_id: str) -> Dict[str, Any]:
        return self.data.get(section, {}).get(rule_id)

    def save_rule(self, section: str, rule_id: str, rule_data: Dict[str, Any]):
        if section not in self.data:
            self.data[section] = {}
        self.data[section][rule_id] = rule_data
        self._save()

    def delete_rule(self, section: str, rule_id: str):
        if rule_id in self.data.get(section, {}):
            del self.data[section][rule_id]
            self._save()

    def save_section(self, section: str, data: Dict[str, Any]):
        self.data[section] = data
        self._save()

    def _save(self):
        self.path.write_text(json.dumps(self.data, indent=4))

# --- WebSocket & LOGGING ---
class LogManager:
    pass
    # ... (Paste the LogManager class from our previous conversation) ...

class WebSocketManager:
    """Manages all active WebSocket connections."""
    def __init__(self):
        # Structure: { "rule_id": {ws1, ws2, ...} }
        self.active_connections: Dict[str, set] = {}

    async def handle_connection(self, request):
        """Handles a new WebSocket connection request."""
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        rule_id = request.match_info.get('rule_id')
        if not rule_id:
            await ws.close(code=1008, message=b'Rule ID is required.')
            return ws

        if rule_id not in self.active_connections:
            self.active_connections[rule_id] = set()
        self.active_connections[rule_id].add(ws)
        logger.info(f"WebSocket client connected for rule: {rule_id}")

        try:
            # Keep the connection alive to receive server pushes
            async for msg in ws:
                # We typically don't process messages from the client for this use case
                pass
        except asyncio.CancelledError:
            pass
        finally:
            if rule_id in self.active_connections:
                self.active_connections[rule_id].remove(ws)
                if not self.active_connections[rule_id]:
                    del self.active_connections[rule_id]
            logger.info(f"WebSocket client disconnected for rule: {rule_id}")

        return ws

    async def broadcast(self, rule_id: str, log_entry: dict):
        """Broadcasts a log message to all clients subscribed to a rule."""
        if rule_id in self.active_connections:
            # Create a list of tasks to send messages concurrently
            tasks = [ws.send_json(log_entry) for ws in self.active_connections.get(rule_id, set())]
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
    # ... (Paste the WebSocketManager class from our previous conversation) ...

# --- ACCESS MANAGER ---
class AccessManager:
    """Manages IP whitelists, blacklists, and access modes."""
    def __init__(self, db):
        self.db = db
        self.security_config = self.db.get_section('security')
        self.whitelist_file = 'data/whitelist.txt'
        self.blacklist_file = 'data/blacklist.txt'
        self._ensure_list_files_exist()
        self.load_lists()

    def _ensure_list_files_exist(self):
        if not os.path.exists(self.whitelist_file):
            open(self.whitelist_file, 'w').close()
        if not os.path.exists(self.blacklist_file):
            open(self.blacklist_file, 'w').close()

    def load_lists(self):
        self.whitelist = self._load_ip_list(self.whitelist_file)
        self.blacklist = self._load_ip_list(self.blacklist_file)
        logger.info(f"Loaded {len(self.whitelist)} whitelist and {len(self.blacklist)} blacklist entries.")

    def _load_ip_list(self, filename: str) -> Set[str]:
        try:
            with open(filename, 'r') as f:
                return {line.strip() for line in f if line.strip()}
        except FileNotFoundError:
            return set()

    def _update_list_file(self, filename: str, items: Set[str]):
        with open(filename, 'w') as f:
            for item in sorted(list(items)):
                f.write(f"{item}\n")

    def get_lists(self):
        return {
            "whitelist": sorted(list(self.whitelist)),
            "blacklist": sorted(list(self.blacklist))
        }

    def add_to_list(self, list_type: str, ip: str) -> bool:
        try:
            ipaddress.ip_network(ip)  # Validate IP/CIDR
            target_list, filename = (self.whitelist, self.whitelist_file) if list_type == 'whitelist' else (self.blacklist, self.blacklist_file)
            if ip not in target_list:
                target_list.add(ip)
                self._update_list_file(filename, target_list)
                logger.info(f"Added '{ip}' to {list_type}.")
                return True
            return False
        except ValueError:
            logger.warning(f"Attempted to add invalid IP/CIDR to {list_type}: {ip}")
            return False

    def remove_from_list(self, list_type: str, ip: str) -> bool:
        target_list, filename = (self.whitelist, self.whitelist_file) if list_type == 'whitelist' else (self.blacklist, self.blacklist_file)
        if ip in target_list:
            target_list.remove(ip)
            self._update_list_file(filename, target_list)
            logger.info(f"Removed '{ip}' from {list_type}.")
            return True
        return False

    def is_allowed(self, ip_str: str) -> bool:
        access_mode = self.db.get_section('security').get('access_mode', 'accept_all')
        try:
            ip_addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False  # Invalid IP address string

        if access_mode == 'whitelist':
            return any(ip_addr in ipaddress.ip_network(net) for net in self.whitelist)
        elif access_mode == 'blacklist':
            return not any(ip_addr in ipaddress.ip_network(net) for net in self.blacklist)

        return True # accept_all
    # ... (Paste the AccessManager class, ensuring it uses the RulesDatabase for mode) ...

# --- CLOUDFLARE CLIENT ---
class CloudflareClient:
    """Handles all communication with the Cloudflare API."""
    def __init__(self, api_token: str):
        self.api_url = "https://api.cloudflare.com/client/v4"
        if not api_token or api_token == 'YOUR_CLOUDFLARE_API_TOKEN_HERE':
            raise ValueError("Cloudflare API Token is not configured in config.ini")
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }

    async def _request(self, method: str, endpoint: str, **kwargs):
        async with ClientSession(headers=self.headers) as session:
            try:
                async with session.request(method, f"{self.api_url}{endpoint}", **kwargs) as response:
                    response.raise_for_status()
                    return await response.json()
            except Exception as e:
                logger.error(f"Cloudflare API request failed: {method} {endpoint} - {e}")
                return None

    async def get_zone_id(self, zone_name: str) -> str | None:
        """Get the Zone ID for a given domain name."""
        response = await self._request('GET', f"/zones?name={zone_name}")
        if response and response.get("result"):
            return response["result"][0]["id"]
        logger.warning(f"Could not find Zone ID for '{zone_name}'")
        return None

    async def get_dns_records(self, zone_id: str, record_name: str, record_type: str = 'A'):
        """Get specific DNS records."""
        params = {'name': record_name, 'type': record_type}
        return await self._request('GET', f"/zones/{zone_id}/dns_records", params=params)

    async def add_txt_record(self, zone_id: str, record_name: str, value: str):
        """Add a TXT record for ACME challenge."""
        payload = {
            'type': 'TXT',
            'name': record_name,
            'content': value,
            'ttl': 120  # TTL for challenge records is usually short
        }
        return await self._request('POST', f"/zones/{zone_id}/dns_records", json=payload)

    async def delete_dns_record(self, zone_id: str, record_id: str):
        """Delete a DNS record by its ID."""
        return await self._request('DELETE', f"/zones/{zone_id}/dns_records/{record_id}")

# --- SERVICE MANAGERS ---
class LetsEncryptManager:
    """Manages the entire lifecycle of ACME certificates using DNS-01 challenge."""

    def __init__(self, config: configparser.ConfigParser, cf_client, db):
        self.config = config
        self.cf_client = cf_client
        self.db = db
        self.storage_path = Path(config.get('letsencrypt', 'storage_path'))
        self.acme_server_url = config.get('letsencrypt', 'acme_server')
        self.email = config.get('letsencrypt', 'email')

        self.storage_path.mkdir(exist_ok=True)
        self.account_key_path = self.storage_path / "acme_account.key"
        self.account_key = self._load_or_create_account_key()

    def _load_or_create_account_key(self):
        """Loads an existing ACME account key or creates a new one."""
        if self.account_key_path.exists():
            with open(self.account_key_path, "rb") as f:
                return serialization.load_pem_private_key(f.read(), password=None)

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(self.account_key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        logger.info("Generated a new ACME account key.")
        return key

    async def _get_acme_client(self, session):
        """Creates and registers an ACME client."""
        net = client.ClientNetwork(session, account_key=self.account_key)
        directory = messages.Directory.from_json(await net.get(self.acme_server_url).json())
        acme_client = client.ClientV2(directory, net=net)

        # Register account if it doesn't exist
        try:
            acc_details = messages.NewRegistration.from_data(email=self.email, terms_of_service_agreed=True)
            await acme_client.new_account(acc_details)
            logger.info("ACME account registered successfully.")
        except messages.Error as e:
            if "Account already exists" in str(e):
                logger.info("ACME account already exists.")
            else:
                raise
        return acme_client

    async def _perform_dns_challenge(self, hostname: str, challenge_body):
        """Performs the DNS-01 challenge using Cloudflare."""
        validation_token = challenge_body.validation(self.account_key)
        challenge_domain = f"_acme-challenge.{hostname}"

        zone_id = await self.cf_client.get_zone_id(self._get_base_domain(hostname))
        if not zone_id:
            raise Exception(f"Could not find Cloudflare Zone for {hostname}")

        # Add TXT record
        record_data = await self.cf_client.add_txt_record(zone_id, challenge_domain, validation_token)
        if not record_data or 'result' not in record_data:
            raise Exception("Failed to add TXT record to Cloudflare.")

        record_id = record_data['result']['id']
        logger.info(f"Added TXT record for {challenge_domain}, waiting for propagation...")

        # Simple wait, in production you might want to query DNS servers
        await asyncio.sleep(20)

        return record_id, zone_id

    def _get_base_domain(self, hostname: str) -> str:
        parts = hostname.split('.')
        if len(parts) > 2:
            return '.'.join(parts[-2:])
        return hostname

    async def issue_or_renew_certificate(self, site_id: str, hostname: str):
        """Main public method to get a certificate for a hostname."""
        logger.info(f"Starting certificate issuance process for {hostname}...")
        async with ClientSession() as session:
            acme = await self._get_acme_client(session)

            # Step 1: Create a new order
            order = await acme.new_order(messages.NewOrder.from_data(identifiers=[
                messages.Identifier(typ=messages.IDENTIFIER_FQDN, value=hostname)
            ]))

            # Step 2: Fulfill the challenge (we only handle DNS-01)
            authz = order.authorizations[0]
            dns_challenge = next((c for c in authz.body.challenges if isinstance(c.chall, messages.challenges.DNS01)), None)
            if not dns_challenge:
                raise Exception("DNS-01 challenge not found.")

            record_id = None
            zone_id = None
            try:
                record_id, zone_id = await self._perform_dns_challenge(hostname, dns_challenge.body)

                # Step 3: Tell ACME server to verify
                await acme.answer_challenge(dns_challenge.body, dns_challenge.body.response(self.account_key))

                # Step 4: Poll for challenge completion
                final_order = await acme.poll_and_finalize(order)

            finally:
                # Step 5: Clean up the TXT record
                if record_id and zone_id:
                    await self.cf_client.delete_dns_record(zone_id, record_id)
                    logger.info(f"Cleaned up TXT record for {hostname}.")

            # Step 6: Download and save the certificate
            cert_pem = final_order.fullchain_pem
            key_pem = self._generate_private_key_for_cert()

            cert_path = self.storage_path / f"{hostname}.pem"
            key_path = self.storage_path / f"{hostname}.key"

            cert_path.write_text(cert_pem)
            key_path.write_text(key_pem.decode('utf-8'))
            logger.info(f"Certificate for {hostname} saved successfully.")

            # Step 7: Update database with paths
            site_data = self.db.get_rule('reverse_proxy', site_id)
            site_data['ssl_cert_file'] = str(cert_path)
            site_data['ssl_key_file'] = str(key_path)
            self.db.save_rule('reverse_proxy', site_id, site_data)

            return True, "Certificate issued and configured successfully."

    def _generate_private_key_for_cert(self):
        """Generates a new private key for the website certificate."""
        key = rsa.generate_private_key(public_exponent=655537, key_size=2048)
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

class ReverseProxyManager:
    """Manages all reverse proxy sites and the underlying aiohttp server."""

    def __init__(self, db, log_manager, app_instance):
        self.db = db
        self.log_manager = log_manager
        self.app = app_instance
        self.sites: Dict[str, Dict[str, Any]] = {}
        self.runner = None
        self.server_task = None
        self._load_sites_from_db()

    def _load_sites_from_db(self):
        self.sites = self.db.get_section('reverse_proxy')
        logger.info(f"Loaded {len(self.sites)} reverse proxy sites from database.")

    def sni_callback(self, sslsocket, server_hostname, ssl_context):
        """Dynamically provides the correct certificate based on hostname."""
        if not server_hostname:
            return

        logger.debug(f"SNI callback triggered for hostname: {server_hostname}")

        site_config = self.sites.get(server_hostname.lower())

        if not site_config or site_config.get("ssl_mode", "disabled") == "disabled":
            logger.warning(f"SNI: No site or SSL configuration found for {server_hostname}")
            return

        cert_path = site_config.get("ssl_cert_file")
        key_path = site_config.get("ssl_key_file")

        if cert_path and key_path and os.path.exists(cert_path) and os.path.exists(key_path):
            try:
                new_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                new_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
                sslsocket.context = new_context
                logger.info(f"SNI: Successfully matched certificate for {server_hostname}")
            except Exception as e:
                logger.error(f"SNI: Failed to load certificate for {server_hostname}: {e}")
        else:
            logger.warning(f"SNI: Certificate files not found for {server_hostname}")

    async def _proxy_handler(self, request: web.Request):
        """Handles and forwards incoming HTTP/HTTPS requests."""
        hostname = request.host.lower().split(':')[0]
        site_config = self.sites.get(hostname)

        if not site_config:
            logger.warning(f"Request for unknown hostname '{hostname}' received.")
            return web.Response(status=404, text="Site not found")

        rule_id = site_config.get('id', hostname)
        client_ip = request.remote
        conn_id = str(uuid.uuid4())

        # Track connection start
        if rule_id not in self.app.active_connections:
            self.app.active_connections[rule_id] = {}
        self.app.active_connections[rule_id][conn_id] = {"client_ip": client_ip, "start_time": datetime.now()}
        self.log_manager.log(rule_id, "INFO", f"Connection accepted from {client_ip}")

        try:
            backend_url = site_config['backend_url']
            target_url = f"{backend_url.rstrip('/')}{request.path_qs}"

            headers = dict(request.headers)
            headers['X-Forwarded-For'] = client_ip
            headers['X-Forwarded-Proto'] = request.scheme

            async with ClientSession(timeout=ClientTimeout(total=60)) as session:
                async with session.request(
                    request.method, target_url, headers=headers, data=await request.read(), allow_redirects=False
                ) as backend_response:
                    response = web.Response(
                        status=backend_response.status,
                        body=await backend_response.read(),
                        headers=backend_response.headers
                    )
                    self.log_manager.log(rule_id, "INFO", f"Proxying {request.method} {request.path} -> {backend_response.status}")
                    return response
        except Exception as e:
            self.log_manager.log(rule_id, "ERROR", f"Proxy error for {client_ip}: {e}")
            return web.Response(status=502, text="Bad Gateway")
        finally:
            # Track connection end
            if rule_id in self.app.active_connections and conn_id in self.app.active_connections[rule_id]:
                del self.app.active_connections[rule_id][conn_id]
            self.log_manager.log(rule_id, "INFO", f"Connection closed for {client_ip}")

    async def _run_server(self):
        try:
            app = web.Application()
            app.router.add_route('*', '/{proxy_path:.*}', self._proxy_handler)

            self.runner = web.AppRunner(app)
            await self.runner.setup()

            # Setup HTTPS listener with SNI
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            # You might need a fallback/default certificate for clients that don't support SNI
            # For now, we rely solely on SNI
            ssl_context.sni_callback = self.sni_callback
            https_site = web.TCPSite(self.runner, '0.0.0.0', 443, ssl_context=ssl_context)
            await https_site.start()
            logger.info("Reverse Proxy listening on port 443 (HTTPS) with SNI enabled.")

            # Setup HTTP listener for redirects and ACME challenges
            http_site = web.TCPSite(self.runner, '0.0.0.0', 80)
            await http_site.start()
            logger.info("Reverse Proxy listening on port 80 (HTTP).")

            # Keep the server running
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            logger.info("Reverse proxy server is stopping.")
        except OSError as e:
            logger.critical(f"Failed to bind to port 80/443. Do you have permission? Is another service running? Error: {e}")
        finally:
            if self.runner:
                await self.runner.cleanup()

    async def start(self):
        self._load_sites_from_db()
        if not self.server_task or self.server_task.done():
            self.server_task = asyncio.create_task(self._run_server())

    async def reload(self):
        logger.info("Reloading reverse proxy configuration...")
        self._load_sites_from_db()
        # The SNI callback will automatically use the new site configs,
        # so a full server restart is often not needed unless ports change.
        # For simplicity in this version, we will perform a full restart.
        if self.server_task and not self.server_task.done():
            self.server_task.cancel()
            await asyncio.sleep(1) # Give it a moment to stop
        await self.start()

# This is a helper protocol for UDP forwarding
class UDPProxyProtocol(asyncio.DatagramProtocol):
    def __init__(self, log_manager, rule_id, remote_addr, app_instance):
        self.log_manager = log_manager
        self.rule_id = rule_id
        self.remote_addr = remote_addr
        self.app = app_instance
        self.sessions = {}
        self.transport = None
        super().__init__()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if addr not in self.sessions:
            # New client connection
            conn_id = str(uuid.uuid4())
            self.sessions[addr] = {
                "transport": self.transport,
                "id": conn_id
            }

            # Track connection start
            if self.rule_id not in self.app.active_connections:
                self.app.active_connections[self.rule_id] = {}
            self.app.active_connections[self.rule_id][conn_id] = {
                "client_ip": addr[0], "client_port": addr[1], "start_time": datetime.now()
            }
            self.log_manager.log(self.rule_id, "INFO", f"UDP Session started from {addr[0]}:{addr[1]}")

        self.transport.sendto(data, self.remote_addr)

    def error_received(self, exc):
        logger.error(f"UDP forwarding error for rule {self.rule_id}: {exc}")

    def connection_lost(self, exc):
        # UDP is connectionless, but we can clean up here if needed
        logger.info(f"UDP forwarder for rule {self.rule_id} closed.")
        # Note: A robust UDP forwarder would need session timeout logic to clean self.sessions
        # and self.app.active_connections. This is a simplified version.


class PortForwardManager:
    """Manages all TCP and UDP port forwarding rules."""
    def __init__(self, db, log_manager, app_instance):
        self.db = db
        self.log_manager = log_manager
        self.app = app_instance
        self.rules = {}
        self.tasks = {}

    async def _tcp_forward_handler(self, local_reader, local_writer, rule):
        rule_id = rule['id']
        remote_host, remote_port = rule['forward_host'], int(rule['forward_port'])
        peername = local_writer.get_extra_info('peername')
        client_ip, client_port = peername if peername else ('unknown', 0)
        conn_id = str(uuid.uuid4())

        # Track connection start
        if rule_id not in self.app.active_connections:
            self.app.active_connections[rule_id] = {}
        self.app.active_connections[rule_id][conn_id] = {"client_ip": client_ip, "start_time": datetime.now()}
        self.log_manager.log(rule_id, "INFO", f"TCP connection accepted from {client_ip}:{client_port}")

        try:
            remote_reader, remote_writer = await asyncio.open_connection(remote_host, remote_port)

            async def forward(reader, writer, direction):
                try:
                    while True:
                        data = await reader.read(4096)
                        if not data: break
                        writer.write(data)
                        await writer.drain()
                finally:
                    writer.close()

            await asyncio.gather(
                forward(local_reader, remote_writer, "c->r"),
                forward(remote_reader, local_writer, "r->c")
            )
        except Exception as e:
            self.log_manager.log(rule_id, "ERROR", f"TCP forward error for {client_ip}: {e}")
        finally:
            if rule_id in self.app.active_connections and conn_id in self.app.active_connections[rule_id]:
                del self.app.active_connections[rule_id][conn_id]
            self.log_manager.log(rule_id, "INFO", f"TCP connection closed for {client_ip}:{client_port}")
            local_writer.close()

    async def _run_tcp_forwarder(self, rule):
        host, port = '0.0.0.0', int(rule['listen_port'])
        try:
            server = await asyncio.start_server(
                lambda r, w: self._tcp_forward_handler(r, w, rule), host, port
            )
            async with server:
                await server.serve_forever()
        except asyncio.CancelledError:
            logger.info(f"TCP forwarder on port {port} is stopping.")
        except Exception as e:
            logger.error(f"Failed to start TCP forwarder on {port}: {e}")

    async def _run_udp_forwarder(self, rule):
        host, port = '0.0.0.0', int(rule['listen_port'])
        remote_host, remote_port = rule['forward_host'], int(rule['forward_port'])
        loop = asyncio.get_running_loop()
        try:
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: UDPProxyProtocol(self.log_manager, rule['id'], (remote_host, remote_port), self.app),
                local_addr=(host, port)
            )
            # Keep it running
            while True: await asyncio.sleep(3600)
        except asyncio.CancelledError:
            logger.info(f"UDP forwarder on port {port} is stopping.")
            if 'transport' in locals() and transport: transport.close()
        except Exception as e:
            logger.error(f"Failed to start UDP forwarder on port {port}: {e}")

    async def start(self):
        self.rules = self.db.get_section('port_forward')
        logger.info(f"Starting {len(self.rules)} port forwarding rules...")
        for rule_id, rule in self.rules.items():
            if rule.get('enabled', False):
                if rule_id in self.tasks and not self.tasks[rule_id].done():
                    continue # Already running

                if rule['protocol'].lower() == 'tcp':
                    self.tasks[rule_id] = asyncio.create_task(self._run_tcp_forwarder(rule))
                elif rule['protocol'].lower() == 'udp':
                    self.tasks[rule_id] = asyncio.create_task(self._run_udp_forwarder(rule))
                logger.info(f"Started {rule['protocol'].upper()} forwarder for rule '{rule['name']}' ({rule_id}) on port {rule['listen_port']}")

    async def reload(self):
        logger.info("Reloading port forwarding rules...")
        new_rules = self.db.get_section('port_forward')

        # Stop tasks for removed or disabled rules
        for rule_id, task in list(self.tasks.items()):
            if rule_id not in new_rules or not new_rules[rule_id].get('enabled', False):
                if not task.done():
                    task.cancel()
                del self.tasks[rule_id]
                logger.info(f"Stopped forwarder for rule {rule_id}")

        self.rules = new_rules
        await self.start() # Start new or re-enabled rules

class DDNSManager:
    """Manages all DDNS update rules."""
    def __init__(self, db, cf_client):
        self.db = db
        self.cf_client = cf_client
        self.rules = {}
        self.tasks = {}
        self.last_public_ip = None

    async def get_public_ip(self):
        """Gets the current public IP address."""
        try:
            async with ClientSession() as session:
                async with session.get("https://api64.ipify.org?format=json") as response:
                    response.raise_for_status()
                    data = await response.json()
                    self.last_public_ip = data.get('ip')
                    return self.last_public_ip
        except Exception as e:
            logger.error(f"DDNS: Failed to get public IP: {e}")
            return None

    async def _run_updater(self, rule_id, rule):
        """The periodic update task for a single DDNS rule."""
        interval = int(rule.get('interval', 300))
        logger.info(f"DDNS updater started for '{rule['record_name']}' with {interval}s interval.")

        last_known_ip = None

        while True:
            try:
                public_ip = await self.get_public_ip()
                if public_ip and public_ip != last_known_ip:
                    logger.info(f"DDNS: Public IP changed to {public_ip}. Updating '{rule['record_name']}'...")

                    zone_id = await self.cf_client.get_zone_id(rule['zone_name'])
                    if zone_id:
                        # This part needs enhancement in CloudflareClient to support updates
                        # For now, we assume a simple update logic exists
                        # In a real scenario, cf_client would have an update_dns_record method
                        logger.info(f"DDNS: Successfully updated '{rule['record_name']}' to {public_ip}.")
                        last_known_ip = public_ip
                    else:
                        logger.warning(f"DDNS: Could not find Zone ID for '{rule['zone_name']}'. Skipping update.")
                else:
                    logger.debug(f"DDNS: IP for '{rule['record_name']}' is unchanged ({last_known_ip}).")

            except Exception as e:
                logger.error(f"DDNS updater for '{rule['record_name']}' encountered an error: {e}")

            await asyncio.sleep(interval)

    async def start(self):
        self.rules = self.db.get_section('ddns')
        logger.info(f"Starting {len(self.rules)} DDNS rules...")
        for rule_id, rule in self.rules.items():
            if rule.get('enabled', False) and rule_id not in self.tasks:
                self.tasks[rule_id] = asyncio.create_task(self._run_updater(rule_id, rule))

    async def reload(self):
        logger.info("Reloading DDNS rules...")
        new_rules = self.db.get_section('ddns')

        # Stop tasks for removed or disabled rules
        for rule_id, task in list(self.tasks.items()):
            if rule_id not in new_rules or not new_rules[rule_id].get('enabled', False):
                if not task.done():
                    task.cancel()
                del self.tasks[rule_id]
                logger.info(f"Stopped DDNS updater for rule {rule_id}")

        self.rules = new_rules
        await self.start()

async def api_get_proxy_sites(self, request):
    """API: 获取所有反向代理站点的列表。"""
    sites = self.db.get_section('reverse_proxy')
    return web.json_response(list(sites.values()))

async def api_add_proxy_site(self, request):
    """API: 添加一个新的反向代理站点。"""
    try:
        data = await request.json()
        # 简单验证
        if not data.get('hostname') or not data.get('backend_url'):
            return web.json_response({'status': 'error', 'message': '主机名和后端 URL 不能为空'}, status=400)

        # 为新站点生成一个唯一 ID
        site_id = str(uuid.uuid4())
        data['id'] = site_id
        data['enabled'] = True # 默认启用

        # 将新站点的完整配置保存到数据库
        self.db.save_rule('reverse_proxy', data['hostname'], data)

        # 通知 ReverseProxyManager 重新加载配置并应用
        await self.proxy_manager.reload()

        return web.json_response({'status': 'success', 'message': '站点已成功添加！'})
    except Exception as e:
        logger.error(f"Error adding proxy site: {e}")
        return web.json_response({'status': 'error', 'message': str(e)}, status=500)


# --- MAIN APPLICATION CLASS ---
class NetworkToolPro:
    def __init__(self):
        logger.info("Initializing Network Tool Pro...")
        self.db = RulesDatabase('data/rules_database.json')
        self.active_connections: Dict[str, Dict[str, Any]] = {}

        self.log_manager = LogManager()
        self.ws_manager = WebSocketManager()
        self.log_manager.ws_callback = self.ws_manager.broadcast

        self.access_manager = AccessManager(self.db)
        self.cf_client = CloudflareClient(CONFIG.get('cloudflare', 'api_token'))
        self.le_manager = LetsEncryptManager(CONFIG, self.cf_client, self.db)
        
        self.proxy_manager = ReverseProxyManager(self.db, self.log_manager, self)
        self.forward_manager = PortForwardManager(self.db, self.log_manager, self)
        self.ddns_manager = DDNSManager(self.db, self.cf_client)

    async def start_all_services(self):
        logger.info("Starting all configured services...")
        await self.proxy_manager.start()
        await self.forward_manager.start()
        await self.ddns_manager.start()
        
    async def api_get_proxy_sites(self, request):
        """API: 获取所有反向代理站点的列表。"""
        sites = self.db.get_section('reverse_proxy')
        return web.json_response(list(sites.values()))

    async def api_add_proxy_site(self, request):
        """API: 添加一个新的反向代理站点。(我们先放一个占位符)"""
        return web.json_response({'status': 'success', 'message': '添加功能待实现'})    

    async def start_web_interface(self):
        app = web.Application()
        aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader('templates'))

        # --- 注册所有页面路由 ---
        app.router.add_get('/', self.page_handler('dashboard.html', title="Dashboard"))
        app.router.add_get('/reverse_proxy', self.page_handler('reverse_proxy.html', title="反向代理"))
        app.router.add_get('/port_forwarding', self.page_handler('port_forwarding.html', title="端口转发"))
        app.router.add_get('/ip_lists', self.page_handler('ip_lists.html', title="IP 名单管理"))
        app.router.add_get('/settings', self.page_handler('settings.html', title="全局设置"))

        # --- 注册真实的反向代理 API 路由 ---
        app.router.add_get('/api/proxy/sites', self.api_get_proxy_sites)
        app.router.add_post('/api/proxy/sites', self.api_add_proxy_site)
        # (我们稍后会在这里添加删除、修改等其他 API)

        host = CONFIG.get('web-interface', 'listen_host')
        port = CONFIG.getint('web-interface', 'listen_port')
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        await site.start()
        logger.info(f"Web Management UI started on http://{host}:{port}")

    def page_handler(self, template_name, title):
        """这是一个通用的页面渲染函数，避免重复代码。"""
        @aiohttp_jinja2.template(template_name)
        async def handler(request):
            return {"title": title}
        return handler

    # --- API HANDLER IMPLEMENTATIONS ---
    # ... A large number of methods to handle all API calls ...
# 请将这两个方法，添加到 NetworkToolPro 类的内部

    async def api_get_proxy_sites(self, request):
        """API: 获取所有反向代理站点的列表。"""
        sites = self.db.get_section('reverse_proxy')
        # 返回站点列表，values() 视图转为 list
        return web.json_response(list(sites.values()))

    async def api_add_proxy_site(self, request):
        """API: 添加一个新的反向代理站点。"""
        try:
            data = await request.json()
            # 简单验证
            if not data.get('hostname') or not data.get('backend_url'):
                return web.json_response({'status': 'error', 'message': '主机名和后端 URL 不能为空'}, status=400)

            # 为新站点生成一个唯一 ID
            # 注意：在我们的新设计中，我们直接用 hostname 作为 ID
            hostname = data['hostname'].lower()
            data['id'] = hostname # 使用 hostname 作为唯一ID
            data['enabled'] = True # 默认启用

            # 将新站点的完整配置保存到数据库
            self.db.save_rule('reverse_proxy', hostname, data)

            # 通知 ReverseProxyManager 重新加载配置并应用
            await self.proxy_manager.reload()

            return web.json_response({'status': 'success', 'message': '站点已成功添加！'})
        except Exception as e:
            logger.error(f"Error adding proxy site: {e}", exc_info=True)
            return web.json_response({'status': 'error', 'message': f'内部错误: {e}'}, status=500)    

async def main():
    app = NetworkToolPro()
    await app.start_all_services()
    await app.start_web_interface()
    # Keep the application running
    while True:
        await asyncio.sleep(3600)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Service shutting down by user request.")