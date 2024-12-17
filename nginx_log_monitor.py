import os
import time
import requests
import re
import json
import yaml
import logging
import ipaddress
from datetime import datetime
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Union

# Configuración mejorada del registro
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/nginx-monitor/monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Gestión de la configuración
class ConfigManager:
    """Manages configuration loading from multiple sources"""
    def __init__(self, config_path: str = '/etc/nginx-monitor/config.yaml'):
        self.config = self.load_config(config_path)
    
    def load_config(self, config_path: str) -> Dict:
        """Load configuration from YAML file with fallback to environment variables"""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning(f"Config file {config_path} not found. Using environment variables.")
            config = {}
        
        # Override with environment variables
        config['DISCORD_WEBHOOK_URL'] = os.environ.get(
            'DISCORD_WEBHOOK_URL', 
            config.get('DISCORD_WEBHOOK_URL', '')
        )
        config['IPINFO_TOKEN'] = os.environ.get(
            'IPINFO_TOKEN', 
            config.get('IPINFO_TOKEN', '')
        )
        
        # Default configurations
        config.setdefault('LOG_FILE', '/var/log/nginx/access.log')
        config.setdefault('IGNORED_IPS', [])
        config.setdefault('WHITELISTED_IPS', [])
        config.setdefault('MAX_THREADS', 5)
        config.setdefault('RISK_THRESHOLDS', {
            'high_status_codes': [500, 403, 401],
            'suspicious_user_agents': ['python-requests', 'curl', 'wget']
        })
        
        return config

# IP Filtering and Validation
# Modificación de la clase IPFilter
class IPFilter:
    def __init__(self, config: Dict):
        self.ignored_ips = self._parse_ip_list(config.get('IGNORED_IPS', []))
    
    def _parse_ip_list(self, ip_list: List[str]) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv4Address]]:
        """
        Convert IP strings to network or address objects for precise matching
        
        Args:
            ip_list (List[str]): List of IP addresses or networks
        
        Returns:
            List[Union[IPv4Network, IPv4Address]]: Parsed IP objects
        """
        parsed_ips = []
        for ip in ip_list:
            try:
                # Attempt to parse as network first
                parsed_ips.append(ipaddress.ip_network(ip, strict=False))
            except ValueError:
                try:
                    # If not a network, try parsing as individual IP
                    parsed_ips.append(ipaddress.ip_address(ip))
                except ValueError:
                    logger.warning(f"Invalid IP/Network: {ip}")
        return parsed_ips
    
    def is_ip_allowed(self, ip: str) -> bool:
        """
        Comprehensive IP filtering with precise exclusion
        
        Args:
            ip (str): IP address to check
        
        Returns:
            bool: True if IP should be processed, False if it should be ignored
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check if IP matches any ignored IP or network
            return not any(
                # Handle both IPv4Network and IPv4Address checks
                (isinstance(ignored_ip, ipaddress.IPv4Network) and ip_obj in ignored_ip) or 
                (isinstance(ignored_ip, ipaddress.IPv4Address) and ip_obj == ignored_ip)
                for ignored_ip in self.ignored_ips
            )
        
        except ValueError:
            logger.error(f"Invalid IP address: {ip}")
            return False

# Enhanced IP Information Retrieval
class IPInfoResolver:
    def __init__(self, config: Dict):
        self.token = config.get('IPINFO_TOKEN')
        self.base_url = 'https://ipinfo.io'
        self.session = requests.Session()
        self.session.headers.update({
            'Accept': 'application/json',
            'User-Agent': 'NginxLogMonitor/1.0'
        })
    
    @lru_cache(maxsize=1000)
    def get_ip_info(self, ip_address: str, max_retries: int = 3) -> Optional[Dict]:
        """
        Retrieve IP information with retry mechanism and caching
        
        Args:
            ip_address (str): IP to lookup
            max_retries (int): Number of retry attempts
        
        Returns:
            Optional[Dict]: IP information or None
        """
        for attempt in range(max_retries):
            try:
                response = self.session.get(
                    f'{self.base_url}/{ip_address}/json',
                    params={'token': self.token},
                    timeout=5
                )
                response.raise_for_status()
                
                ip_data = response.json()
                return {
                    'country': ip_data.get('country', 'Unknown'),
                    'region': ip_data.get('region', 'Unknown'),
                    'city': ip_data.get('city', 'Unknown'),
                    'location': ip_data.get('loc', 'Unknown'),
                    'org': ip_data.get('org', 'Unknown'),
                    'postal': ip_data.get('postal', 'Unknown'),
                    'timezone': ip_data.get('timezone', 'Unknown'),
                    'risk_score': self._calculate_ip_risk(ip_data)
                }
            except requests.RequestException as e:
                logger.warning(f"IP info retrieval failed (Attempt {attempt + 1}): {e}")
                time.sleep(1)  # Wait before retry
        
        return None
    
    def _calculate_ip_risk(self, ip_data: Dict) -> int:
        """
        Calculate a basic risk score for an IP
        
        Args:
            ip_data (Dict): IP information from IPinfo
        
        Returns:
            int: Risk score (0-100)
        """
        risk_score = 0
        
        # Increase risk for hosting providers, cloud services
        if any(provider in ip_data.get('org', '').lower() for provider in [
            'amazon', 'google', 'microsoft', 'digitalocean', 'linode'
        ]):
            risk_score += 20
        
        # Increase risk for certain countries
        high_risk_countries = ['CN', 'RU', 'IR', 'KP']
        if ip_data.get('country') in high_risk_countries:
            risk_score += 30
        
        return min(risk_score, 100)

# Enhanced Log Parsing
class LogParser:
    NGINX_PATTERNS = [
        # Standard Nginx log format
        r'^(\d+\.\d+\.\d+\.\d+) - (.*?) \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"$',
        # Alternative formats with variations
        r'^(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"$'
    ]
    
    @classmethod
    def parse_log_line(cls, line: str) -> Optional[Dict]:
        """
        Robust log line parsing with multiple format support
        
        Args:
            line (str): Log line to parse
        
        Returns:
            Optional[Dict]: Parsed log data or None
        """
        for pattern in cls.NGINX_PATTERNS:
            match = re.match(pattern, line.strip())
            if match:
                try:
                    groups = match.groups()
                    return {
                        'ip': groups[0],
                        'timestamp': datetime.strptime(groups[2], '%d/%b/%Y:%H:%M:%S %z'),
                        'request': groups[3],
                        'status_code': int(groups[4]),
                        'body_bytes': int(groups[5]),
                        'referrer': groups[6],
                        'user_agent': groups[7],
                        'request_method': cls._extract_request_method(groups[3])
                    }
                except (ValueError, IndexError) as e:
                    logger.error(f"Log parsing error: {e}")
                    return None
        
        logger.warning(f"Unrecognized log format: {line}")
        return None
    
    @staticmethod
    def _extract_request_method(request: str) -> str:
        """
        Extract HTTP method from request string
        
        Args:
            request (str): Full request string
        
        Returns:
            str: HTTP method
        """
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']
        for method in methods:
            if request.startswith(method):
                return method
        return 'UNKNOWN'

# Discord Notification System
class DiscordNotifier:
    def __init__(self, config):
        """
        Inicializa el notificador de Discord
        
        Args:
            config (dict): Configuración con URL de webhook
        """
        self.webhook_url = config.get('DISCORD_WEBHOOK_URL', '')
        self.token_ipinfo = config.get('IPINFO_TOKEN', '')

    def create_discord_embed(self, log_data: Dict, ip_info: Dict) -> Dict:
        """
        Crea un embed de Discord con información detallada del log e IP

        Args:
            log_data (dict): Datos parseados del log
            ip_info (dict): Información de geolocalización de la IP
        
        Returns:
            dict: Payload para el webhook de Discord
        """
        # Calcular riesgo de la IP
        risk_score = ip_info.get('risk_score', 0)
        
        # Determinar color del embed basado en riesgo y código de estado
        embed_color = self._get_embed_color(log_data, ip_info)
        
        embed = {
            "title": f"🚨 Actividad de Red Detectada: {self._get_activity_type(log_data)}",
            "description": f"**Resumen de Actividad Potencialmente Sospechosa**\n*Monitoreo Continuo de Seguridad de Nginx*",
            "color": embed_color,
            "fields": [
                # Información de Ubicación
                {
                    "name": "🌐 Información de Ubicación",
                    "value": (
                        f"**País:** {ip_info.get('country', 'Desconocido')}\n"
                        f"**Ciudad:** {ip_info.get('city', 'Desconocido')}\n"
                        f"**Organización:** {ip_info.get('org', 'Desconocido')}\n"
                        f"**Zona Horaria:** {ip_info.get('timezone', 'Desconocido')}"
                    ),
                    "inline": False
                },
                # Detalles de la Solicitud
                {
                    "name": "📡 Detalles de la Solicitud",
                    "value": (
                        f"**Dirección IP:** `{log_data['ip']}`\n"
                        f"**Método:** `{log_data['request_method']}`\n"
                        f"**Código de Estado:** `{log_data['status_code']}`\n"
                        f"**Tamaño de Respuesta:** `{log_data['body_bytes']} bytes`"
                    ),
                    "inline": False
                },
                # Información de Riesgo
                {
                    "name": "🚨 Evaluación de Riesgo",
                    "value": (
                        f"**Nivel de Riesgo de IP:** {risk_score}/100\n"
                        f"**Análisis:** {self._get_risk_description(risk_score)}"
                    ),
                    "inline": False
                },
                # Detalles Técnicos
                {
                    "name": "🔍 Detalles Técnicos",
                    "value": (
                        f"**User Agent:** `{log_data['user_agent']}`\n"
                        f"**Solicitud Completa:** `{log_data['request']}`"
                    ),
                    "inline": False
                }
            ],
            "footer": {
                "text": f"Monitoreo de Seguridad | {log_data['timestamp'].strftime('%d/%m/%Y %H:%M:%S')}",
                "icon_url": "https://cdn.icon-icons.com/icons2/1749/PNG/512/20_113668.png"
            }
        }
        
        return {"embeds": [embed]}

    def _get_risk_description(self, risk_score: int) -> str:
        """
        Obtiene una descripción descriptiva del riesgo
        
        Args:
            risk_score (int): Puntaje de riesgo de IP
        
        Returns:
            str: Descripción del riesgo
        """
        if risk_score < 30:
            return "🟢 Bajo Riesgo: Sin indicadores significativos de amenaza"
        elif risk_score < 60:
            return "🟠 Riesgo Moderado: Algunos indicadores de precaución"
        else:
            return "🔴 Alto Riesgo: Múltiples indicadores de posible amenaza"

    def _calcular_riesgo_ip(self, ip_info):
        """
        Calcula un puntaje de riesgo básico para la IP
        
        Args:
            ip_info (dict): Información de la IP
        
        Returns:
            int: Puntaje de riesgo (0-100)
        """
        riesgo = 0
        
        # Incrementar riesgo para proveedores de hosting conocidos
        proveedores_riesgo = [
            'amazon', 'google', 'microsoft', 'digitalocean', 
            'linode', 'aws', 'azure', 'cloud'
        ]
        
        if any(proveedor in ip_info.get('org', '').lower() for proveedor in proveedores_riesgo):
            riesgo += 30

        # Incrementar riesgo para ciertos países
        paises_riesgo = ['CN', 'RU', 'IR', 'KP', 'US']
        if ip_info.get('country') in paises_riesgo:
            riesgo += 40
        
        return min(riesgo, 100)

    def _get_activity_type(self, log_data: Dict) -> str:
        """
        Determina el tipo de actividad
        
        Args:
            log_data (Dict): Datos de log parseados
        
        Returns:
            str: Descripción del tipo de actividad
        """
        if log_data['status_code'] >= 400:
            return "⚠️ Error/Ataque Potencial"
        
        return f"🌐 Solicitud {log_data['request_method']}"

    def _get_embed_color(self, log_data: Dict, ip_info: Dict) -> int:
        """
        Determinar color del embed basado en riesgo y estado
        
        Args:
            log_data (Dict): Datos de log parseados
            ip_info (Dict): Información de IP
        
        Returns:
            int: Color en hexadecimal
        """
        risk_score = ip_info.get('risk_score', 0)
        
        if log_data['status_code'] >= 400:
            return 0xFF0000  # Rojo para errores
        
        if risk_score > 70:
            return 0xFF4500  # Rojo-naranja para riesgo alto
        
        if risk_score > 30:
            return 0xFFA500  # Naranja para riesgo medio
        
        return 0x00FF00  # Verde para riesgo bajo

    def send_notification(self, payload: Dict):
        """
        Envía la notificación al webhook de Discord
        
        Args:
            payload (dict): Payload a enviar
        """
        headers = {"Content-Type": "application/json"}
        try:
            response = requests.post(
                self.webhook_url, 
                json=payload, 
                headers=headers,
                timeout=5
            )
            
            if response.status_code == 204:
                logging.info("Notificación enviada a Discord correctamente.")
            else:
                logging.error(f"Error al enviar notificación: {response.status_code}, {response.text}")
        
        except requests.RequestException as e:
            logging.error(f"Excepción al enviar a Discord: {e}")

# Main Log Monitoring Class
class LogMonitor:
    def __init__(self, config_path: str = '/etc/nginx-monitor/config.yaml'):
        self.config_manager = ConfigManager(config_path)
        self.config = self.config_manager.config
        
        self.ip_filter = IPFilter(self.config)
        self.ip_resolver = IPInfoResolver(self.config)
        self.discord_notifier = DiscordNotifier(self.config)
        
        self.log_file = self.config.get('LOG_FILE', '/var/log/nginx/access.log')
        self.max_threads = self.config.get('MAX_THREADS', 5)
    
    def process_log_batch(self, log_lines: List[str]):
        """
        Process a batch of log lines concurrently
        
        Args:
            log_lines (List[str]): Batch of log lines to process
        """
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {}
            for line in log_lines:
                log_data = LogParser.parse_log_line(line)
                if log_data and self.ip_filter.is_ip_allowed(log_data['ip']):
                    futures[executor.submit(self._process_single_log, log_data)] = log_data
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error processing log: {e}")
    
    def _process_single_log(self, log_data: Dict):
        """
        Process a single log entry
        
        Args:
            log_data (Dict): Parsed log data
        """
        ip_info = self.ip_resolver.get_ip_info(log_data['ip'])
        if ip_info:
            payload = self.discord_notifier.create_discord_embed(log_data, ip_info)
            self.discord_notifier.send_notification(payload)
    
    def monitor(self):
        """
        Continuously monitor the log file for new entries
        """
        logger.info("Starting log monitoring...")
        
        try:
            with open(self.log_file, 'r') as f:
                # Move to the end of the file
                f.seek(0, 2)
                
                batch = []
                while True:
                    line = f.readline()
                    if not line:
                        # Process any remaining lines in the batch
                        if batch:
                            self.process_log_batch(batch)
                            batch.clear()
                        
                        # Wait a bit before checking for new lines
                        time.sleep(1)
                        continue
                    
                    # Add line to batch
                    batch.append(line.strip())
                    
                    # Process batch when it reaches a certain size
                    if len(batch) >= 10:
                        self.process_log_batch(batch)
                        batch.clear()
        
        except FileNotFoundError:
            logger.error(f"Log file not found: {self.log_file}")
        except PermissionError:
            logger.error(f"Permission denied reading log file: {self.log_file}")
        except Exception as e:
            logger.error(f"Unexpected error in log monitoring: {e}")

def main():
    """
    Main entry point for the Nginx Log Monitor
    """
    try:
        # Ensure log directory exists
        os.makedirs('/var/log/nginx-monitor', exist_ok=True)
        
        # Initialize and start monitoring
        monitor = LogMonitor()
        monitor.monitor()
    
    except KeyboardInterrupt:
        logger.info("Log monitoring stopped by user.")
    except Exception as e:
        logger.error(f"Critical error in log monitoring: {e}")
        # Optionally, send a critical error notification
        critical_notifier = DiscordNotifier({
            'DISCORD_WEBHOOK_URL': os.environ.get('DISCORD_WEBHOOK_URL', '')
        })
        critical_notifier.send_notification({
            "embeds": [{
                "title": "🚨 CRITICAL: Nginx Log Monitor Failure",
                "description": f"The log monitoring process encountered a critical error: {e}",
                "color": 0xFF0000
            }]
        })

if __name__ == "__main__":
    main()