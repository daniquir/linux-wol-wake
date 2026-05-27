from scapy.all import ARP, Ether, srp
import socket
import nmap
import concurrent.futures
import subprocess
import re
import time
import struct

def scan_network(network_range):
    """
    Scan the network for active devices using:
    - Nmap host discovery (multiple techniques)
    - ARP scan on the local subnet
    - mDNS/Bonjour for Apple/IoT devices
    - NetBIOS for Windows hosts
    """
    devices = {}
    scanned_ips = set()
    
    # 1. Nmap host discovery con múltiples técnicas y timeout extendido
    nm = nmap.PortScanner()
    # Técnicas: -sn (ping), -PR (ARP), -PE (ICMP echo), -PS (TCP SYN), -PA (TCP ACK), -PP (ICMP timestamp)
    # --max-retries 2: reintentos limitados para velocidad
    # --host-timeout 4s: timeout más generoso
    nm.scan(hosts=network_range, arguments='-sn -PR -PE -PS22,80,443,445,554,8000,8080,8899 -PA80,443,22 -PP -T4 --max-retries 2 --host-timeout 4s')
    
    for host in nm.all_hosts():
        scanned_ips.add(host)
        res = nm[host]
        mac = res['addresses'].get('mac', 'Unknown')
        vendor = res['vendor'].get(mac, 'Unknown') if mac != 'Unknown' else 'Unknown'
        hostname = res.hostname() or 'Unknown'
        
        devices[host] = {
            'ip': host,
            'mac': mac,
            'hostname': hostname,
            'vendor': vendor,
            'source': 'nmap',
            'state': res.state()
        }
    
    # 2. ARP scan complementario para toda la red (captura dispositivos que no respondieron a nmap)
    try:
        arp_targets = _get_ip_list_from_range(network_range)
        # Escaneo ARP en paralelo por bloques
        arp_results = _arp_scan_parallel(arp_targets, chunk_size=16)
        for ip, mac in arp_results:
            if ip in devices:
                if devices[ip]['mac'] == 'Unknown':
                    devices[ip]['mac'] = mac
            else:
                scanned_ips.add(ip)
                devices[ip] = {
                    'ip': ip,
                    'mac': mac,
                    'hostname': 'Unknown',
                    'vendor': 'Unknown',
                    'source': 'arp',
                    'state': 'up'
                }
    except Exception as e:
        print(f"ARP scan warning: {e}")
    
    # 3. mDNS discovery para dispositivos que anuncian servicios (Apple, impresoras, IoT)
    try:
        mdns_devices = _mdns_discovery(timeout=2)
        for ip, info in mdns_devices.items():
            if ip in devices:
                if info.get('hostname') and devices[ip]['hostname'] == 'Unknown':
                    devices[ip]['hostname'] = info['hostname']
                if info.get('vendor') and devices[ip]['vendor'] == 'Unknown':
                    devices[ip]['vendor'] = info['vendor']
            else:
                scanned_ips.add(ip)
                devices[ip] = {
                    'ip': ip,
                    'mac': info.get('mac', 'Unknown'),
                    'hostname': info.get('hostname', 'Unknown'),
                    'vendor': info.get('vendor', 'Unknown'),
                    'source': 'mdns',
                    'state': 'up'
                }
    except Exception as e:
        print(f"mDNS discovery warning: {e}")
    
    # 4. NetBIOS discovery para dispositivos Windows
    try:
        netbios_devices = _netbios_discovery(list(devices.keys()))
        for ip, info in netbios_devices.items():
            if ip in devices:
                if info.get('hostname') and devices[ip]['hostname'] in ['Unknown', '']:
                    devices[ip]['hostname'] = info['hostname']
                if info.get('vendor') and devices[ip]['vendor'] == 'Unknown':
                    devices[ip]['vendor'] = info['vendor']
    except Exception as e:
        print(f"NetBIOS discovery warning: {e}")
    
    # 5. Resolver hostnames para dispositivos sin nombre
    for ip, dev in list(devices.items()):
        if dev['hostname'] in ['Unknown', '']:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                if hostname and hostname != ip:
                    dev['hostname'] = hostname
            except:
                pass
    
    # 6. Escaneo de puertos en paralelo para todos los dispositivos
    device_list = list(devices.values())
    port_results = _scan_ports_parallel(device_list)
    
    # 7. Construir resultado final con categorización
    result = []
    for ip, dev in devices.items():
        open_ports = port_results.get(ip, [])
        
        # Actualizar MAC desde ARP si aún es Unknown
        if dev['mac'] == 'Unknown' and ip in port_results:
            dev['mac'] = _get_mac_from_arp(ip) or 'Unknown'
        
        # Detectar vendor por MAC si es Unknown
        if dev['vendor'] == 'Unknown' and dev['mac'] != 'Unknown':
            dev['vendor'] = _lookup_vendor_by_mac(dev['mac'])
        
        wol_supported, wol_reasons = detect_wol_support(ip, dev['mac'], dev['vendor'], dev['hostname'], open_ports)
        category = categorize_device(dev['hostname'], dev['vendor'], open_ports)
        
        # ONVIF detection: más puertos y también por categoría
        onvif_ports = ['80', '8080', '8899', '8000', '81', '82', '800', '5000']
        onvif_detected = category == 'Camera' and any(p in open_ports for p in onvif_ports + ['554'])
        
        result.append({
            'ip': ip,
            'mac': dev['mac'],
            'hostname': dev['hostname'],
            'vendor': dev['vendor'],
            'category': category,
            'is_online': True,
            'open_ports': ','.join(open_ports) if open_ports else None,
            'wol_detected': wol_supported,
            'wol_reasons': ','.join(wol_reasons) if wol_reasons else None,
            'onvif_detected': onvif_detected,
            'discovery_source': dev.get('source', 'unknown')
        })
    
    return result


def _get_ip_list_from_range(network_range):
    """Convierte rango CIDR a lista de IPs."""
    import ipaddress
    try:
        network = ipaddress.ip_network(network_range, strict=False)
        return [str(ip) for ip in network.hosts()]
    except:
        return []


def _arp_scan_parallel(targets, chunk_size=16, timeout=2):
    """
    Escaneo ARP en paralelo por bloques para mejor rendimiento.
    """
    results = []
    
    def scan_chunk(chunk):
        chunk_results = []
        try:
            # Crear paquetes ARP para todo el chunk
            packets = [Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip) for ip in chunk]
            answered, _ = srp(packets, timeout=timeout, verbose=False, retry=1)
            for sent, received in answered:
                chunk_results.append((received.psrc, received.hwsrc))
        except Exception as e:
            pass
        return chunk_results
    
    # Dividir en chunks y escanear
    chunks = [targets[i:i+chunk_size] for i in range(0, len(targets), chunk_size)]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        future_to_chunk = {executor.submit(scan_chunk, chunk): chunk for chunk in chunks}
        for future in concurrent.futures.as_completed(future_to_chunk):
            try:
                chunk_results = future.result()
                results.extend(chunk_results)
            except:
                pass
    
    return results


def _get_mac_from_arp(ip):
    """Obtiene MAC de tabla ARP o envía petición ARP directa."""
    try:
        # Intentar leer de tabla ARP del sistema
        with open('/proc/net/arp', 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip:
                    mac = parts[3]
                    if mac != '00:00:00:00:00:00':
                        return mac
    except:
        pass
    
    # Petición ARP directa
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=1, verbose=False)
        if ans:
            return ans[0][1].hwsrc
    except:
        pass
    return None


def _lookup_vendor_by_mac(mac):
    """Busca vendor por OUI usando nmap o base de datos local."""
    try:
        oui = mac[:8].upper().replace(':', '-')
        # Intentar usar nmap para lookup
        nm = nmap.PortScanner()
        # Nmap tiene una base de datos de vendors en su código
        common_vendors = {
            '00-50-56': 'VMware', '00-0C-29': 'VMware', '00-15-5D': 'Microsoft',
            '00-11-32': 'Synology', '00-08-9B': 'QNAP', 'D8-CB-8A': 'MSI',
            'BC-5F-F4': 'ASRock', 'E0-D5-5E': 'GIGABYTE', 'B8-AE-ED': 'GIGABYTE',
            '00-25-90': 'Supermicro', '00-30-48': 'Supermicro', '00-1F-D0': 'Giga-byte',
            '00-24-1D': 'Giga-byte', '00-1D-72': 'Realtek', '00-E0-4C': 'Realtek',
            '00-1C-C0': 'Intel', '00-1B-21': 'Intel', '00-16-76': 'Intel',
            '00-13-21': 'HP', '00-11-0A': 'HP', '00-14-22': 'Dell', '00-15-C5': 'Dell',
            'AC-DE-48': 'Private', '00-05-1E': 'Apple', '00-03-93': 'Apple',
            '00-0A-27': 'Apple', '00-0A-95': 'Apple', '00-17-F2': 'Apple',
            '00-1B-63': 'Apple', '00-1C-B3': 'Apple', '00-1D-4F': 'Apple',
            '00-1E-52': 'Apple', '00-1E-C2': 'Apple', '00-1F-5B': 'Apple',
            '00-1F-F3': 'Apple', '00-21-E9': 'Apple', '00-22-41': 'Apple',
            '00-23-32': 'Apple', '00-23-6C': 'Apple', '00-23-DF': 'Apple',
            '00-24-36': 'Apple', '00-25-00': 'Apple', '00-25-4B': 'Apple',
            '00-25-BC': 'Apple', '00-26-08': 'Apple', '00-26-4A': 'Apple',
            '00-26-B0': 'Apple', '00-26-BB': 'Apple', '00-26-BB': 'Apple',
            '00-30-65': 'Apple', '00-3E-E1': 'Apple', '00-50-E4': 'Apple',
            '00-56-CD': 'Apple', '00-61-71': 'Apple', '00-88-65': 'Apple',
            '00-90-27': 'Apple', '00-9E-1E': 'Apple', '00-A0-40': 'Apple',
            '00-A0-B0': 'Apple', '00-B0-52': 'Apple', '00-C0-1A': 'Apple',
            '00-C1-63': 'Apple', '00-C3-47': 'Apple', '00-C5-E4': 'Apple',
            '00-C6-10': 'Apple', '00-C8-3E': 'Apple', '00-CD-FE': 'Apple',
            '00-D0-4B': 'Apple', '00-DB-70': 'Apple', '00-DD-7A': 'Apple',
            '00-E0-4C': 'Realtek', '00-E1-6D': 'Apple', '00-E3-7F': 'Apple',
            '00-E5-E4': 'Apple', '00-E8-AB': 'Apple', '00-E9-0B': 'Apple',
            '00-EB-2D': 'Apple', '00-EB-D8': 'Apple', '00-EE-AB': 'Apple',
            '00-F0-4F': 'Apple', '00-F4-8D': 'Apple', '00-F7-6F': 'Apple',
            '00-FF-86': 'Apple', '04-0C-CE': 'Apple', '04-15-52': 'Apple',
            '04-1E-64': 'Apple', '04-26-65': 'Apple', '04-32-F4': 'Apple',
            '04-48-C9': 'Apple', '04-4B-ED': 'Apple', '04-52-F3': 'Apple',
            '04-54-53': 'Apple', '04-5F-8A': 'Apple', '04-69-F8': 'Apple',
            '04-6C-59': 'Apple', '04-79-70': 'Apple', '04-8A-15': 'Apple',
            '04-8C-9F': 'Apple', '04-CE-14': 'Apple', '04-D3-B0': 'Apple',
            '04-D9-05': 'Apple', '04-E5-36': 'Apple', '04-F1-3E': 'Apple',
            '04-F7-E4': 'Apple', '08-00-05': 'Apple', '08-00-07': 'Apple',
            '08-00-09': 'Apple', '08-00-2E': 'Apple', '08-00-69': 'Apple',
        }
        return common_vendors.get(oui, 'Unknown')
    except:
        return 'Unknown'


def _mdns_discovery(timeout=2):
    """
    Descubre dispositivos mediante mDNS/Bonjour.
    Retorna dict: {ip: {'hostname': ..., 'vendor': ..., 'mac': ...}}
    """
    devices = {}
    try:
        # Usar avahi-browse o dns-sd si están disponibles
        # Fallback: escanear puertos mDNS comunes
        result = subprocess.run(
            ['timeout', str(timeout), 'avahi-browse', '-atlpf'], 
            capture_output=True, text=True, timeout=timeout+1
        )
        if result.returncode == 0 or result.stdout:
            for line in result.stdout.split('\n'):
                # Parsear líneas de avahi-browse
                match = re.search(r';\S+;\S+;\S+;(\S+);(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    name, ip = match.groups()
                    if ip and ip not in devices:
                        hostname = name.replace('\\', '')
                        vendor = _guess_vendor_from_hostname(hostname)
                        devices[ip] = {'hostname': hostname, 'vendor': vendor, 'mac': 'Unknown'}
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    except Exception as e:
        pass
    return devices


def _netbios_discovery(target_ips):
    """
    Descubre información NetBIOS de dispositivos Windows.
    Retorna dict: {ip: {'hostname': ..., 'vendor': ...}}
    """
    results = {}
    try:
        # Usar nmblookup si está disponible
        for ip in target_ips[:20]:  # Limitar a 20 para no saturar
            try:
                result = subprocess.run(
                    ['nmblookup', '-A', ip], 
                    capture_output=True, text=True, timeout=3
                )
                if result.returncode == 0:
                    # Parsear salida de nmblookup
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if '<00>' in line and 'UNIQUE' in line:
                            parts = line.split()
                            if len(parts) >= 1:
                                hostname = parts[0].strip()
                                if hostname and ip not in results:
                                    results[ip] = {'hostname': hostname, 'vendor': 'Microsoft/Windows'}
            except:
                pass
    except:
        pass
    return results


def _guess_vendor_from_hostname(hostname):
    """Intenta adivinar el vendor basado en el hostname."""
    h = hostname.lower()
    if any(x in h for x in ['ipad', 'iphone', 'macbook', 'imac', 'mac', 'apple-tv', 'airport']):
        return 'Apple'
    if any(x in h for x in ['android', 'pixel', 'samsung', 'galaxy']):
        return 'Mobile Device'
    if any(x in h for x in ['hp', 'hewlett']):
        return 'HP'
    if any(x in h for x in ['dell', 'optiplex', 'precision']):
        return 'Dell'
    if any(x in h for x in ['synology']):
        return 'Synology'
    if any(x in h for x in ['qnap']):
        return 'QNAP'
    if any(x in h for x in ['printer', 'epson', 'canon', 'brother', 'lexmark']):
        return 'Printer'
    return 'Unknown'


def _scan_ports_parallel(devices, max_workers=16):
    """
    Escanea puertos en paralelo para múltiples dispositivos.
    Retorna dict: {ip: [open_ports]}
    """
    # Puertos ampliados para mejor detección
    ports_to_scan = [
        '22', '23', '80', '81', '82', '88', '139', '443', '445', '554', '587', '800', 
        '843', '902', '993', '995', '1433', '1883', '2000', '2049', '3000', '3128', 
        '3306', '3389', '37777', '5000', '5432', '5900', '8000', '8006', '8008', 
        '8009', '8080', '8081', '8443', '8834', '8888', '8899', '9000', '9090', 
        '9091', '9443', '10000'
    ]
    port_list = ','.join(ports_to_scan)
    results = {}
    
    def scan_single_device(device):
        ip = device['ip']
        open_ports = []
        
        # Intentar conexión TCP a cada puerto
        for port in ports_to_scan:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, int(port)))
                sock.close()
                if result == 0:
                    open_ports.append(port)
            except:
                pass
        
        return ip, open_ports
    
    # Escaneo en paralelo con ThreadPoolExecutor
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_device = {executor.submit(scan_single_device, dev): dev for dev in devices}
        for future in concurrent.futures.as_completed(future_to_device):
            try:
                ip, open_ports = future.result()
                results[ip] = open_ports
            except:
                pass
    
    return results

def detect_wol_support(ip, mac, vendor, hostname, open_ports=None):
    """
    Heuristically guess whether a host likely supports Wake-on-LAN.
    Returns (bool, list_of_reasons).
    """
    v = vendor.lower()
    h = hostname.lower()
    m = mac.upper()
    ports = open_ports or []
    reasons = []
    
    # 1. Por Fabricante de la tarjeta de red (Casi todos los integrados de escritorio/servidor lo soportan)
    # Incluimos prefijos de MAC conocidos para tarjetas Ethernet que suelen soportar WoL
    wol_vendors = [
        'intel', 'realtek', 'broadcom', 'dell', 'hp', 'hewlett packard', 
        'gigabyte', 'asustek', 'msi', 'asrock', 'supermicro', 'synology', 
        'qnap', 'tp-link', 'd-link', 'cisco', 'nvidia', 'shenzhen cyx',
        'liteon', 'hon hai', 'foxconn', 'asus', 'asustek', 'lenovo', 'fujitsu',
        'super micro', 'supermicro', 'tyan', 'zebra', 'advantech', 'acer', 'toshiba',
        'samsung', 'sony', 'lg electronics', 'buffalo', 'terramaster', 'synology', 'qnap',
        'asustor', 'drobo', 'netgear', 'ubiquiti', 'mikrotik', 'linksys', 'belkin'
    ]
    
    # Excluir dispositivos móviles de forma más estricta para reducir falsos positivos
    is_mobile = any(mob in h or mob in v for mob in ['iphone', 'android', 'phone', 'tablet', 'ipad', 'watch', 'wearable', 'amazon', 'pixel', 'galaxy', 'xiaomi', 'huawei'])

    if any(wv in v for wv in wol_vendors) and not is_mobile:
        reasons.append(f"Vendor compatible ({vendor})")
            
    # 2. Por Hostname (Servidores, NAS, Desktops suelen tenerlo)
    if any(sh in h for sh in ['server', 'nas', 'desktop', 'pc', 'workstation', 'proxmox', 'esxi', 'node', 'cluster', 'pve', 'hyperv', 'vmware', 'host', 'media', 'tv', 'ps4', 'ps5', 'xbox', 'wii']):
        reasons.append(f"Nombre de host indicativo ({hostname})")

    # 3. Por prefijos de MAC comunes en hardware de red/servidores (OUI)
    wol_ouis = [
        '00:15:5D', # Microsoft Hyper-V
        '00:0C:29', # VMware
        '00:50:56', # VMware
        '00:11:32', # Synology
        '00:08:9B', # QNAP
        'D8:CB:8A', # Micro-Star (MSI)
        'BC:5F:F4', # ASRock
        'E0:D5:5E', # GIGABYTE
        'B8:AE:ED', # GIGABYTE
        '00:25:90', # Supermicro
        '00:30:48', # Supermicro
        '00:1F:D0', # Giga-byte
        '00:24:1D', # Giga-byte
        '00:1D:72', # Realtek
        '00:E0:4C', # Realtek
        '00:1C:C0', # Intel
        '00:1B:21', # Intel
        '00:16:76', # Intel
        '00:13:21', # HP
        '00:11:0A', # HP
        '00:14:22', # Dell
        '00:15:C5', # Dell
    ]
    if any(m.startswith(oui) for oui in wol_ouis):
        reasons.append(f"MAC OUI compatible ({m[:8]})")

    # 4. Por puertos abiertos típicos de PCs/Servidores (No móviles)
    # RDP, VNC, SSH, SMB, Proxmox, etc.
    if any(p in ports for p in ['3389', '5900', '22', '445', '8006', '9000']):
        if not is_mobile:
            reasons.append("Servicios de escritorio/servidor detectados")

    return (len(reasons) > 0, reasons)

def categorize_device(hostname, vendor, open_ports=None):
    """
    Categorize a device from hostname, vendor, and open ports (fingerprinting).
    """
    h = hostname.lower()
    v = vendor.lower()
    ports = open_ports or []
    
    # Cámaras e IoT (Prioridad alta para dispositivos específicos)
    if any(x in h for x in ['cam', 'camera', 'ring', 'nest', 'hikvision', 'dahua', 'amcrest', 'reolink', 'tapo', 'yi', 'wyze', 'nvr', 'dvr', 'foscam', 'axis', 'onvif']):
        return 'Camera'
    if any(x in v for x in ['hikvision', 'dahua', 'foscam', 'hanwha', 'axis communications', 'mobotix', 'reolink', 'vivotek', 'amcrest']):
        return 'Camera'
    # Detección por puertos altamente específicos de cámara (RTSP, ONVIF, puertos alternativos HTTP)
    camera_ports = ['8899', '554', '81', '82', '800', '37777', '8834', '8081']
    if any(p in ports for p in camera_ports):
        # Verificar que no sea un servidor con muchos puertos abiertos
        if len([p for p in ports if p in ['22', '23', '445', '139', '2049', '8006']]) == 0:
            return 'Camera'
    
    if any(x in h for x in ['iot', 'smart', 'bulb', 'plug', 'shelly', 'sonoff', 'tuya', 'esp32', 'esp8266', 'tasmota', 'zigbee', 'mqtt', 'bridge']):
        return 'IoT'
    if any(x in v for x in ['espressif', 'tuya', 'wemo', 'philips lighting', 'wyze', 'shelly', 'sonoff', 'itead', 'leedarson']):
        return 'IoT'

    # Equipos de Red
    if any(x in h for x in ['switch', 'router', 'gateway', 'ap', 'unifi', 'tplink', 'dlink', 'mikrotik', 'ubnt', 'firewall', 'pfsense', 'opnsense', 'wifi']):
        return 'Network'
    if any(x in v for x in ['cisco', 'ubiquiti', 'tp-link', 'd-link', 'netgear', 'mikrotik', 'linksys', 'aruba', 'juniper', 'fortinet', 'zyxel', 'synology router']):
        return 'Network'
    
    # Servidores y NAS (Detectado por puertos también)
    if any(x in h for x in ['server', 'nas', 'docker', 'pi', 'synology', 'qnap', 'truenas', 'unraid', 'proxmox', 'esxi', 'node', 'cluster', 'pve', 'srv']):
        return 'Server'
    if any(x in v for x in ['synology', 'qnap', 'asustor', 'terramaster', 'buffalo', 'drobo']):
        return 'Server'
    if any(p in ports for p in ['22', '23', '445', '139', '2049', '5000', '8006', '9000', '9443']):
        # Si tiene puertos de NAS/Server (SSH, SMB, NFS, Synology UI, Proxmox UI, Portainer)
        return 'Server'

    # Multimedia / TV
    if any(x in h for x in ['tv', 'roku', 'firestick', 'chromecast', 'apple-tv', 'shield', 'kodi', 'plex', 'bravia', 'vizio', 'lg-tv', 'samsung-tv', 'philips-tv', 'panasonic-tv']):
        return 'Media'
    if any(x in v for x in ['sony', 'vizio', 'lg electronics', 'samsung', 'roku', 'nvidia', 'sonos', 'denon', 'marantz', 'yamaha']):
        if 'phone' not in h and 'mobile' not in h:
            return 'Media'
    
    # Consolas de Videojuegos
    if any(x in h for x in ['playstation', 'xbox', 'nintendo', 'switch-console', 'ps4', 'ps5', 'wii']):
        return 'Console'
    if any(x in v for x in ['nintendo', 'sony interactive', 'microsoft corp']):
        if any(x in h for x in ['xbox', 'playstation']):
            return 'Console'

    # Móviles y Tablets
    if any(x in h for x in ['iphone', 'android', 'phone', 'mobile', 'galaxy', 'pixel', 'oneplus', 'xiaomi', 'huawei']):
        return 'Mobile'
    if any(x in h for x in ['ipad', 'tablet', 'tab', 'kindle', 'lenovo-tab', 'surface-go']):
        return 'Tablet'

    # Impresoras
    if any(x in h for x in ['printer', 'epson', 'hp', 'canon', 'brother', 'lexmark', 'xerox', 'kyocera', 'ricoh', 'konica']):
        return 'Printer'
    if any(x in v for x in ['epson', 'hewlett-packard', 'canon', 'brother', 'lexmark', 'xerox', 'kyocera', 'ricoh', 'konica']):
        return 'Printer'
    
    # PCs y Laptops
    if any(x in h for x in ['desktop', 'pc', 'workstation', 'gaming', 'studio', 'optiplex', 'thinkcentre', 'precision']):
        return 'PC'
    if any(x in h for x in ['laptop', 'macbook', 'surface', 'thinkpad', 'zenbook', 'book', 'latitude', 'xps', 'inspiron', 'pavilion', 'envy']):
        return 'Laptop'
    
    # Refinamiento por Vendor final
    if 'apple' in v:
        if 'iphone' in h: return 'Mobile'
        if 'ipad' in h: return 'Tablet'
        if 'macbook' in h or 'mac' in h or 'laptop' in h: return 'Laptop'
        if 'tv' in h: return 'Media'
        return 'PC'
    
    if any(x in v for x in ['samsung', 'huawei', 'xiaomi', 'oppo', 'vivo']):
        if 'tv' in h or 'smart-tv' in h: return 'Media'
        if 'tab' in h or 'tablet' in h: return 'Tablet'
        return 'Mobile'

    # Fallback por puertos
    if '3389' in ports or '5900' in ports: # RDP / VNC
        return 'PC'
    
    # Por defecto
    return 'Other'

def get_local_network():
    """Guess the local network CIDR (/24) from the default route."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # no necesita conectarse realmente
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        network_prefix = '.'.join(ip.split('.')[:-1]) + '.0/24'
    except Exception:
        network_prefix = '192.168.1.0/24'
    finally:
        s.close()
    return network_prefix
