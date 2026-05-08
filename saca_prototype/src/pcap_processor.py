"""
Enhanced PCAP Processor for Security Analysis
Supports deep packet inspection and advanced security detection with comprehensive threat analysis
"""

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
# TLS import - handle missing TLS class in some Scapy versions
try:
    from scapy.layers.tls import TLS
except ImportError:
    # Define a dummy TLS class for compatibility
    class TLS:
        pass
import asyncio
import hashlib
import json
import math
import re
import math
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import ipaddress
import logging

# Import enhanced components
from .enhanced_payload_analyzer import EnhancedPayloadAnalyzer, ThreatDetection
from .iso27001_compliance_analyzer import ISO27001ComplianceAnalyzer

logger = logging.getLogger(__name__)

@dataclass
class SecurityEvent:
    """Represents a security event detected in network traffic"""
    event_id: str
    event_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    timestamp: float
    source_ip: Optional[str]
    dest_ip: Optional[str]
    source_port: Optional[int]
    dest_port: Optional[int]
    protocol: str
    description: str
    evidence: Dict[str, Any]
    attack_category: str
    confidence_score: float
    remediation: List[str]

class AdvancedPcapProcessor:
    """Advanced PCAP processor with comprehensive security analysis"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.packets = []
        self.network_entities = {
            'hosts': {},
            'services': {},
            'protocols': {},
            'connections': [],
            'security_events': [],
            'dns_records': {},
            'arp_table': {},
            'tcp_sessions': {},
            'tls_sessions': {},
            'http_sessions': {},
            'tcp_sessions': {},
            'file_transfers': {},
            'malware_indicators': {},
            'network_flows': {},
            'scan_tracking': {}
        }
        
        # Initialize enhanced components
        self.enhanced_payload_analyzer = EnhancedPayloadAnalyzer(config)
        self.compliance_analyzer = ISO27001ComplianceAnalyzer(config)
        
        # Security detection rules
        self.attack_patterns = self._load_attack_patterns()
        self.vulnerability_signatures = self._load_vulnerability_signatures()
        
        # Statistical tracking
        self.packet_stats = defaultdict(int)
        self.protocol_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        
        # Enhanced threat detection storage
        self.threat_detections = []
        self.payload_analyses = []
        
    def _load_attack_patterns(self) -> Dict[str, Any]:
        """Load attack pattern definitions"""
        return {
            'port_scan': {
                'pattern': 'multiple_ports_single_source',
                'threshold': 10,
                'time_window': 60
            },
            'ddos': {
                'pattern': 'high_volume_single_target',
                'threshold': 1000,
                'time_window': 10
            },
            'brute_force': {
                'pattern': 'multiple_login_attempts',
                'threshold': 10,
                'ports': [21, 22, 23, 3389, 443]
            },
            'dns_tunneling': {
                'pattern': 'suspicious_dns_queries',
                'indicators': ['long_subdomain', 'base64_patterns', 'high_entropy']
            },
            'arp_poisoning': {
                'pattern': 'arp_reply_anomalies',
                'indicators': ['mac_ip_conflicts', 'gratuitous_arps']
            },
            'sql_injection': {
                'pattern': 'malicious_http_payloads',
                'signatures': ['union select', '1=1', 'drop table', 'xp_cmdshell']
            },
            'command_injection': {
                'pattern': 'shell_command_payloads',
                'signatures': ['|nc ', ';cat ', '`whoami`', '$(id)']
            },
            'data_exfiltration': {
                'pattern': 'large_outbound_transfers',
                'threshold': 10485760,  # 10MB
                'protocols': ['HTTP', 'HTTPS', 'FTP', 'DNS']
            }
        }
    
    def _load_vulnerability_signatures(self) -> Dict[str, Any]:
        """Load vulnerability signatures"""
        return {
            'cve_2017_0144': {  # EternalBlue
                'name': 'EternalBlue SMB Exploit',
                'ports': [445],
                'protocols': ['SMB'],
                'patterns': [b'\\x00\\x00\\x00\\x2f\\xff\\x53\\x4d\\x42\\x72']
            },
            'cve_2014_0160': {  # Heartbleed
                'name': 'Heartbleed OpenSSL Vulnerability',
                'ports': [443],
                'protocols': ['TLS'],
                'patterns': [b'\\x18\\x03', b'\\x01\\x00\\x40\\x00']
            },
            'cve_2019_0708': {  # BlueKeep
                'name': 'BlueKeep RDP Vulnerability',
                'ports': [3389],
                'protocols': ['RDP'],
                'patterns': [b'\\x03\\x00\\x00\\x13\\x0e\\xe0']
            }
        }
    
    async def process_pcap_file(self, pcap_path: str) -> Dict[str, Any]:
        """Process PCAP file with comprehensive security analysis"""
        logger.info(f"Starting analysis of PCAP file: {pcap_path}")
        
        try:
            # Load PCAP
            self.packets = scapy.rdpcap(pcap_path)
            logger.info(f"Loaded {len(self.packets)} packets")
            
            # Process packets in chunks for better performance
            chunk_size = self.config.get('pcap', {}).get('chunk_size', 1000)
            total_packets = len(self.packets)
            
            for i in range(0, total_packets, chunk_size):
                chunk = self.packets[i:i + chunk_size]
                await self._process_packet_chunk(chunk, i)
                
                # Progress update
                progress = min(100, (i + chunk_size) / total_packets * 100)
                logger.info(f"Processing progress: {progress:.1f}%")
            
            # Perform advanced analysis
            await self._advanced_security_analysis()
            
            # Generate analysis summary
            analysis_summary = self._generate_analysis_summary()
            
            logger.info("PCAP analysis completed successfully")
            return {
                'network_entities': self.network_entities,
                'analysis_summary': analysis_summary,
                'packet_statistics': dict(self.packet_stats),
                'protocol_statistics': dict(self.protocol_stats)
            }
            
        except Exception as e:
            logger.error(f"PCAP processing failed: {e}")
            raise
    
    async def _process_packet_chunk(self, packets: List, chunk_start: int):
        """Process a chunk of packets"""
        
        for idx, packet in enumerate(packets):
            packet_idx = chunk_start + idx
            timestamp = float(packet.time) if hasattr(packet, 'time') else packet_idx
            
            try:
                # Basic packet analysis
                self._analyze_packet_layers(packet, packet_idx, timestamp)
                
                # Protocol-specific analysis
                if packet.haslayer(IP):
                    await self._analyze_ip_layer(packet, timestamp)
                
                if packet.haslayer(TCP):
                    await self._analyze_tcp_layer(packet, timestamp)
                    
                if packet.haslayer(UDP):
                    await self._analyze_udp_layer(packet, timestamp)
                
                if packet.haslayer(DNS):
                    await self._analyze_dns_layer(packet, timestamp)
                    
                if packet.haslayer(HTTP):
                    await self._analyze_http_layer(packet, timestamp)
                    
                if packet.haslayer(TLS):
                    await self._analyze_tls_layer(packet, timestamp)
                    
                if packet.haslayer(ARP):
                    await self._analyze_arp_layer(packet, timestamp)
                
                # Real-time threat detection
                await self._detect_threats_in_packet(packet, timestamp)
                
            except Exception as e:
                logger.warning(f"Error processing packet {packet_idx}: {e}")
                continue
    
    def _analyze_packet_layers(self, packet, packet_idx: int, timestamp: float):
        """Analyze packet layers and update statistics"""
        
        packet_size = len(packet)
        self.packet_stats['total_packets'] += 1
        self.packet_stats['total_bytes'] += packet_size
        
        # Layer analysis
        layer_names = []
        layer = packet
        while layer:
            layer_name = layer.__class__.__name__
            layer_names.append(layer_name)
            self.protocol_stats[layer_name] += 1
            layer = layer.payload if hasattr(layer, 'payload') and layer.payload else None
        
        # Store packet metadata
        packet_info = {
            'packet_idx': packet_idx,
            'timestamp': timestamp,
            'size': packet_size,
            'layers': layer_names
        }
        
        return packet_info
    
    async def _analyze_ip_layer(self, packet, timestamp: float):
        """Comprehensive IP layer analysis"""
        
        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        
        # Update host entities
        for ip_addr in [src_ip, dst_ip]:
            if ip_addr not in self.network_entities['hosts']:
                self.network_entities['hosts'][ip_addr] = {
                    'ip_address': ip_addr,
                    'first_seen': timestamp,
                    'last_seen': timestamp,
                    'packet_count': 0,
                    'bytes_total': 0,
                    'protocols': set(),
                    'ports_contacted': set(),
                    'geographic_info': self._get_geographic_info(ip_addr),
                    'reputation': await self._check_ip_reputation(ip_addr),
                    'is_internal': self._is_internal_ip(ip_addr),
                    'communication_partners': set(),
                    'suspicious_activities': [],
                    'services_offered': set(),
                    'vulnerabilities': []
                }
        
        # Update host statistics
        host_src = self.network_entities['hosts'][src_ip]
        host_dst = self.network_entities['hosts'][dst_ip]
        
        host_src['last_seen'] = timestamp
        host_src['packet_count'] += 1
        host_src['bytes_total'] += len(packet)
        host_src['communication_partners'].add(dst_ip)
        
        host_dst['communication_partners'].add(src_ip)
        
        # Record connection
        connection = {
            'timestamp': timestamp,
            'source_ip': src_ip,
            'dest_ip': dst_ip,
            'protocol': ip.proto,
            'packet_size': len(packet),
            'ttl': ip.ttl,
            'flags': ip.flags if hasattr(ip, 'flags') else 0,
            'connection_type': 'ip_communication'
        }
        
        self.network_entities['connections'].append(connection)
    
    async def _analyze_tcp_layer(self, packet, timestamp: float):
        """Advanced TCP layer analysis"""
        
        tcp = packet[TCP]
        ip = packet[IP]
        
        src_port = tcp.sport
        dst_port = tcp.dport
        flags = tcp.flags
        
        # Service identification
        service_info = self._identify_service(dst_port, 'tcp')
        
        # TCP session tracking
        session_key = f"{ip.src}:{src_port}-{ip.dst}:{dst_port}"
        
        if session_key not in self.network_entities['tcp_sessions']:
            self.network_entities['tcp_sessions'][session_key] = {
                'source_ip': ip.src,
                'dest_ip': ip.dst,
                'source_port': src_port,
                'dest_port': dst_port,
                'service': service_info,
                'first_seen': timestamp,
                'last_seen': timestamp,
                'packet_count': 0,
                'bytes_transferred': 0,
                'flags_seen': set(),
                'session_state': 'UNKNOWN',
                'payload_data': [],
                'security_flags': []
            }
        
        session = self.network_entities['tcp_sessions'][session_key]
        session['last_seen'] = timestamp
        session['packet_count'] += 1
        session['bytes_transferred'] += len(packet)
        session['flags_seen'].add(flags)
        
        # TCP state analysis
        if flags & 0x02:  # SYN
            session['session_state'] = 'SYN_SENT'
        elif flags & 0x12:  # SYN-ACK
            session['session_state'] = 'SYN_RECEIVED'
        elif flags & 0x10:  # ACK
            if session['session_state'] == 'SYN_RECEIVED':
                session['session_state'] = 'ESTABLISHED'
        elif flags & 0x01:  # FIN
            session['session_state'] = 'CLOSING'
        elif flags & 0x04:  # RST
            session['session_state'] = 'RESET'
        
        # Enhanced payload analysis
        if tcp.payload:
            payload = bytes(tcp.payload)
            
            # Create packet info for enhanced analysis
            packet_info = {
                'source_ip': ip.src,
                'dest_ip': ip.dst,
                'source_port': src_port,
                'dest_port': dst_port,
                'protocol': 'TCP',
                'layer': 'transport',
                'timestamp': timestamp,
                'session_id': session_key,
                'session_context': session.get('session_state', 'unknown')
            }
            
            # Use enhanced payload analyzer
            payload_analysis = await self.enhanced_payload_analyzer.analyze_payload_comprehensive(
                payload, packet_info
            )
            
            # Store payload analysis results
            self.payload_analyses.append(payload_analysis)
            
            # Convert payload analysis threats to security events
            await self._convert_payload_threats_to_events(payload_analysis, packet_info)
            
            # Store payload data in session
            session['payload_data'].append({
                'timestamp': timestamp,
                'size': len(payload),
                'analysis': payload_analysis,
                'hex_preview': payload[:64].hex() if len(payload) > 0 else ''
            })
        
        # Port scanning detection
        await self._detect_port_scanning(ip.src, dst_port, timestamp)
    
    async def _analyze_udp_layer(self, packet, timestamp: float):
        """Analyze UDP layer for security threats"""
        
        udp = packet[UDP]
        ip = packet[IP]
        
        src_port = udp.sport
        dst_port = udp.dport
        
        # Service identification
        service_info = self._identify_service(dst_port, 'udp')
        
        # Enhanced payload analysis for UDP
        if udp.payload:
            payload = bytes(udp.payload)
            
            # Create packet info for enhanced analysis
            packet_info = {
                'source_ip': ip.src,
                'dest_ip': ip.dst,
                'source_port': src_port,
                'dest_port': dst_port,
                'protocol': 'UDP',
                'layer': 'transport',
                'timestamp': timestamp,
                'service': service_info
            }
            
            # Use enhanced payload analyzer
            payload_analysis = await self.enhanced_payload_analyzer.analyze_payload_comprehensive(
                payload, packet_info
            )
            
            # Store payload analysis results
            self.payload_analyses.append(payload_analysis)
            
            # Convert payload analysis threats to security events
            await self._convert_payload_threats_to_events(payload_analysis, packet_info)
        
    async def _analyze_dns_layer(self, packet, timestamp: float):
        """Comprehensive DNS analysis with threat detection"""
        
        dns = packet[DNS]
        ip = packet[IP]
        
        # DNS query analysis
        if dns.qd:
            query_name = dns.qd.qname.decode('utf-8').rstrip('.')
            query_type = dns.qd.qtype
            
            dns_record = {
                'query': query_name,
                'query_type': query_type,
                'requester': ip.src,
                'timestamp': timestamp,
                'response_code': dns.rcode if hasattr(dns, 'rcode') else 0,
                'answers': [],
                'suspicious_indicators': []
            }
            
            # DNS tunneling detection
            await self._detect_dns_tunneling(query_name, dns_record)
            
            # Malicious domain detection
            await self._detect_malicious_domains(query_name, dns_record)
            
            # DNS response analysis
            if dns.an:
                for answer in dns.an:
                    if hasattr(answer, 'rdata'):
                        dns_record['answers'].append({
                            'type': answer.type,
                            'data': str(answer.rdata),
                            'ttl': answer.ttl
                        })
            
            record_key = f"{query_name}:{query_type}"
            self.network_entities['dns_records'][record_key] = dns_record
    
    async def _analyze_http_layer(self, packet, timestamp: float):
        """HTTP traffic analysis for security threats"""
        
        http = packet[HTTP]
        ip = packet[IP]
        tcp = packet[TCP]
        
        if isinstance(http, HTTPRequest):
            await self._analyze_http_request(http, ip, tcp, timestamp)
        elif isinstance(http, HTTPResponse):
            await self._analyze_http_response(http, ip, tcp, timestamp)
    
    async def _analyze_http_request(self, http, ip, tcp, timestamp):
        """Analyze HTTP request for security threats"""
        
        method = http.Method.decode() if hasattr(http, 'Method') else 'UNKNOWN'
        path = http.Path.decode() if hasattr(http, 'Path') else '/'
        host = http.Host.decode() if hasattr(http, 'Host') else ip.dst
        
        request_data = {
            'timestamp': timestamp,
            'source_ip': ip.src,
            'dest_ip': ip.dst,
            'method': method,
            'path': path,
            'host': host,
            'user_agent': '',
            'headers': {},
            'payload': '',
            'security_flags': []
        }
        
        # Extract headers
        if hasattr(http, 'headers'):
            for header in http.headers:
                if hasattr(header, 'name') and hasattr(header, 'value'):
                    header_name = header.name.decode()
                    header_value = header.value.decode()
                    request_data['headers'][header_name] = header_value
                    
                    if header_name.lower() == 'user-agent':
                        request_data['user_agent'] = header_value
        
        # Payload analysis
        if hasattr(http, 'load'):
            request_data['payload'] = http.load.decode('utf-8', errors='ignore')
        
        # Security analysis
        await self._detect_web_attacks(request_data)
        
        session_key = f"http_{ip.src}:{tcp.sport}-{ip.dst}:{tcp.dport}"
        if session_key not in self.network_entities['http_sessions']:
            self.network_entities['http_sessions'][session_key] = []
        
        self.network_entities['http_sessions'][session_key].append(request_data)
    
    async def _analyze_http_response(self, http, ip, tcp, timestamp):
        """Analyze HTTP response for security indicators"""
        
        status_code = getattr(http, 'Status_Code', b'200').decode()
        
        response_data = {
            'timestamp': timestamp,
            'source_ip': ip.src,
            'dest_ip': ip.dst,
            'status_code': status_code,
            'headers': {},
            'payload': '',
            'security_flags': []
        }
        
        # Extract headers
        if hasattr(http, 'headers'):
            for header in http.headers:
                if hasattr(header, 'name') and hasattr(header, 'value'):
                    header_name = header.name.decode()
                    header_value = header.value.decode()
                    response_data['headers'][header_name] = header_value
        
        # Payload analysis
        if hasattr(http, 'load'):
            response_data['payload'] = http.load.decode('utf-8', errors='ignore')
        
        # Check for information disclosure
        if '500' in status_code or 'error' in response_data['payload'].lower():
            await self._create_security_event(
                event_type="information_disclosure",
                severity="LOW",
                source_ip=ip.src,
                dest_ip=ip.dst,
                description=f"Potential information disclosure in HTTP response: {status_code}",
                evidence={'status_code': status_code, 'response_preview': response_data['payload'][:200]},
                timestamp=timestamp
            )
    
    async def _analyze_tls_layer(self, packet, timestamp: float):
        """Analyze TLS layer for security vulnerabilities"""
        
        tls = packet[TLS]
        ip = packet[IP]
        tcp = packet[TCP]
        
        session_key = f"tls_{ip.src}:{tcp.sport}-{ip.dst}:{tcp.dport}"
        
        if session_key not in self.network_entities['tls_sessions']:
            self.network_entities['tls_sessions'][session_key] = {
                'source_ip': ip.src,
                'dest_ip': ip.dst,
                'source_port': tcp.sport,
                'dest_port': tcp.dport,
                'first_seen': timestamp,
                'last_seen': timestamp,
                'tls_version': None,
                'cipher_suite': None,
                'certificates': [],
                'vulnerabilities': []
            }
        
        session = self.network_entities['tls_sessions'][session_key]
        session['last_seen'] = timestamp
        
        # TLS version analysis
        if hasattr(tls, 'version'):
            session['tls_version'] = tls.version
            
            # Check for vulnerable TLS versions
            if tls.version < 0x0303:  # TLS 1.2
                await self._create_security_event(
                    event_type="tls_vulnerability",
                    severity="MEDIUM",
                    source_ip=ip.src,
                    dest_ip=ip.dst,
                    description=f"Vulnerable TLS version detected: {hex(tls.version)}",
                    evidence={'tls_version': hex(tls.version)},
                    timestamp=timestamp,
                    attack_category="PROTOCOL_ATTACK"
                )
    
    async def _analyze_arp_layer(self, packet, timestamp: float):
        """Analyze ARP layer for poisoning attacks"""
        
        arp = packet[ARP]
        
        # ARP table tracking
        arp_key = f"{arp.psrc}_{arp.hwsrc}"
        
        if arp_key not in self.network_entities['arp_table']:
            self.network_entities['arp_table'][arp_key] = {
                'ip_address': arp.psrc,
                'mac_address': arp.hwsrc,
                'first_seen': timestamp,
                'last_seen': timestamp,
                'request_count': 0,
                'reply_count': 0
            }
        
        arp_entry = self.network_entities['arp_table'][arp_key]
        arp_entry['last_seen'] = timestamp
        
        if arp.op == 1:  # ARP Request
            arp_entry['request_count'] += 1
        elif arp.op == 2:  # ARP Reply
            arp_entry['reply_count'] += 1
            
            # Check for ARP poisoning indicators
            await self._detect_arp_poisoning(arp, timestamp)
    
    async def _detect_arp_poisoning(self, arp, timestamp: float):
        """Detect ARP poisoning attacks"""
        
        # Check for gratuitous ARP replies
        if arp.op == 2 and arp.psrc == arp.pdst:
            await self._create_security_event(
                event_type="arp_poisoning",
                severity="HIGH",
                description=f"Gratuitous ARP reply detected from {arp.hwsrc}",
                evidence={
                    'source_ip': arp.psrc,
                    'source_mac': arp.hwsrc,
                    'target_ip': arp.pdst,
                    'target_mac': arp.hwdst
                },
                timestamp=timestamp,
                attack_category="NETWORK_ATTACK"
            )
        
        # Check for MAC-IP conflicts
        for existing_key, existing_entry in self.network_entities['arp_table'].items():
            if (existing_entry['ip_address'] == arp.psrc and 
                existing_entry['mac_address'] != arp.hwsrc):
                await self._create_security_event(
                    event_type="arp_poisoning",
                    severity="HIGH",
                    description=f"ARP spoofing detected: IP {arp.psrc} claimed by multiple MACs",
                    evidence={
                        'conflicting_ip': arp.psrc,
                        'original_mac': existing_entry['mac_address'],
                        'spoofing_mac': arp.hwsrc
                    },
                    timestamp=timestamp,
                    attack_category="NETWORK_ATTACK"
                )
    
    async def _detect_web_attacks(self, request_data: Dict):
        """Detect web-based attacks in HTTP requests"""
        
        path = request_data.get('path', '')
        payload = request_data.get('payload', '')
        headers = request_data.get('headers', {})
        
        # SQL Injection detection
        sql_patterns = [
            r"'.*union.*select", r"1=1", r"drop\s+table", r"xp_cmdshell",
            r"sp_executesql", r"exec\s*\(", r";\s*shutdown", r"benchmark\s*\("
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, path + payload, re.IGNORECASE):
                await self._create_security_event(
                    event_type="sql_injection_attempt",
                    severity="HIGH",
                    source_ip=request_data['source_ip'],
                    dest_ip=request_data['dest_ip'],
                    description=f"SQL injection pattern detected: {pattern}",
                    evidence={'pattern': pattern, 'path': path, 'payload': payload[:500]},
                    timestamp=request_data['timestamp']
                )
        
        # XSS detection
        xss_patterns = [
            r"<script", r"javascript:", r"onload=", r"onerror=",
            r"alert\s*\(", r"document\.cookie", r"eval\s*\("
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, path + payload, re.IGNORECASE):
                await self._create_security_event(
                    event_type="xss_attempt",
                    severity="MEDIUM",
                    source_ip=request_data['source_ip'],
                    dest_ip=request_data['dest_ip'],
                    description=f"Cross-site scripting pattern detected: {pattern}",
                    evidence={'pattern': pattern, 'path': path, 'payload': payload[:500]},
                    timestamp=request_data['timestamp']
                )
        
        # Command injection detection
        cmd_patterns = [
            r";\s*cat\s", r"\|.*nc\s", r"`.*whoami.*`", r"\$\(.*id.*\)",
            r"&&\s*ls", r";\s*wget", r"\|.*curl"
        ]
        
        for pattern in cmd_patterns:
            if re.search(pattern, path + payload, re.IGNORECASE):
                await self._create_security_event(
                    event_type="command_injection_attempt",
                    severity="HIGH",
                    source_ip=request_data['source_ip'],
                    dest_ip=request_data['dest_ip'],
                    description=f"Command injection pattern detected: {pattern}",
                    evidence={'pattern': pattern, 'path': path, 'payload': payload[:500]},
                    timestamp=request_data['timestamp']
                )
    
    async def _detect_dns_tunneling(self, query_name: str, dns_record: Dict):
        """Detect DNS tunneling attempts"""
        
        indicators = []
        
        # Long subdomain detection
        if len(query_name) > 100:
            indicators.append('extremely_long_domain')
        
        # High entropy detection (Base64/encoded data)
        entropy = self._calculate_entropy(query_name)
        if entropy > 4.5:
            indicators.append('high_entropy_domain')
        
        # Suspicious TLD patterns
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.bit']
        for tld in suspicious_tlds:
            if query_name.endswith(tld):
                indicators.append('suspicious_tld')
        
        # Base64 pattern detection
        if re.search(r'^[A-Za-z0-9+/=]{20,}', query_name.split('.')[0]):
            indicators.append('base64_pattern')
        
        if indicators:
            dns_record['suspicious_indicators'] = indicators
            
            await self._create_security_event(
                event_type="dns_tunneling_attempt",
                severity="MEDIUM",
                source_ip=dns_record['requester'],
                description=f"DNS tunneling indicators detected: {', '.join(indicators)}",
                evidence={
                    'domain': query_name,
                    'indicators': indicators,
                    'entropy': entropy
                },
                timestamp=dns_record['timestamp']
            )
    
    async def _detect_malicious_domains(self, query_name: str, dns_record: Dict):
        """Detect malicious domains in DNS queries"""
        
        # Placeholder for malicious domain detection
        # In a real implementation, this would check against threat intelligence feeds
        
        suspicious_keywords = ['malware', 'phishing', 'botnet', 'c2', 'command']
        
        for keyword in suspicious_keywords:
            if keyword in query_name.lower():
                dns_record['suspicious_indicators'].append(f'suspicious_keyword_{keyword}')
                
                await self._create_security_event(
                    event_type="malicious_domain_query",
                    severity="HIGH",
                    source_ip=dns_record['requester'],
                    description=f"Suspicious domain query detected: {query_name}",
                    evidence={
                        'domain': query_name,
                        'suspicious_keyword': keyword
                    },
                    timestamp=dns_record['timestamp'],
                    attack_category="MALWARE_COMMUNICATION"
                )
    
    async def _detect_threats_in_packet(self, packet, timestamp: float):
        """Real-time threat detection in individual packets"""
        
        # Check for known vulnerability signatures
        packet_bytes = bytes(packet)
        
        for vuln_id, vuln_info in self.vulnerability_signatures.items():
            for pattern in vuln_info['patterns']:
                if pattern in packet_bytes:
                    await self._create_security_event(
                        event_type="vulnerability_exploit",
                        severity="CRITICAL",
                        description=f"Known vulnerability exploit detected: {vuln_info['name']}",
                        evidence={
                            'vulnerability_id': vuln_id,
                            'pattern_matched': pattern.hex(),
                            'packet_preview': packet_bytes[:100].hex()
                        },
                        timestamp=timestamp,
                        attack_category="EXPLOIT_ATTEMPT"
                    )
    
    async def _detect_port_scanning(self, source_ip: str, dest_port: int, timestamp: float):
        """Detect port scanning activities"""
        
        # Track port access per source
        scan_key = f"scan_{source_ip}"
        
        if scan_key not in self.network_entities['scan_tracking']:
            self.network_entities['scan_tracking'] = {}
        
        if scan_key not in self.network_entities['scan_tracking']:
            self.network_entities['scan_tracking'][scan_key] = {
                'source_ip': source_ip,
                'ports_contacted': set(),
                'timestamps': [],
                'targets': set()
            }
        
        scan_info = self.network_entities['scan_tracking'][scan_key]
        scan_info['ports_contacted'].add(dest_port)
        scan_info['timestamps'].append(timestamp)
        
        # Port scan detection logic
        if len(scan_info['ports_contacted']) > 20:  # More than 20 ports
            time_window = max(scan_info['timestamps']) - min(scan_info['timestamps'])
            
            if time_window < 60:  # In less than 1 minute
                await self._create_security_event(
                    event_type="port_scanning",
                    severity="MEDIUM",
                    source_ip=source_ip,
                    description=f"Port scanning detected: {len(scan_info['ports_contacted'])} ports in {time_window:.1f} seconds",
                    evidence={
                        'ports_scanned': list(scan_info['ports_contacted']),
                        'time_window': time_window,
                        'scan_rate': len(scan_info['ports_contacted']) / time_window
                    },
                    timestamp=timestamp
                )
    
    async def _create_security_event(self, event_type: str, severity: str,
                                   source_ip: str = None, dest_ip: str = None,
                                   source_port: int = None, dest_port: int = None,
                                   protocol: str = 'UNKNOWN', description: str = '',
                                   evidence: Dict = None, timestamp: float = None,
                                   attack_category: str = 'UNKNOWN',
                                   confidence_score: float = 0.8,
                                   remediation: List[str] = None):
        """Create a comprehensive security event"""
        
        if evidence is None:
            evidence = {}
        
        if remediation is None:
            remediation = []
        
        event_id = hashlib.sha256(
            f"{event_type}{timestamp}{source_ip}{dest_ip}".encode()
        ).hexdigest()[:16]
        
        security_event = SecurityEvent(
            event_id=event_id,
            event_type=event_type,
            severity=severity,
            timestamp=timestamp or datetime.now().timestamp(),
            source_ip=source_ip,
            dest_ip=dest_ip,
            source_port=source_port,
            dest_port=dest_port,
            protocol=protocol,
            description=description,
            evidence=evidence,
            attack_category=attack_category,
            confidence_score=confidence_score,
            remediation=remediation
        )
        
        self.network_entities['security_events'].append(security_event)
        
        logger.warning(f"Security event detected: {event_type} - {description}")
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        
        # Count character frequencies
        char_counts = Counter(text)
        text_len = len(text)
        
        # Calculate entropy
        entropy = 0
        for count in char_counts.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _is_internal_ip(self, ip_str: str) -> bool:
        """Check if IP address is internal/private"""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return ip_obj.is_private
        except:
            return False
    
    def _get_geographic_info(self, ip_str: str) -> Dict[str, str]:
        """Get geographic information for IP address"""
        # Placeholder for GeoIP integration
        return {
            'country': 'Unknown',
            'city': 'Unknown',
            'asn': 'Unknown'
        }
    
    async def _check_ip_reputation(self, ip_str: str) -> str:
        """Check IP reputation against threat intelligence"""
        # Placeholder for threat intelligence integration
        return 'unknown'
    
    def _identify_service(self, port: int, protocol: str) -> Dict[str, str]:
        """Identify service based on port and protocol"""
        services = {
            'tcp': {
                21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
                80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
                995: 'POP3S', 3389: 'RDP', 445: 'SMB', 139: 'NetBIOS', 135: 'RPC'
            },
            'udp': {
                53: 'DNS', 67: 'DHCP_Server', 68: 'DHCP_Client', 69: 'TFTP',
                123: 'NTP', 161: 'SNMP', 514: 'Syslog', 1194: 'OpenVPN'
            }
        }
        
        service_name = services.get(protocol, {}).get(port, f'Port_{port}')
        
        return {
            'name': service_name,
            'port': port,
            'protocol': protocol.upper(),
            'risk_level': self._assess_service_risk(service_name, port)
        }
    
    def _assess_service_risk(self, service_name: str, port: int) -> str:
        """Assess security risk level of a service"""
        high_risk_services = ['FTP', 'Telnet', 'HTTP', 'SMB', 'RPC']
        medium_risk_services = ['SSH', 'SMTP', 'POP3', 'IMAP']
        
        if service_name in high_risk_services:
            return 'HIGH'
        elif service_name in medium_risk_services:
            return 'MEDIUM'
        elif port > 49152:  # Dynamic/ephemeral ports
            return 'LOW'
        else:
            return 'MEDIUM'
    
    async def _advanced_security_analysis(self):
        """Perform advanced security analysis on collected data"""
        
        logger.info("Performing advanced security analysis...")
        
        # Behavioral analysis
        await self._analyze_communication_patterns()
        await self._detect_data_exfiltration()
        await self._analyze_protocol_anomalies()
        await self._detect_lateral_movement()
        
        # Statistical analysis
        await self._statistical_anomaly_detection()
        
        # Perform comprehensive threat correlation
        await self._perform_comprehensive_threat_correlation()
        
        # Analyze attack chains
        await self._analyze_attack_chains()
        
        # Perform compliance analysis
        await self._perform_compliance_analysis()
        
        logger.info("Advanced security analysis completed")
    
    async def _analyze_communication_patterns(self):
        """Analyze communication patterns for anomalies"""
        
        # Analyze traffic flows
        flow_stats = defaultdict(lambda: {'packet_count': 0, 'byte_count': 0})
        
        for connection in self.network_entities['connections']:
            flow_key = f"{connection['source_ip']}->{connection['dest_ip']}"
            flow_stats[flow_key]['packet_count'] += 1
            flow_stats[flow_key]['byte_count'] += connection.get('packet_size', 0)
        
        # Detect unusual traffic patterns
        for flow_key, stats in flow_stats.items():
            if stats['byte_count'] > 100_000_000:  # >100MB
                source_ip, dest_ip = flow_key.split('->')
                await self._create_security_event(
                    event_type="large_data_transfer",
                    severity="MEDIUM",
                    source_ip=source_ip,
                    dest_ip=dest_ip,
                    description=f"Large data transfer detected: {stats['byte_count']:,} bytes",
                    evidence={'byte_count': stats['byte_count'], 'packet_count': stats['packet_count']},
                    attack_category="DATA_EXFILTRATION"
                )
    
    async def _detect_data_exfiltration(self):
        """Detect potential data exfiltration patterns"""
        
        # Analyze large outbound transfers
        outbound_transfers = defaultdict(int)
        
        for connection in self.network_entities['connections']:
            source_ip = connection['source_ip']
            if self._is_internal_ip(source_ip):
                dest_ip = connection['dest_ip']
                if not self._is_internal_ip(dest_ip):
                    outbound_transfers[f"{source_ip}->{dest_ip}"] += connection.get('packet_size', 0)
        
        # Flag suspicious transfers
        for transfer_key, total_bytes in outbound_transfers.items():
            if total_bytes > 50_000_000:  # >50MB
                source_ip, dest_ip = transfer_key.split('->')
                await self._create_security_event(
                    event_type="data_exfiltration",
                    severity="HIGH",
                    source_ip=source_ip,
                    dest_ip=dest_ip,
                    description=f"Large outbound data transfer detected: {total_bytes:,} bytes",
                    evidence={'bytes_transferred': total_bytes},
                    attack_category="DATA_EXFILTRATION"
                )
    
    async def _analyze_protocol_anomalies(self):
        """Analyze protocol usage for anomalies"""
        
        # Check for unusual protocol distributions
        total_packets = sum(self.protocol_stats.values())
        
        for protocol, count in self.protocol_stats.items():
            percentage = (count / total_packets) * 100
            
            # Flag protocols with unusual usage patterns
            if protocol in ['DNS', 'ICMP'] and percentage > 30:
                await self._create_security_event(
                    event_type="protocol_anomaly",
                    severity="MEDIUM",
                    description=f"Unusual {protocol} traffic volume: {percentage:.1f}% of total traffic",
                    evidence={'protocol': protocol, 'percentage': percentage, 'packet_count': count},
                    attack_category="ANOMALOUS_BEHAVIOR"
                )
    
    async def _detect_lateral_movement(self):
        """Detect lateral movement patterns"""
        
        # Analyze internal-to-internal communications
        internal_communications = defaultdict(set)
        
        for connection in self.network_entities['connections']:
            source_ip = connection['source_ip']
            dest_ip = connection['dest_ip']
            
            if self._is_internal_ip(source_ip) and self._is_internal_ip(dest_ip):
                internal_communications[source_ip].add(dest_ip)
        
        # Flag hosts communicating with many internal hosts
        for source_ip, destinations in internal_communications.items():
            if len(destinations) > 10:  # Communicating with >10 internal hosts
                await self._create_security_event(
                    event_type="lateral_movement",
                    severity="MEDIUM",
                    source_ip=source_ip,
                    description=f"Potential lateral movement: {source_ip} communicating with {len(destinations)} internal hosts",
                    evidence={'destination_count': len(destinations), 'destinations': list(destinations)[:10]},
                    attack_category="LATERAL_MOVEMENT"
                )
    
    async def _statistical_anomaly_detection(self):
        """Perform statistical anomaly detection"""
        
        # Analyze packet size distributions
        packet_sizes = []
        for connection in self.network_entities['connections']:
            packet_sizes.append(connection.get('packet_size', 0))
        
        if packet_sizes:
            avg_size = sum(packet_sizes) / len(packet_sizes)
            
            # Flag unusually large packets
            for connection in self.network_entities['connections']:
                packet_size = connection.get('packet_size', 0)
                if packet_size > avg_size * 10:  # 10x larger than average
                    await self._create_security_event(
                        event_type="anomalous_packet_size",
                        severity="LOW",
                        source_ip=connection['source_ip'],
                        dest_ip=connection['dest_ip'],
                        description=f"Unusually large packet detected: {packet_size} bytes (avg: {avg_size:.0f})",
                        evidence={'packet_size': packet_size, 'average_size': avg_size},
                        attack_category="ANOMALOUS_BEHAVIOR"
                    )
    
    def _generate_analysis_summary(self) -> Dict[str, Any]:
        """Generate comprehensive analysis summary"""
        
        hosts = self.network_entities['hosts']
        security_events = self.network_entities['security_events']
        
        # Calculate security score
        security_score = 100
        critical_events = len([e for e in security_events if e.severity == 'CRITICAL'])
        high_events = len([e for e in security_events if e.severity == 'HIGH'])
        medium_events = len([e for e in security_events if e.severity == 'MEDIUM'])
        
        security_score -= critical_events * 30
        security_score -= high_events * 20
        security_score -= medium_events * 10
        security_score = max(0, security_score)
        
        return {
            'analysis_timestamp': datetime.now().isoformat(),
            'total_packets': self.packet_stats['total_packets'],
            'total_bytes': self.packet_stats['total_bytes'],
            'analysis_duration': 'unknown',
            'hosts_discovered': len(hosts),
            'internal_hosts': len([h for h in hosts.values() if h['is_internal']]),
            'external_hosts': len([h for h in hosts.values() if not h['is_internal']]),
            'services_discovered': len(self.network_entities.get('services', {})),
            'protocols_detected': list(self.protocol_stats.keys()),
            'security_events': {
                'total': len(security_events),
                'critical': critical_events,
                'high': high_events,
                'medium': medium_events,
                'low': len([e for e in security_events if e.severity == 'LOW'])
            },
            'security_score': security_score,
            'risk_level': 'LOW' if security_score >= 80 else 'MEDIUM' if security_score >= 50 else 'HIGH',
            'top_threats': self._get_top_threats(),
            'recommendations': self._generate_recommendations()
        }
    
    async def _convert_payload_threats_to_events(self, payload_analysis: Dict, packet_info: Dict):
        """Convert payload analysis threats to security events"""
        
        threats_detected = payload_analysis.get('threats_detected', [])
        
        for threat in threats_detected:
            # Create security event from threat detection
            await self._create_security_event(
                event_type=threat.get('attack_type', 'unknown_threat'),
                severity=threat.get('severity', 'MEDIUM'),
                source_ip=packet_info.get('source_ip'),
                dest_ip=packet_info.get('dest_ip'),
                source_port=packet_info.get('source_port'),
                dest_port=packet_info.get('dest_port'),
                protocol=packet_info.get('protocol', 'TCP'),
                description=threat.get('description', 'Threat detected in payload analysis'),
                evidence={
                    'payload_analysis': threat,
                    'hex_evidence': threat.get('evidence', ''),
                    'confidence': threat.get('confidence', 0.0),
                    'attack_vector': threat.get('attack_vector', 'unknown')
                },
                timestamp=packet_info.get('timestamp'),
                attack_category=self._map_attack_type_to_category(threat.get('attack_type', 'unknown')),
                confidence_score=threat.get('confidence', 0.0),
                remediation=threat.get('remediation', [])
            )
    
    def _map_attack_type_to_category(self, attack_type: str) -> str:
        """Map attack type to category"""
        
        category_mapping = {
            'sql_injection_attempt': 'WEB_APPLICATION_ATTACK',
            'xss_attempt': 'WEB_APPLICATION_ATTACK',
            'directory_traversal': 'WEB_APPLICATION_ATTACK',
            'token_injection': 'AUTHENTICATION_ATTACK',
            'command_injection': 'SYSTEM_ATTACK',
            'arp_poisoning': 'NETWORK_ATTACK',
            'dns_tunneling': 'DATA_EXFILTRATION',
            'tls_vulnerability': 'PROTOCOL_ATTACK',
            'zmq_exploitation': 'SERVICE_ATTACK'
        }
        
        return category_mapping.get(attack_type, 'UNKNOWN_ATTACK')

    async def _perform_comprehensive_threat_correlation(self):
        """Perform comprehensive threat correlation analysis"""
        
        logger.info("Performing comprehensive threat correlation...")
        
        # Correlate payload analysis results with security events
        for payload_analysis in self.payload_analyses:
            threats = payload_analysis.get('threats_detected', [])
            
            for threat in threats:
                # Look for related security events
                related_events = self._find_related_security_events(threat)
                
                if related_events:
                    # Create correlation event
                    await self._create_security_event(
                        event_type="threat_correlation",
                        severity="HIGH",
                        description=f"Correlated threat pattern detected: {threat.get('attack_type', 'unknown')}",
                        evidence={
                            'primary_threat': threat,
                            'related_events': [asdict(event) for event in related_events],
                            'correlation_confidence': self._calculate_correlation_confidence(threat, related_events)
                        },
                        attack_category="CORRELATED_ATTACK",
                        confidence_score=0.9
                    )
    
    async def _analyze_attack_chains(self):
        """Analyze potential attack chains and multi-stage attacks"""
        
        logger.info("Analyzing attack chains...")
        
        # Group security events by source IP and time windows
        attack_sequences = self._group_events_by_attack_sequence()
        
        for sequence in attack_sequences:
            if len(sequence) >= 2:  # Multi-stage attack
                await self._create_security_event(
                    event_type="multi_stage_attack",
                    severity="CRITICAL",
                    source_ip=sequence[0].source_ip,
                    description=f"Multi-stage attack detected with {len(sequence)} phases",
                    evidence={
                        'attack_sequence': [asdict(event) for event in sequence],
                        'attack_duration': sequence[-1].timestamp - sequence[0].timestamp,
                        'attack_progression': self._analyze_attack_progression(sequence)
                    },
                    attack_category="ADVANCED_PERSISTENT_THREAT",
                    confidence_score=0.95
                )
    
    async def _perform_compliance_analysis(self):
        """Perform ISO 27001 compliance analysis"""
        
        logger.info("Performing ISO 27001 compliance analysis...")
        
        try:
            # Perform comprehensive compliance analysis
            compliance_assessment = await self.compliance_analyzer.analyze_comprehensive_compliance(
                self.network_entities,
                self.threat_detections
            )
            
            # Store compliance results
            self.network_entities['compliance_assessment'] = {
                'overall_status': compliance_assessment.overall_status.value,
                'compliance_score': compliance_assessment.compliance_score,
                'total_violations': len(compliance_assessment.violations),
                'critical_violations': len([v for v in compliance_assessment.violations if v.severity == 'CRITICAL']),
                'high_violations': len([v for v in compliance_assessment.violations if v.severity == 'HIGH']),
                'recommendations': compliance_assessment.recommendations,
                'assessment_timestamp': compliance_assessment.assessment_timestamp.isoformat()
            }
            
            # Create compliance violation events for critical issues
            critical_violations = [v for v in compliance_assessment.violations if v.severity == 'CRITICAL']
            for violation in critical_violations:
                await self._create_security_event(
                    event_type="compliance_violation",
                    severity="CRITICAL",
                    description=f"Critical ISO 27001 compliance violation: {violation.control_name}",
                    evidence={
                        'control_id': violation.control_id,
                        'violation_type': violation.violation_type,
                        'compliance_gap': violation.compliance_gap,
                        'affected_assets': violation.affected_assets,
                        'risk_rating': violation.risk_rating
                    },
                    attack_category="COMPLIANCE_VIOLATION",
                    confidence_score=0.9,
                    remediation=violation.remediation_actions
                )
            
            logger.info(f"Compliance analysis completed: {compliance_assessment.compliance_score:.1f}% compliant")
            
        except Exception as e:
            logger.error(f"Compliance analysis failed: {e}")
    
    def _find_related_security_events(self, threat: Dict) -> List:
        """Find security events related to a threat"""
        
        related_events = []
        threat_type = threat.get('attack_type', '')
        
        # Look for events of similar type or from same source
        for event in self.network_entities['security_events']:
            if (event.event_type == threat_type or
                self._are_attacks_related(threat_type, event.event_type)):
                related_events.append(event)
        
        return related_events
    
    def _are_attacks_related(self, attack1: str, attack2: str) -> bool:
        """Check if two attack types are related"""
        
        related_groups = [
            ['sql_injection_attempt', 'xss_attempt', 'directory_traversal'],  # Web attacks
            ['arp_poisoning', 'port_scanning', 'dns_tunneling'],  # Network attacks
            ['token_injection', 'authentication_bypass', 'privilege_escalation'],  # Auth attacks
            ['command_injection', 'privilege_escalation', 'lateral_movement']  # System attacks
        ]
        
        for group in related_groups:
            if attack1 in group and attack2 in group:
                return True
        
        return False
    
    def _calculate_correlation_confidence(self, threat: Dict, related_events: List) -> float:
        """Calculate confidence score for threat correlation"""
        
        base_confidence = 0.5
        
        # Increase confidence based on number of related events
        confidence = base_confidence + (len(related_events) * 0.1)
        
        # Increase confidence if events are close in time
        if related_events:
            time_proximity = self._calculate_time_proximity(related_events)
            confidence += time_proximity * 0.2
        
        return min(1.0, confidence)
    
    def _calculate_time_proximity(self, events: List) -> float:
        """Calculate time proximity factor for events"""
        
        if len(events) < 2:
            return 0.0
        
        timestamps = [event.timestamp for event in events]
        time_span = max(timestamps) - min(timestamps)
        
        # Higher proximity for events within shorter time spans
        if time_span < 60:  # Within 1 minute
            return 1.0
        elif time_span < 300:  # Within 5 minutes
            return 0.8
        elif time_span < 3600:  # Within 1 hour
            return 0.5
        else:
            return 0.2
    
    def _group_events_by_attack_sequence(self) -> List[List]:
        """Group security events into potential attack sequences"""
        
        sequences = []
        events_by_source = defaultdict(list)
        
        # Group events by source IP
        for event in self.network_entities['security_events']:
            if event.source_ip:
                events_by_source[event.source_ip].append(event)
        
        # Analyze each source for attack sequences
        for source_ip, events in events_by_source.items():
            if len(events) >= 2:
                # Sort by timestamp
                events.sort(key=lambda x: x.timestamp)
                
                # Group events within time windows
                current_sequence = [events[0]]
                
                for i in range(1, len(events)):
                    time_diff = events[i].timestamp - events[i-1].timestamp
                    
                    if time_diff <= 3600:  # Within 1 hour
                        current_sequence.append(events[i])
                    else:
                        if len(current_sequence) >= 2:
                            sequences.append(current_sequence)
                        current_sequence = [events[i]]
                
                if len(current_sequence) >= 2:
                    sequences.append(current_sequence)
        
        return sequences
    
    def _analyze_attack_progression(self, sequence: List) -> Dict:
        """Analyze the progression of an attack sequence"""
        
        progression = {
            'phases': [],
            'escalation_detected': False,
            'lateral_movement': False,
            'data_access_attempts': False
        }
        
        for i, event in enumerate(sequence):
            phase = {
                'phase_number': i + 1,
                'event_type': event.event_type,
                'severity': event.severity,
                'timestamp': event.timestamp,
                'description': event.description
            }
            progression['phases'].append(phase)
            
            # Check for escalation patterns
            if i > 0 and self._is_escalation(sequence[i-1], event):
                progression['escalation_detected'] = True
            
            # Check for lateral movement
            if 'lateral' in event.event_type or 'movement' in event.description.lower():
                progression['lateral_movement'] = True
            
            # Check for data access attempts
            if any(term in event.event_type for term in ['data', 'file', 'directory', 'exfiltration']):
                progression['data_access_attempts'] = True
        
        return progression
    
    def _is_escalation(self, prev_event, current_event) -> bool:
        """Check if current event represents escalation from previous"""
        
        severity_levels = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        
        prev_level = severity_levels.get(prev_event.severity, 1)
        current_level = severity_levels.get(current_event.severity, 1)
        
        return current_level > prev_level
    
    def _get_top_threats(self) -> List[Dict[str, Any]]:
        """Get top security threats detected"""
        
        threat_counts = defaultdict(int)
        for event in self.network_entities['security_events']:
            threat_counts[event.event_type] += 1
        
        return [
            {'threat_type': threat, 'count': count}
            for threat, count in sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ]
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on findings"""
        
        recommendations = []
        security_events = self.network_entities['security_events']
        
        if any(e.event_type == 'port_scanning' for e in security_events):
            recommendations.append("Implement network segmentation and intrusion detection systems")
        
        if any(e.event_type == 'sql_injection_attempt' for e in security_events):
            recommendations.append("Review web application security and implement input validation")
        
        if any(e.event_type == 'dns_tunneling_attempt' for e in security_events):
            recommendations.append("Implement DNS monitoring and filtering solutions")
        
        if any(e.event_type == 'large_data_transfer' for e in security_events):
            recommendations.append("Monitor for data exfiltration and implement DLP solutions")
        
        # Default recommendations
        recommendations.extend([
            "Regular security assessments and penetration testing",
            "Keep systems updated with latest security patches",
            "Implement comprehensive logging and monitoring",
            "Employee security awareness training"
        ])
        
        return recommendations
    
    # Missing methods that are called but not implemented
    async def _analyze_udp_layer(self, packet, timestamp: float):
        """Analyze UDP layer"""
        udp = packet[UDP]
        ip = packet[IP]
        
        src_port = udp.sport
        dst_port = udp.dport
        
        # Service identification
        service_info = self._identify_service(dst_port, 'udp')
        
        # Update host statistics
        host_src = self.network_entities['hosts'][ip.src]
        host_dst = self.network_entities['hosts'][ip.dst]
        
        host_src['protocols'].add('UDP')
        host_dst['protocols'].add('UDP')
        
        # Record connection
        connection = {
            'timestamp': timestamp,
            'source_ip': ip.src,
            'dest_ip': ip.dst,
            'source_port': src_port,
            'dest_port': dst_port,
            'protocol': 'UDP',
            'packet_size': len(packet),
            'connection_type': 'udp_communication'
        }
        
        self.network_entities['connections'].append(connection)
    
    async def _analyze_arp_layer(self, packet, timestamp: float):
        """Analyze ARP layer"""
        arp = packet[ARP]
        
        # Store ARP information
        arp_record = {
            'timestamp': timestamp,
            'operation': arp.op,  # 1 = request, 2 = reply
            'sender_ip': arp.psrc,
            'sender_mac': arp.hwsrc,
            'target_ip': arp.pdst,
            'target_mac': arp.hwdst
        }
        
        arp_key = f"{arp.psrc}_{arp.hwsrc}"
        self.network_entities['arp_table'][arp_key] = arp_record
        
        # Detect ARP poisoning
        await self._detect_arp_poisoning(arp_record)
    
    async def _detect_arp_poisoning(self, arp_record: Dict):
        """Detect ARP poisoning attempts"""
        sender_ip = arp_record['sender_ip']
        sender_mac = arp_record['sender_mac']
        
        # Check for MAC-IP conflicts
        for existing_key, existing_record in self.network_entities['arp_table'].items():
            if (existing_record['sender_ip'] == sender_ip and
                existing_record['sender_mac'] != sender_mac):
                
                await self._create_security_event(
                    event_type="arp_poisoning_attempt",
                    severity="HIGH",
                    source_ip=sender_ip,
                    description=f"ARP poisoning detected: IP {sender_ip} associated with multiple MACs",
                    evidence={
                        'original_mac': existing_record['sender_mac'],
                        'new_mac': sender_mac,
                        'timestamp': arp_record['timestamp']
                    },
                    timestamp=arp_record['timestamp'],
                    attack_category="NETWORK_ATTACK"
                )
    
    async def _detect_data_exfiltration(self):
        """Detect potential data exfiltration"""
        # Analyze large outbound transfers
        outbound_transfers = defaultdict(int)
        
        for connection in self.network_entities['connections']:
            src_ip = connection['source_ip']
            dst_ip = connection['dest_ip']
            packet_size = connection.get('packet_size', 0)
            
            # Check if source is internal and destination is external
            if (self._is_internal_ip(src_ip) and not self._is_internal_ip(dst_ip)):
                transfer_key = f"{src_ip}->{dst_ip}"
                outbound_transfers[transfer_key] += packet_size
        
        # Flag large transfers
        for transfer_key, total_bytes in outbound_transfers.items():
            if total_bytes > 50_000_000:  # 50MB threshold
                src_ip, dst_ip = transfer_key.split('->')
                
                await self._create_security_event(
                    event_type="data_exfiltration_attempt",
                    severity="HIGH",
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    description=f"Large data transfer detected: {total_bytes:,} bytes",
                    evidence={
                        'bytes_transferred': total_bytes,
                        'transfer_direction': 'outbound'
                    },
                    attack_category="DATA_EXFILTRATION",
                    confidence_score=0.7
                )
    
    async def _analyze_communication_patterns(self):
        """Analyze communication patterns for anomalies"""
        # Analyze traffic flows
        flow_stats = defaultdict(lambda: {'packet_count': 0, 'byte_count': 0})
        
        for connection in self.network_entities['connections']:
            flow_key = f"{connection['source_ip']}->{connection['dest_ip']}"
            flow_stats[flow_key]['packet_count'] += 1
            flow_stats[flow_key]['byte_count'] += connection.get('packet_size', 0)
        
        # Detect unusual traffic patterns
        for flow_key, stats in flow_stats.items():
            if stats['byte_count'] > 100_000_000:  # >100MB
                source_ip, dest_ip = flow_key.split('->')
                await self._create_security_event(
                    event_type="large_data_transfer",
                    severity="MEDIUM",
                    source_ip=source_ip,
                    dest_ip=dest_ip,
                    description=f"Large data transfer detected: {stats['byte_count']:,} bytes",
                    evidence={'byte_count': stats['byte_count'], 'packet_count': stats['packet_count']},
                    attack_category="DATA_EXFILTRATION"
                )
    
    async def _analyze_protocol_anomalies(self):
        """Analyze protocol usage for anomalies"""
        # This is a placeholder for protocol anomaly detection
        pass
    
    async def _detect_lateral_movement(self):
        """Detect lateral movement patterns"""
        # Track internal-to-internal communications
        internal_comms = []
        
        for connection in self.network_entities['connections']:
            src_ip = connection['source_ip']
            dst_ip = connection['dest_ip']
            
            if self._is_internal_ip(src_ip) and self._is_internal_ip(dst_ip):
                internal_comms.append(connection)
        
        # Analyze for suspicious patterns (placeholder)
        if len(internal_comms) > 1000:  # High internal activity
            await self._create_security_event(
                event_type="high_internal_activity",
                severity="MEDIUM",
                description=f"High internal network activity detected: {len(internal_comms)} connections",
                evidence={'internal_connections': len(internal_comms)},
                attack_category="LATERAL_MOVEMENT"
            )
    
    async def _statistical_anomaly_detection(self):
        """Perform statistical anomaly detection"""
        # This is a placeholder for statistical analysis
        pass
    
    async def _analyze_tcp_payload(self, payload: bytes, session: Dict, timestamp: float):
        """Analyze TCP payload for threats"""
        if not payload:
            return
        
        payload_str = payload.decode('utf-8', errors='ignore')
        
        # Store payload sample
        if len(session['payload_data']) < 10:  # Keep first 10 payload samples
            session['payload_data'].append({
                'timestamp': timestamp,
                'size': len(payload),
                'sample': payload_str[:200]  # First 200 chars
            })
        
        # Basic payload analysis for suspicious content
        suspicious_patterns = [
            b'cmd.exe', b'powershell', b'/bin/sh', b'wget', b'curl',
            b'SELECT * FROM', b'UNION SELECT', b'DROP TABLE'
        ]
        
        for pattern in suspicious_patterns:
            if pattern in payload:
                await self._create_security_event(
                    event_type="suspicious_payload",
                    severity="MEDIUM",
                    source_ip=session['source_ip'],
                    dest_ip=session['dest_ip'],
                    source_port=session['source_port'],
                    dest_port=session['dest_port'],
                    description=f"Suspicious payload pattern detected: {pattern.decode()}",
                    evidence={'pattern': pattern.decode(), 'payload_sample': payload_str[:100]},
                    timestamp=timestamp,
                    attack_category="PAYLOAD_ANALYSIS"
                )
    
    async def _detect_threats_in_packet(self, packet, timestamp: float):
        """Real-time threat detection in individual packets"""
        # This is a placeholder for real-time threat detection
        pass