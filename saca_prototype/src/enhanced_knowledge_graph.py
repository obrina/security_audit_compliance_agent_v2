"""
Enhanced Knowledge Graph for Comprehensive Security Analysis
Integrates LightRAG with Neo4j and Jina reranker for advanced threat correlation
"""

import asyncio
import json
import logging
from typing import Dict, List, Any, Optional
from dataclasses import asdict
import networkx as nx
from neo4j import GraphDatabase
from datetime import datetime
import numpy as np

# Use the installed lightrag package with correct API
from lightrag.core import Generator, Retriever, Embedder, Sequential
from lightrag.core.model_client import ModelClient
from lightrag.core.embedder import EmbedderOutputType
from lightrag.core.generator import GeneratorOutputType

from .jina_reranker import JinaRerankerService
from .enhanced_payload_analyzer import ThreatDetection

logger = logging.getLogger(__name__)

class EnhancedSecurityKnowledgeGraph:
    """
    Advanced Security Knowledge Graph with comprehensive threat analysis capabilities
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.generator = None
        self.embedder = None
        self.retriever = None
        self.neo4j_driver = None
        self.jina_reranker = None
        self.knowledge_documents = []
        self.entity_relationships = []
        
        # ISO 27001 controls mapping
        self.iso27001_controls = {
            'A.9.4.2': 'Secure Log-on Procedures',
            'A.13.1.1': 'Network Controls',
            'A.13.2.1': 'Information Transfer Policies',
            'A.14.1.2': 'Securing Application Services',
            'A.14.2.1': 'Secure Development Policy',
            'A.14.2.5': 'Secure System Engineering Principles',
            'A.16.1.2': 'Reporting Information Security Incidents',
            'A.16.1.4': 'Assessment of Information Security Events',
            'A.12.6.1': 'Management of Technical Vulnerabilities'
        }
        
    async def initialize(self):
        """Initialize enhanced knowledge graph components"""
        logger.info("Initializing Enhanced Security Knowledge Graph...")
        
        try:
            # Initialize Neo4j connection
            await self._initialize_neo4j()
            
            # Initialize Jina reranker
            self.jina_reranker = JinaRerankerService(self.config)
            
            # Initialize LightRAG components
            await self._initialize_lightrag_components()
            
            logger.info("Enhanced Security Knowledge Graph initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize enhanced knowledge graph: {e}")
            raise
    
    async def _initialize_neo4j(self):
        """Initialize Neo4j database connection with enhanced schema"""
        neo4j_config = self.config.get('neo4j', {})
        
        self.neo4j_driver = GraphDatabase.driver(
            neo4j_config.get('uri', 'bolt://localhost:7687'),
            auth=(
                neo4j_config.get('username', 'neo4j'),
                neo4j_config.get('password', 'password')
            )
        )
        
        # Test connection
        with self.neo4j_driver.session() as session:
            result = session.run("RETURN 1 as test")
            result.single()
            
        logger.info("Neo4j connection established")
        
        # Create enhanced schema for security analysis
        await self._setup_enhanced_neo4j_schema()
    
    async def _setup_enhanced_neo4j_schema(self):
        """Setup comprehensive Neo4j schema for security analysis"""
        
        schema_queries = [
            # Node constraints
            "CREATE CONSTRAINT host_ip IF NOT EXISTS FOR (h:Host) REQUIRE h.ip_address IS UNIQUE",
            "CREATE CONSTRAINT event_id IF NOT EXISTS FOR (e:SecurityEvent) REQUIRE e.event_id IS UNIQUE",
            "CREATE CONSTRAINT service_id IF NOT EXISTS FOR (s:Service) REQUIRE s.service_id IS UNIQUE",
            "CREATE CONSTRAINT attack_id IF NOT EXISTS FOR (a:Attack) REQUIRE a.attack_id IS UNIQUE",
            "CREATE CONSTRAINT vuln_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.vuln_id IS UNIQUE",
            "CREATE CONSTRAINT control_id IF NOT EXISTS FOR (c:ISO27001Control) REQUIRE c.control_id IS UNIQUE",
            
            # Performance indexes
            "CREATE INDEX host_reputation IF NOT EXISTS FOR (h:Host) ON (h.reputation)",
            "CREATE INDEX event_severity IF NOT EXISTS FOR (e:SecurityEvent) ON (e.severity)",
            "CREATE INDEX event_type IF NOT EXISTS FOR (e:SecurityEvent) ON (e.event_type)",
            "CREATE INDEX attack_type IF NOT EXISTS FOR (a:Attack) ON (a.attack_type)",
            "CREATE INDEX service_port IF NOT EXISTS FOR (s:Service) ON (s.port)",
            "CREATE INDEX connection_timestamp IF NOT EXISTS FOR (c:Connection) ON (c.timestamp)",
            "CREATE INDEX payload_hash IF NOT EXISTS FOR (p:Payload) ON (p.hash)",
            
            # Full-text search indexes
            "CALL db.index.fulltext.createNodeIndex('security_events_fulltext', ['SecurityEvent'], ['description', 'evidence']) IF NOT EXISTS",
            "CALL db.index.fulltext.createNodeIndex('hosts_fulltext', ['Host'], ['hostname', 'description']) IF NOT EXISTS",
            "CALL db.index.fulltext.createNodeIndex('attacks_fulltext', ['Attack'], ['description', 'indicators']) IF NOT EXISTS",
            "CALL db.index.fulltext.createNodeIndex('payloads_fulltext', ['Payload'], ['ascii_content', 'analysis']) IF NOT EXISTS"
        ]
        
        with self.neo4j_driver.session() as session:
            for query in schema_queries:
                try:
                    session.run(query)
                except Exception as e:
                    logger.warning(f"Schema setup warning: {e}")
        
        logger.info("Enhanced Neo4j schema setup completed")
    
    async def _initialize_lightrag_components(self):
        """Initialize LightRAG components with enhanced security-focused configuration"""
        
        lightrag_config = self.config.get('lightrag', {})
        openai_config = self.config.get('openai', {})
        
        # Initialize Generator for LLM operations
        self.generator = Generator(
            model_client=ModelClient.from_config({
                'model': openai_config.get('model', 'gpt-4o-mini'),
                'api_key': openai_config.get('api_key'),
                'max_tokens': openai_config.get('max_tokens', 4096)
            })
        )
        
        # Initialize Embedder for text embeddings
        self.embedder = Embedder(
            model_client=ModelClient.from_config({
                'model': openai_config.get('embedding_model', 'text-embedding-3-large'),
                'api_key': openai_config.get('api_key')
            })
        )
        
        # Initialize Retriever for document retrieval
        self.retriever = Retriever()
        
        logger.info("LightRAG components initialized with security-focused configuration")
    
    async def _generate_security_analysis(self, prompt: str, system_prompt: str = None) -> str:
        """Generate security analysis using LightRAG Generator"""
        
        if system_prompt is None:
            system_prompt = """You are an expert cybersecurity analyst and network forensics specialist with deep expertise in:

CORE COMPETENCIES:
- Advanced threat detection and classification
- Multi-vector attack analysis and correlation
- Network protocol security assessment
- Vulnerability analysis and risk evaluation
- ISO 27001 compliance and regulatory frameworks
- Incident response and digital forensics

ANALYSIS APPROACH:
- Extract security-relevant entities with precise relationships
- Identify attack patterns and threat indicators
- Correlate events across time and network topology
- Assess compliance violations and control gaps
- Provide actionable threat intelligence

Always maintain security context and provide detailed technical analysis suitable for both automated processing and human review."""

        try:
            if self.generator:
                # Use the generator to create analysis
                full_prompt = f"{system_prompt}\n\nUser Query: {prompt}"
                result = await self.generator.acall(full_prompt)
                # Handle the result based on its type
                if hasattr(result, 'data'):
                    return result.data
                return str(result)
            else:
                return f"Security analysis completed with limitations. Generator not initialized."
            
        except Exception as e:
            logger.error(f"Security analysis generation error: {e}")
            return f"Security analysis completed with limitations. Error: {str(e)[:100]}"
    
    async def _create_embeddings(self, texts: List[str]) -> np.ndarray:
        """Create embeddings with security context"""
        
        try:
            if self.embedder:
                # Enhance texts with security context
                enhanced_texts = []
                for text in texts:
                    enhanced_text = f"SECURITY ANALYSIS CONTEXT: {text}"
                    enhanced_texts.append(enhanced_text)
                
                # Create embeddings
                embeddings_result = await self.embedder.acall(enhanced_texts)
                # Handle the result based on its type
                if hasattr(embeddings_result, 'data'):
                    return embeddings_result.data
                return embeddings_result
            else:
                # Return valid embeddings shape
                batch_size = len(texts) if isinstance(texts, list) else 1
                return np.zeros((batch_size, 3072), dtype=np.float32)
            
        except Exception as e:
            logger.error(f"Embedding creation error: {e}")
            # Return valid embeddings shape
            batch_size = len(texts) if isinstance(texts, list) else 1
            return np.zeros((batch_size, 3072), dtype=np.float32)
    
    async def build_comprehensive_knowledge_graph(self, network_entities: Dict[str, Any], 
                                                threat_detections: List[ThreatDetection] = None) -> bool:
        """Build comprehensive knowledge graph from network entities and threat detections"""
        
        logger.info("Building comprehensive security knowledge graph...")
        
        try:
            # Create enhanced security documents
            documents = await self._create_comprehensive_security_documents(
                network_entities, threat_detections
            )
            
            # Process documents with reranking
            await self._process_documents_with_reranking(documents)
            
            # Build enhanced Neo4j graph
            await self._build_enhanced_neo4j_graph(network_entities, threat_detections)
            
            logger.info(f"Comprehensive knowledge graph built successfully with {len(documents)} documents")
            return True
            
        except Exception as e:
            logger.error(f"Failed to build comprehensive knowledge graph: {e}")
            return False
    
    async def _create_comprehensive_security_documents(self, network_entities: Dict[str, Any], 
                                                     threat_detections: List[ThreatDetection] = None) -> List[str]:
        """Create comprehensive security-focused documents with enhanced context"""
        
        documents = []
        
        # Document 1: Multi-Attack Threat Landscape Analysis
        doc1 = await self._create_multi_attack_landscape_document(network_entities, threat_detections)
        documents.append(doc1)
        
        # Document 2: Network Infrastructure Security Assessment
        doc2 = await self._create_infrastructure_security_document(network_entities)
        documents.append(doc2)
        
        # Document 3: Attack Chain and Correlation Analysis
        doc3 = await self._create_attack_correlation_document(network_entities, threat_detections)
        documents.append(doc3)
        
        # Document 4: Comprehensive ISO 27001 Compliance Analysis
        doc4 = await self._create_comprehensive_compliance_document(network_entities, threat_detections)
        documents.append(doc4)
        
        # Document 5: Payload Analysis and Hexdump Intelligence
        doc5 = await self._create_payload_intelligence_document(threat_detections)
        documents.append(doc5)
        
        # Document 6: Temporal Attack Pattern Analysis
        doc6 = await self._create_temporal_analysis_document(network_entities, threat_detections)
        documents.append(doc6)
        
        self.knowledge_documents = documents
        logger.info(f"Created {len(documents)} comprehensive security analysis documents")
        
        return documents
    
    async def _create_multi_attack_landscape_document(self, entities: Dict[str, Any], 
                                                    threat_detections: List[ThreatDetection] = None) -> str:
        """Create comprehensive multi-attack landscape analysis document"""
        
        security_events = entities.get('security_events', [])
        hosts = entities.get('hosts', {})
        
        # Combine security events with threat detections
        all_threats = []
        if security_events:
            all_threats.extend(security_events)
        if threat_detections:
            all_threats.extend(threat_detections)
        
        # Categorize threats by attack type
        attack_categories = {
            'web_application_attacks': [],
            'network_layer_attacks': [],
            'protocol_vulnerabilities': [],
            'authentication_attacks': [],
            'data_exfiltration_attempts': [],
            'system_exploitation': []
        }
        
        for threat in all_threats:
            attack_type = getattr(threat, 'attack_type', getattr(threat, 'event_type', 'unknown'))
            
            if attack_type in ['sql_injection_attempt', 'xss_attempt', 'directory_traversal']:
                attack_categories['web_application_attacks'].append(threat)
            elif attack_type in ['arp_poisoning', 'port_scanning', 'dns_tunneling']:
                attack_categories['network_layer_attacks'].append(threat)
            elif attack_type in ['tls_vulnerability', 'zmq_exploitation']:
                attack_categories['protocol_vulnerabilities'].append(threat)
            elif attack_type in ['token_injection', 'authentication_bypass']:
                attack_categories['authentication_attacks'].append(threat)
            elif attack_type in ['large_data_transfer', 'data_exfiltration']:
                attack_categories['data_exfiltration_attempts'].append(threat)
            else:
                attack_categories['system_exploitation'].append(threat)
        
        doc = f"""# Comprehensive Multi-Attack Threat Landscape Analysis

## Executive Summary
This document provides detailed analysis of {len(all_threats)} security threats detected across multiple attack vectors, representing a comprehensive view of the current threat landscape affecting the analyzed network infrastructure.

## Threat Distribution Overview

### Attack Vector Analysis
- **Web Application Attacks**: {len(attack_categories['web_application_attacks'])} incidents
- **Network Layer Attacks**: {len(attack_categories['network_layer_attacks'])} incidents  
- **Protocol Vulnerabilities**: {len(attack_categories['protocol_vulnerabilities'])} incidents
- **Authentication Attacks**: {len(attack_categories['authentication_attacks'])} incidents
- **Data Exfiltration Attempts**: {len(attack_categories['data_exfiltration_attempts'])} incidents
- **System Exploitation**: {len(attack_categories['system_exploitation'])} incidents

## Detailed Attack Category Analysis

"""
        
        # Analyze each attack category
        for category, threats in attack_categories.items():
            if threats:
                doc += f"""
### {category.replace('_', ' ').title()} Analysis
**Threat Count**: {len(threats)}
**Risk Assessment**: {self._assess_category_risk_level(threats)}

"""
                
                # Analyze top threats in category
                for i, threat in enumerate(threats[:3], 1):
                    threat_type = getattr(threat, 'attack_type', getattr(threat, 'event_type', 'unknown'))
                    severity = getattr(threat, 'severity', 'UNKNOWN')
                    confidence = getattr(threat, 'confidence_score', getattr(threat, 'confidence', 0.0))
                    description = getattr(threat, 'description', 'No description available')
                    evidence = getattr(threat, 'evidence', {})
                    
                    doc += f"""
**Threat Instance {i}**: {threat_type.replace('_', ' ').title()}
- **Severity Level**: {severity}
- **Confidence Score**: {confidence:.2f}
- **Attack Description**: {description}
- **Technical Evidence**: {json.dumps(evidence, indent=2)[:300]}...
- **ISO 27001 Impact**: {self._map_threat_to_iso_control(threat_type)}
- **Attack Vector**: {self._identify_attack_vector(threat)}
- **Potential Impact**: {self._assess_threat_impact(threat)}

**Threat Intelligence**: This {threat_type} represents a {severity.lower()}-severity security incident that demonstrates {self._analyze_threat_sophistication(threat)}.
"""
        
        # Add correlation analysis
        doc += f"""
## Multi-Vector Attack Correlation

### Attack Chain Analysis
{self._analyze_attack_chains(all_threats)}

### Temporal Correlation Patterns
{self._analyze_temporal_correlations(all_threats)}

### Geographic Attack Distribution
{self._analyze_geographic_patterns(hosts, all_threats)}

### Threat Actor Profiling
{self._analyze_threat_actor_patterns(all_threats)}

## Strategic Security Recommendations

### Immediate Response Actions
1. **Critical Threat Mitigation**: Address {len([t for t in all_threats if getattr(t, 'severity', 'LOW') == 'CRITICAL'])} critical-severity incidents
2. **Attack Vector Hardening**: Implement controls for identified attack vectors
3. **Incident Response Activation**: Initiate formal incident response procedures
4. **Threat Hunting**: Conduct proactive threat hunting based on identified patterns

### Long-term Security Improvements
1. **Defense in Depth**: Implement layered security controls
2. **Continuous Monitoring**: Enhance detection capabilities
3. **Security Awareness**: Update training based on attack patterns
4. **Compliance Alignment**: Address ISO 27001 control gaps

This comprehensive analysis provides the foundation for strategic security decision-making and tactical threat response.
"""
        
        return doc
    
    async def _process_documents_with_reranking(self, documents: List[str]) -> bool:
        """Process documents with Jina reranking optimization"""
        
        logger.info("Processing documents with reranking optimization...")
        
        try:
            # Pre-process documents for optimal processing order
            if self.jina_reranker and self.jina_reranker.api_key:
                # Create a general security query for optimal ordering
                security_query = "comprehensive network security analysis threat detection vulnerability assessment"
                
                # Rerank documents for optimal processing order
                reranked_docs = await self.jina_reranker.rerank_security_documents(
                    security_query, documents, len(documents)
                )
                
                # Process in reranked order
                for i, reranked_doc in enumerate(reranked_docs):
                    logger.info(f"Processing document {i+1}/{len(reranked_docs)} (reranked)...")
                    # Store document content for later retrieval
                    self.knowledge_documents.append(reranked_doc.content)
                    await asyncio.sleep(0.1)  # Brief pause to prevent overwhelming
            else:
                # Process in original order if reranker unavailable
                for i, document in enumerate(documents):
                    logger.info(f"Processing document {i+1}/{len(documents)}...")
                    # Store document content for later retrieval
                    self.knowledge_documents.append(document)
                    await asyncio.sleep(0.1)
            
            logger.info("All documents processed successfully with reranking optimization")
            return True
            
        except Exception as e:
            logger.error(f"Failed to process documents with reranking: {e}")
            return False
    
    async def query_enhanced_security_knowledge(self, query: str, mode: str = "hybrid",
                                              top_k: int = 10,
                                              security_context: Optional[Dict] = None) -> Dict[str, Any]:
        """Query the enhanced security knowledge graph with reranking"""
        
        try:
            # Generate security analysis using the generator
            security_analysis = await self._generate_security_analysis(
                f"Analyze the following security query: {query}"
            )
            
            # Query Neo4j for structured data
            neo4j_result = await self._query_enhanced_neo4j(query, security_context)
            
            # Apply Jina reranking if available
            if self.jina_reranker and self.jina_reranker.api_key:
                # Create documents from results for reranking
                result_documents = [security_analysis] + [str(result) for result in neo4j_result]
                
                reranked_results = await self.jina_reranker.rerank_security_documents(
                    query, result_documents, top_k, security_context
                )
                
                enhanced_analysis = reranked_results[0].content if reranked_results else security_analysis
            else:
                enhanced_analysis = security_analysis
            
            # Combine and enhance results
            combined_result = {
                'query': query,
                'timestamp': datetime.now().isoformat(),
                'lightrag_response': enhanced_analysis,
                'structured_data': neo4j_result,
                'analysis_mode': mode,
                'security_context': security_context,
                'confidence_score': self._calculate_enhanced_confidence_score(
                    enhanced_analysis, neo4j_result, security_context
                ),
                'threat_indicators': self._extract_threat_indicators_from_response(enhanced_analysis),
                'compliance_references': self._extract_compliance_references(enhanced_analysis)
            }
            
            return combined_result
            
        except Exception as e:
            logger.error(f"Enhanced query failed: {e}")
            return {
                'query': query,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    # Helper methods for document creation and analysis
    def _assess_category_risk_level(self, threats: List) -> str:
        """Assess risk level for a category of threats"""
        if not threats:
            return 'LOW'
        
        critical_count = len([t for t in threats if getattr(t, 'severity', 'LOW') == 'CRITICAL'])
        high_count = len([t for t in threats if getattr(t, 'severity', 'LOW') == 'HIGH'])
        
        if critical_count > 0:
            return 'CRITICAL'
        elif high_count > len(threats) * 0.5:
            return 'HIGH'
        elif len(threats) > 5:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _map_threat_to_iso_control(self, threat_type: str) -> str:
        """Map threat type to relevant ISO 27001 control"""
        threat_control_mapping = {
            'sql_injection_attempt': 'A.14.2.5 - Secure System Engineering Principles',
            'xss_attempt': 'A.14.2.1 - Secure Development Policy',
            'directory_traversal': 'A.14.2.5 - Secure System Engineering Principles',
            'token_injection': 'A.9.4.2 - Secure Log-on Procedures',
            'arp_poisoning': 'A.13.1.1 - Network Controls',
            'port_scanning': 'A.13.1.1 - Network Controls',
            'dns_tunneling': 'A.13.2.1 - Information Transfer Policies',
            'tls_vulnerability': 'A.13.2.1 - Information Transfer Policies',
            'zmq_exploitation': 'A.14.1.2 - Securing Application Services'
        }
        
        return threat_control_mapping.get(threat_type, 'A.16.1.4 - Assessment of Information Security Events')
    
    def _identify_attack_vector(self, threat) -> str:
        """Identify the primary attack vector for a threat"""
        threat_type = getattr(threat, 'attack_type', getattr(threat, 'event_type', 'unknown'))
        
        vector_mapping = {
            'sql_injection_attempt': 'Web Application Input Validation',
            'xss_attempt': 'Web Application Client-Side Injection',
            'directory_traversal': 'File System Access Control',
            'token_injection': 'Authentication Mechanism',
            'arp_poisoning': 'Network Layer Protocol',
            'port_scanning': 'Network Service Discovery',
            'dns_tunneling': 'DNS Protocol Abuse',
            'tls_vulnerability': 'Cryptographic Protocol',
            'zmq_exploitation': 'Message Queue Protocol'
        }
        
        return vector_mapping.get(threat_type, 'Unknown Attack Vector')
    
    def _assess_threat_impact(self, threat) -> str:
        """Assess the potential impact of a threat"""
        severity = getattr(threat, 'severity', 'LOW')
        threat_type = getattr(threat, 'attack_type', getattr(threat, 'event_type', 'unknown'))
        
        if severity == 'CRITICAL':
            return 'Complete system compromise, data breach, service disruption'
        elif severity == 'HIGH':
            return 'Significant security breach, potential data exposure, system instability'
        elif severity == 'MEDIUM':
            return 'Security control bypass, limited data access, performance degradation'
        else:
            return 'Minor security concern, reconnaissance activity, policy violation'
    
    def _analyze_threat_sophistication(self, threat) -> str:
        """Analyze the sophistication level of a threat"""
        confidence = getattr(threat, 'confidence_score', getattr(threat, 'confidence', 0.0))
        evidence = getattr(threat, 'evidence', {})
        
        if confidence > 0.9:
            return 'high sophistication with clear attack patterns and advanced techniques'
        elif confidence > 0.7:
            return 'moderate sophistication with recognizable attack methodologies'
        elif confidence > 0.5:
            return 'basic attack techniques with standard exploitation methods'
        else:
            return 'low sophistication or potential false positive requiring further analysis'
    
    async def _query_enhanced_neo4j(self, query: str, security_context: Optional[Dict] = None) -> List[Dict]:
        """Query Neo4j for structured security data"""
        try:
            if not self.neo4j_driver:
                return []
            
            # Simple Neo4j query for security events
            with self.neo4j_driver.session() as session:
                result = session.run(
                    "MATCH (n:SecurityEvent) WHERE n.description CONTAINS $query RETURN n LIMIT 10",
                    query=query
                )
                return [record["n"] for record in result]
        except Exception as e:
            logger.error(f"Neo4j query error: {e}")
            return []
    
    def _calculate_enhanced_confidence_score(self, analysis: str, neo4j_data: List, security_context: Optional[Dict]) -> float:
        """Calculate confidence score for the analysis"""
        base_score = 0.7
        if neo4j_data:
            base_score += 0.2
        if security_context:
            base_score += 0.1
        return min(base_score, 1.0)
    
    def _extract_threat_indicators_from_response(self, response: str) -> List[str]:
        """Extract threat indicators from the response"""
        indicators = []
        # Simple keyword-based extraction
        threat_keywords = ['malware', 'attack', 'vulnerability', 'exploit', 'breach', 'intrusion']
        for keyword in threat_keywords:
            if keyword.lower() in response.lower():
                indicators.append(keyword)
        return indicators
    
    def _extract_compliance_references(self, response: str) -> List[str]:
        """Extract compliance references from the response"""
        references = []
        # Look for ISO 27001 control references
        for control_id, control_name in self.iso27001_controls.items():
            if control_id in response or control_name.lower() in response.lower():
                references.append(f"{control_id}: {control_name}")
        return references

    def close(self):
        """Close database connections"""
        if self.neo4j_driver:
            self.neo4j_driver.close()
            logger.info("Enhanced Neo4j connection closed")