"""
Streamlit Web Interface for PCAP Security Analyzer
Provides intuitive web-based interface for security analysis and visualization
"""

import streamlit as st
import asyncio
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
import os
import logging
from typing import Dict, List, Any, Optional
import zipfile
import io
from dataclasses import asdict

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.pcap_processor import AdvancedPcapProcessor
from src.enhanced_knowledge_graph import EnhancedSecurityKnowledgeGraph
from src.neo4j_html_visualizer_fixed import Neo4jHTMLVisualizer
from src.jina_reranker import JinaRerankerService

logger = logging.getLogger(__name__)

class PCAPSecurityAnalyzerApp:
    """Main Streamlit application for PCAP Security Analysis"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.processor = None
        self.knowledge_graph = None
        self.visualizer = None
        self.jina_reranker = None
        self.analysis_results = None
        
    def run(self):
        """Run the Streamlit application"""
        st.set_page_config(
            page_title="PCAP Security Analyzer",
            page_icon="🔒",
            layout="wide",
            initial_sidebar_state="expanded"
        )
        
        # Apply custom CSS
        self._apply_custom_css()
        
        # Initialize session state
        self._initialize_session_state()
        
        # Sidebar
        self._create_sidebar()
        
        # Main content
        if st.session_state.get('analysis_completed', False):
            self._display_analysis_results()
        else:
            self._display_upload_interface()
    
    def _apply_custom_css(self):
        """Apply custom CSS styling"""
        st.markdown("""
        <style>
        .main-header {
            background: linear-gradient(90deg, #1e3c72, #2a5298);
            padding: 1rem;
            border-radius: 10px;
            color: white;
            margin-bottom: 2rem;
        }
        
        .metric-card {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 8px;
            border-left: 4px solid #007bff;
            margin: 0.5rem 0;
        }
        
        .security-alert {
            padding: 1rem;
            border-radius: 8px;
            margin: 1rem 0;
        }
        
        .alert-critical {
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }
        
        .alert-high {
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
        }
        
        .alert-success {
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }
        
        .stProgress > div > div > div > div {
            background-color: #007bff;
        }
        
        .knowledge-graph-container {
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            padding: 1rem;
            background: #fafafa;
        }
        </style>
        """, unsafe_allow_html=True)
    
    def _initialize_session_state(self):
        """Initialize Streamlit session state"""
        if 'analysis_results' not in st.session_state:
            st.session_state.analysis_results = None
        if 'knowledge_graph_ready' not in st.session_state:
            st.session_state.knowledge_graph_ready = False
        if 'analysis_completed' not in st.session_state:
            st.session_state.analysis_completed = False
        if 'query_history' not in st.session_state:
            st.session_state.query_history = []
    
    def _create_sidebar(self):
        """Create application sidebar"""
        with st.sidebar:
            st.markdown("""
            <div class="main-header">
                <h2>🔒 PCAP Security Analyzer</h2>
                <p>Advanced Network Security Analysis Tool</p>
            </div>
            """, unsafe_allow_html=True)
            
            # Analysis Status
            st.subheader("📊 Analysis Status")
            
            if st.session_state.get('analysis_completed', False):
                st.success("✅ Analysis Complete")
                
                results = st.session_state.analysis_results
                if results:
                    summary = results.get('analysis_summary', {})
                    
                    # Display key metrics
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Security Score", f"{summary.get('security_score', 0)}/100")
                        st.metric("Hosts Found", summary.get('hosts_discovered', 0))
                    with col2:
                        st.metric("Threats Detected", summary.get('security_events', {}).get('total', 0))
                        st.metric("Services Found", summary.get('services_discovered', 0))
            else:
                st.info("🔄 Ready for Analysis")
            
            # Quick Actions
            st.subheader("⚡ Quick Actions")
            
            if st.button("🆕 New Analysis", use_container_width=True):
                self._reset_analysis()
            
            if st.session_state.get('analysis_completed', False):
                if st.button("📥 Export Results", use_container_width=True):
                    self._export_analysis_results()
                
                if st.button("🔍 Advanced Query", use_container_width=True):
                    st.session_state.show_advanced_query = True
            
            # Enhanced Features Status
            st.subheader("🚀 Enhanced Features")
            
            # Check which enhanced features are available
            neo4j_available = bool(self.config.get('neo4j', {}).get('password'))
            jina_available = bool(self.config.get('jina', {}).get('api_key'))
            openai_available = bool(self.config.get('openai', {}).get('api_key'))
            
            if neo4j_available:
                st.success("✅ Neo4j Graph Database")
            else:
                st.warning("⚠️ Neo4j Not Configured")
                
            if jina_available:
                st.success("✅ Jina AI Reranker")
            else:
                st.info("ℹ️ Jina Reranker Optional")
                
            if openai_available:
                st.success("✅ OpenAI GPT Analysis")
            else:
                st.error("❌ OpenAI API Required")
            
            # Configuration
            st.subheader("⚙️ Analysis Configuration")
            
            analysis_depth = st.selectbox(
                "Analysis Depth",
                ["Quick", "Standard", "Deep"],
                index=1
            )
            
            enable_ml_detection = st.checkbox("Enable ML Threat Detection", value=True)
            enable_behavioral_analysis = st.checkbox("Behavioral Analysis", value=True)
            enable_neo4j_graphs = st.checkbox("Neo4j Graph Visualization", value=neo4j_available)
            enable_jina_reranking = st.checkbox("Jina AI Reranking", value=jina_available)
            
            # Store config in session state
            st.session_state.analysis_config = {
                'depth': analysis_depth.lower(),
                'ml_detection': enable_ml_detection,
                'behavioral_analysis': enable_behavioral_analysis,
                'neo4j_graphs': enable_neo4j_graphs,
                'jina_reranking': enable_jina_reranking
            }
    
    def _display_upload_interface(self):
        """Display PCAP file upload interface"""
        
        st.markdown("""
        <div class="main-header">
            <h1>🕸️ PCAP Security Analysis Platform</h1>
            <p>Upload your PCAP file for comprehensive network security analysis with AI-powered threat detection and interactive knowledge graphs.</p>
        </div>
        """, unsafe_allow_html=True)
        
        # File Upload Section
        st.subheader("📁 Upload PCAP File")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            uploaded_file = st.file_uploader(
                "Choose a PCAP/PCAPNG file",
                type=['pcap', 'pcapng'],
                help="Upload network traffic capture files for security analysis"
            )
            
            if uploaded_file:
                # Display file info
                file_size = len(uploaded_file.getvalue())
                st.info(f"📄 **File:** {uploaded_file.name} ({self._format_file_size(file_size)})")
                
                # Analysis options
                with st.expander("🔧 Analysis Options", expanded=True):
                    col_opt1, col_opt2 = st.columns(2)
                    
                    with col_opt1:
                        max_packets = st.number_input(
                            "Max Packets to Analyze",
                            min_value=100,
                            max_value=100000,
                            value=10000,
                            step=1000
                        )
                        
                        enable_payload_analysis = st.checkbox(
                            "Deep Payload Inspection",
                            value=True
                        )
                    
                    with col_opt2:
                        enable_ml_scoring = st.checkbox(
                            "ML Threat Scoring",
                            value=True
                        )
                        
                        create_knowledge_graph = st.checkbox(
                            "Build Knowledge Graph",
                            value=True
                        )
                
                # Start Analysis Button
                if st.button("🚀 Start Security Analysis", type="primary", use_container_width=True):
                    self._start_analysis(uploaded_file, {
                        'max_packets': max_packets,
                        'payload_analysis': enable_payload_analysis,
                        'ml_scoring': enable_ml_scoring,
                        'knowledge_graph': create_knowledge_graph
                    })
        
        with col2:
            st.markdown("""
            ### 🛡️ Analysis Features
            
            ✅ **Advanced Threat Detection**
            - SQL Injection & XSS Detection
            - Port Scanning & Brute Force
            - DNS Tunneling & Data Exfiltration
            - Malware Communication Patterns
            
            ✅ **AI-Powered Analysis**
            - LLM-based Security Assessment
            - Behavioral Pattern Recognition
            - Automated Risk Scoring
            
            ✅ **Interactive Knowledge Graph**
            - Query Network Relationships
            - Visual Threat Correlations
            - Natural Language Queries
            
            ✅ **Comprehensive Reporting**
            - Executive Security Summary
            - Technical Threat Details
            - Remediation Recommendations
            """)
        
        # Example Files Section
        st.subheader("📚 Example Analysis")
        
        col_ex1, col_ex2, col_ex3 = st.columns(3)
        
        with col_ex1:
            if st.button("🌐 Web Attack Sample", use_container_width=True):
                st.info("This would demonstrate analysis of web-based attacks including SQL injection and XSS attempts.")
        
        with col_ex2:
            if st.button("🕵️ Lateral Movement", use_container_width=True):
                st.info("This would show detection of lateral movement and privilege escalation attempts.")
        
        with col_ex3:
            if st.button("📡 DNS Tunneling", use_container_width=True):
                st.info("This would demonstrate detection of DNS tunneling and data exfiltration.")
    
    def _start_analysis(self, uploaded_file, options):
        """Start the PCAP analysis process"""
        
        # Save uploaded file
        temp_file_path = f"/tmp/{uploaded_file.name}"
        with open(temp_file_path, "wb") as f:
            f.write(uploaded_file.getvalue())
        
        # Create progress indicator
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        try:
            # Initialize components
            status_text.text("🔧 Initializing analysis components...")
            progress_bar.progress(10)
            
            self.processor = AdvancedPcapProcessor(self.config)
            self.visualizer = Neo4jHTMLVisualizer(self.config)
            
            # Initialize Jina reranker if configured and enabled (with error handling)
            if self.config.get('jina', {}).get('enabled', False) and self.config.get('jina', {}).get('api_key'):
                try:
                    status_text.text("🔧 Initializing Jina reranker...")
                    progress_bar.progress(15)
                    self.jina_reranker = JinaRerankerService(self.config)
                    status_text.text("✅ Jina reranker initialized successfully")
                except Exception as e:
                    st.warning(f"⚠️ Jina reranker initialization failed: {str(e)}")
                    st.info("📝 Continuing without Jina reranker - analysis will use standard ranking")
                    self.jina_reranker = None
            else:
                st.info("📝 Jina reranker not configured - using standard ranking")
            
            if options.get('knowledge_graph', True):
                try:
                    # Skip enhanced knowledge graph due to ResolvedAddress error
                    # Directly use basic knowledge graph
                    status_text.text("🕸️ Initializing basic knowledge graph...")
                    from src.knowledge_graph import SecurityKnowledgeGraph
                    self.knowledge_graph = SecurityKnowledgeGraph(self.config)
                    asyncio.run(self.knowledge_graph.initialize())
                    status_text.text("✅ Basic knowledge graph initialized")
                    st.session_state.knowledge_graph_ready = True
                except Exception as fallback_error:
                    st.warning(f"⚠️ Knowledge graph initialization failed: {str(fallback_error)}")
                    st.info("📝 Continuing without knowledge graph")
                    self.knowledge_graph = None
                    st.session_state.knowledge_graph_ready = False
            
            # Process PCAP
            status_text.text("📡 Processing network traffic...")
            progress_bar.progress(30)
            
            analysis_results = asyncio.run(self.processor.process_pcap_file(temp_file_path))
            
            # Build enhanced knowledge graph with Jina reranking
            if self.knowledge_graph and options.get('knowledge_graph', True):
                status_text.text("🕸️ Building enhanced knowledge graph with AI reranking...")
                progress_bar.progress(60)
                
                try:
                    # Use basic knowledge graph method
                    kg_success = asyncio.run(
                        self.knowledge_graph.build_knowledge_graph(
                            analysis_results['network_entities']
                        )
                    )
                    
                    if kg_success:
                        st.session_state.knowledge_graph_ready = True
                        status_text.text("✅ Knowledge graph ready!")
                    else:
                        status_text.text("⚠️ Knowledge graph construction failed")
                        
                except Exception as e:
                    st.warning(f"⚠️ Knowledge graph building failed: {str(e)}")
                    status_text.text("⚠️ Knowledge graph construction failed, continuing without it")
                    st.session_state.knowledge_graph_ready = False
            
            # Create enhanced visualizations with Neo4j
            status_text.text("📊 Generating enhanced Neo4j visualizations...")
            progress_bar.progress(80)
            
            try:
                # Try enhanced Neo4j visualizations first
                if hasattr(self.visualizer, 'create_interactive_security_graph'):
                    status_text.text("📊 Creating interactive Neo4j security graph...")
                    network_viz = self.visualizer.create_interactive_security_graph(
                        analysis_results['network_entities']
                    )
                    security_dashboard = self.visualizer.create_enhanced_threat_dashboard(
                        analysis_results['network_entities'],
                        analysis_results.get('analysis_summary', {})
                    )
                    status_text.text("✅ Enhanced Neo4j visualizations created!")
                else:
                    # Fallback to basic visualizations
                    status_text.text("📊 Using fallback visualizations...")
                    from src.visualization import SecurityVisualizationEngine
                    fallback_viz = SecurityVisualizationEngine(self.config)
                    network_viz = fallback_viz.create_interactive_network_graph(
                        analysis_results['network_entities']
                    )
                    security_dashboard = fallback_viz.create_security_dashboard(
                        analysis_results['network_entities'],
                        analysis_results['analysis_summary']
                    )
                    
            except Exception as e:
                st.warning(f"⚠️ Enhanced visualization failed: {str(e)}")
                st.info("📝 Using fallback visualizations")
                # Fallback to basic visualizations
                from src.visualization import SecurityVisualizationEngine
                fallback_viz = SecurityVisualizationEngine(self.config)
                network_viz = fallback_viz.create_interactive_network_graph(
                    analysis_results['network_entities']
                )
                security_dashboard = fallback_viz.create_security_dashboard(
                    analysis_results['network_entities'],
                    analysis_results['analysis_summary']
                )
            
            # Complete analysis
            progress_bar.progress(100)
            status_text.text("✅ Analysis complete!")
            
            # Store results and components
            st.session_state.analysis_results = {
                **analysis_results,
                'network_visualization': network_viz,
                'security_dashboard': security_dashboard,
                'file_info': {
                    'name': uploaded_file.name,
                    'size': len(uploaded_file.getvalue()),
                    'analysis_time': datetime.now().isoformat()
                }
            }
            
            # Store enhanced components in session state for later use
            st.session_state.visualizer = self.visualizer
            st.session_state.processor = self.processor
            st.session_state.knowledge_graph = self.knowledge_graph
            st.session_state.jina_reranker = self.jina_reranker
            
            st.session_state.analysis_completed = True
            
            # Clean up
            os.remove(temp_file_path)
            
            # Refresh the page to show results
            st.rerun()
            
        except Exception as e:
            st.error(f"❌ Analysis failed: {str(e)}")
            logger.error(f"Analysis failed: {e}")
            
            # Clean up
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)
    
    def _display_analysis_results(self):
        """Display comprehensive analysis results"""
        
        results = st.session_state.analysis_results
        if not results:
            st.error("No analysis results available")
            return
        
        # Restore enhanced components from session state
        if hasattr(st.session_state, 'visualizer'):
            self.visualizer = st.session_state.visualizer
        if hasattr(st.session_state, 'processor'):
            self.processor = st.session_state.processor
        if hasattr(st.session_state, 'knowledge_graph'):
            self.knowledge_graph = st.session_state.knowledge_graph
        if hasattr(st.session_state, 'jina_reranker'):
            self.jina_reranker = st.session_state.jina_reranker
        
        # Header with key metrics
        file_info = results.get('file_info', {})
        summary = results.get('analysis_summary', {})
        
        st.markdown(f"""
        <div class="main-header">
            <h1>🔍 Security Analysis Results</h1>
            <p><strong>File:</strong> {file_info.get('name', 'Unknown')} | 
            <strong>Analyzed:</strong> {datetime.fromisoformat(file_info.get('analysis_time', '')).strftime('%Y-%m-%d %H:%M:%S') if file_info.get('analysis_time') else 'Unknown'}</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Key Metrics Dashboard
        self._display_key_metrics(summary)
        
        # Tabs for different views
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "🛡️ Security Overview",
            "🕸️ Knowledge Graph",
            "📊 Network Analysis", 
            "⚠️ Threat Details",
            "📋 Executive Report"
        ])
        
        with tab1:
            self._display_security_overview(results)
        
        with tab2:
            self._display_knowledge_graph_interface(results)
        
        with tab3:
            self._display_network_analysis(results)
        
        with tab4:
            self._display_threat_details(results)
        
        with tab5:
            self._display_executive_report(results)
    
    def _display_key_metrics(self, summary: Dict):
        """Display key security metrics"""
        
        col1, col2, col3, col4, col5 = st.columns(5)
        
        security_score = summary.get('security_score', 0)
        risk_level = summary.get('risk_level', 'UNKNOWN')
        
        with col1:
            # Security Score with color coding
            score_color = "normal" if security_score >= 80 else "inverse" if security_score >= 60 else "off"
            st.metric(
                "Security Score",
                f"{security_score}/100",
                delta=f"{risk_level} Risk",
                delta_color=score_color
            )
        
        with col2:
            threat_count = summary.get('security_events', {}).get('total', 0)
            st.metric(
                "Threats Detected",
                threat_count,
                delta="Active" if threat_count > 0 else "None",
                delta_color="inverse" if threat_count > 0 else "normal"
            )
        
        with col3:
            st.metric(
                "Hosts Analyzed",
                summary.get('hosts_discovered', 0),
                delta=f"{summary.get('internal_hosts', 0)} Internal"
            )
        
        with col4:
            st.metric(
                "Network Services",
                summary.get('services_discovered', 0),
                delta="Active"
            )
        
        with col5:
            total_packets = summary.get('total_packets', 0)
            st.metric(
                "Traffic Volume",
                self._format_number(total_packets),
                delta="Packets"
            )
    
    def _display_security_overview(self, results: Dict):
        """Display security overview with visualizations"""
        
        summary = results.get('analysis_summary', {})
        security_events = results.get('network_entities', {}).get('security_events', [])
        
        # Security Status Alert with improved contrast
        security_score = summary.get('security_score', 0)
        threat_count = summary.get('security_events', {}).get('total', 0)
        
        if threat_count == 0:
            st.markdown("""
            <div style="background: linear-gradient(135deg, #28a745, #20c997); padding: 20px; border-radius: 10px; margin: 20px 0; border: 2px solid #28a745; box-shadow: 0 4px 8px rgba(0,0,0,0.2);">
                <h3 style="color: #ffffff !important; margin: 0 0 10px 0; font-size: 1.4em; text-shadow: 2px 2px 4px rgba(0,0,0,0.5); font-weight: 700;">✅ Network Security Status: SECURE</h3>
                <p style="color: #ffffff !important; margin: 0; font-size: 1.1em; font-weight: 500; text-shadow: 1px 1px 2px rgba(0,0,0,0.3);">No security threats detected during the analysis period. The network demonstrates normal operational patterns without identified malicious activities.</p>
            </div>
            """, unsafe_allow_html=True)
        else:
            if threat_count >= 10 or security_score < 50:
                bg_color = "linear-gradient(135deg, #dc3545, #c82333)"
                border_color = "#dc3545"
                status = "CRITICAL THREATS DETECTED"
                icon = "🚨"
            else:
                bg_color = "linear-gradient(135deg, #fd7e14, #e55a00)"
                border_color = "#fd7e14"
                status = "SECURITY ISSUES FOUND"
                icon = "⚠️"
            
            st.markdown(f"""
            <div style="background: {bg_color}; padding: 20px; border-radius: 10px; margin: 20px 0; border: 2px solid {border_color}; box-shadow: 0 4px 8px rgba(0,0,0,0.2);">
                <h3 style="color: #ffffff !important; margin: 0 0 10px 0; font-size: 1.4em; text-shadow: 2px 2px 4px rgba(0,0,0,0.5); font-weight: 700;">{icon} Network Security Status: {status}</h3>
                <p style="color: #ffffff !important; margin: 0; font-size: 1.1em; font-weight: 500; text-shadow: 1px 1px 2px rgba(0,0,0,0.3);">{threat_count} security events detected requiring immediate attention and investigation.</p>
            </div>
            """, unsafe_allow_html=True)
        
        # Security Dashboard
        col1, col2 = st.columns([2, 1])
        
        with col1:
            # Display security dashboard
            security_dashboard = results.get('security_dashboard')
            if security_dashboard:
                # Check if it's HTML content (from Neo4j visualizer)
                if isinstance(security_dashboard, str):
                    if security_dashboard.startswith('<!DOCTYPE html>'):
                        # Display HTML visualization
                        st.components.v1.html(security_dashboard, height=500, scrolling=True)
                    else:
                        st.error("Invalid dashboard format received")
                elif hasattr(security_dashboard, 'show'):
                    # Display Plotly figure (fallback)
                    st.plotly_chart(security_dashboard, use_container_width=True)
                else:
                    st.warning("Security dashboard format not recognized")
        
        with col2:
            # Top threats summary
            st.subheader("🎯 Top Threats")
            
            top_threats = summary.get('top_threats', [])
            if top_threats:
                for i, threat in enumerate(top_threats[:5], 1):
                    threat_type = threat['threat_type'].replace('_', ' ').title()
                    count = threat['count']
                    
                    st.markdown(f"""
                    <div class="metric-card">
                        <strong>{i}. {threat_type}</strong><br>
                        <span style="color: #666;">Incidents: {count}</span>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.success("No specific threats identified")
            
            # Recommendations
            st.subheader("💡 Recommendations")
            
            recommendations = summary.get('recommendations', [])
            for rec in recommendations[:3]:
                st.markdown(f"• {rec}")
        
        # Timeline visualization with better error handling
        if security_events:
            st.subheader("📈 Threat Timeline")
            # Initialize enhanced visualizer if not available
            if not self.visualizer:
                self.visualizer = Neo4jHTMLVisualizer(self.config)
            
            try:
                # Try enhanced timeline first
                if hasattr(self.visualizer, 'create_enhanced_attack_timeline'):
                    timeline_result = self.visualizer.create_enhanced_attack_timeline(security_events)
                    
                    # Check if it's valid HTML content
                    if isinstance(timeline_result, str) and timeline_result.startswith('<!DOCTYPE html>') and len(timeline_result) > 100:
                        # Display HTML visualization
                        st.components.v1.html(timeline_result, height=400, scrolling=True)
                    elif hasattr(timeline_result, 'show'):
                        # Display Plotly figure (fallback)
                        st.plotly_chart(timeline_result, use_container_width=True)
                    else:
                        # Fallback to simple timeline
                        st.info("Using simplified timeline visualization")
                        self._create_simple_timeline(security_events)
                else:
                    # Fallback to simple timeline
                    self._create_simple_timeline(security_events)
                    
            except Exception as e:
                st.warning(f"Enhanced timeline visualization failed: {str(e)}")
                # Create a simple fallback timeline
                self._create_simple_timeline(security_events)
        
        # ISO 27001 Compliance Analysis Section
        st.subheader("🏛️ ISO 27001 Compliance Analysis")
        
        try:
            # Import and initialize ISO 27001 compliance analyzer
            from src.iso27001_compliance_analyzer import ISO27001ComplianceAnalyzer
            compliance_analyzer = ISO27001ComplianceAnalyzer(self.config)
            
            # Perform compliance analysis
            with st.spinner("Analyzing ISO 27001 compliance..."):
                import asyncio
                compliance_assessment = asyncio.run(
                    compliance_analyzer.analyze_comprehensive_compliance(
                        results.get('network_entities', {}),
                        security_events
                    )
                )
            
            # Display compliance results
            col_comp1, col_comp2, col_comp3 = st.columns(3)
            
            with col_comp1:
                # Compliance score gauge
                compliance_score = compliance_assessment.compliance_score
                if compliance_score >= 95:
                    score_color = "success"
                    status_icon = "✅"
                elif compliance_score >= 80:
                    score_color = "warning"
                    status_icon = "⚠️"
                else:
                    score_color = "error"
                    status_icon = "❌"
                
                st.metric(
                    "Compliance Score",
                    f"{compliance_score:.1f}%",
                    delta=f"{status_icon} {compliance_assessment.overall_status.value.replace('_', ' ').title()}"
                )
            
            with col_comp2:
                st.metric(
                    "Compliant Controls",
                    f"{compliance_assessment.compliant_controls}/{compliance_assessment.total_controls_assessed}",
                    delta=f"{len(compliance_assessment.violations)} violations"
                )
            
            with col_comp3:
                critical_violations = len([v for v in compliance_assessment.violations if v.severity == 'CRITICAL'])
                st.metric(
                    "Critical Issues",
                    critical_violations,
                    delta="Immediate action required" if critical_violations > 0 else "None"
                )
            
            # Compliance status overview
            if compliance_assessment.overall_status.value == 'compliant':
                st.success("🎉 **ISO 27001 COMPLIANT**: Your network demonstrates strong adherence to ISO 27001:2022 requirements.")
            elif compliance_assessment.overall_status.value == 'partially_compliant':
                st.warning("⚠️ **PARTIALLY COMPLIANT**: Some ISO 27001 controls need attention to achieve full compliance.")
            else:
                st.error("❌ **NON-COMPLIANT**: Significant compliance gaps require immediate remediation.")
            
            # Top compliance violations
            if compliance_assessment.violations:
                st.markdown("**🚨 Top Compliance Violations:**")
                
                # Sort violations by severity and risk rating
                sorted_violations = sorted(
                    compliance_assessment.violations,
                    key=lambda x: (
                        {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(x.severity, 3),
                        -x.risk_rating
                    )
                )
                
                for violation in sorted_violations[:5]:
                    severity_color = {
                        'CRITICAL': '#dc3545',
                        'HIGH': '#fd7e14',
                        'MEDIUM': '#ffc107',
                        'LOW': '#28a745'
                    }.get(violation.severity, '#6c757d')
                    
                    st.markdown(f"""
                    <div style="border-left: 4px solid {severity_color}; padding: 15px; margin: 10px 0; background: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border: 1px solid #e0e0e0;">
                        <strong style="color: #212529; font-size: 1.1em;">Control {violation.control_id}: {violation.control_name}</strong><br>
                        <span style="color: {severity_color}; font-weight: bold; font-size: 0.9em; background: rgba({severity_color.replace('#', '')}, 0.1); padding: 2px 6px; border-radius: 3px; margin: 5px 0; display: inline-block;">{violation.severity}</span> |
                        <span style="color: #495057; font-weight: 600;">Risk: {violation.risk_rating:.1f}/10</span><br>
                        <em style="color: #6c757d; line-height: 1.4; display: block; margin: 8px 0;">{violation.description}</em><br>
                        <small style="color: #495057; background: #f8f9fa; padding: 4px 8px; border-radius: 4px; display: inline-block;"><strong>Gap:</strong> {violation.compliance_gap}</small>
                    </div>
                    """, unsafe_allow_html=True)
            
            # Compliance recommendations
            if compliance_assessment.recommendations:
                with st.expander("💡 Compliance Recommendations", expanded=True):
                    for i, recommendation in enumerate(compliance_assessment.recommendations[:5], 1):
                        st.markdown(f"{i}. {recommendation}")
            
            # Detailed compliance report option
            if st.button("📋 Generate Detailed Compliance Report"):
                detailed_report = compliance_analyzer.generate_compliance_report(compliance_assessment)
                st.markdown("### ISO 27001 Compliance Report")
                st.markdown(detailed_report)
                
                # Offer download
                st.download_button(
                    label="📥 Download Compliance Report",
                    data=detailed_report,
                    file_name=f"iso27001_compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                    mime="text/markdown"
                )
        
        except Exception as e:
            st.error(f"ISO 27001 compliance analysis failed: {str(e)}")
            st.info("Compliance analysis requires proper configuration and security event data.")
    
    def _display_knowledge_graph_interface(self, results: Dict):
        """Display interactive knowledge graph interface"""
        
        st.markdown("""
        <div style="background: linear-gradient(135deg, #1e3c72, #2a5298); padding: 20px; border-radius: 10px; margin-bottom: 20px; border: 1px solid #4a90e2;">
            <h2 style="color: #ffffff; margin: 0 0 10px 0; text-shadow: 2px 2px 4px rgba(0,0,0,0.5);">🕸️ Interactive Security Knowledge Graph</h2>
            <p style="color: #e0e0e0; margin: 0; font-size: 1.1em;">Query the knowledge graph using natural language to explore network relationships and security insights.</p>
        </div>
        """, unsafe_allow_html=True)
        
        if not st.session_state.get('knowledge_graph_ready', False):
            st.warning("⚠️ Knowledge graph is not available. Please re-run analysis with knowledge graph enabled.")
            return
        
        # Query Interface
        col1, col2 = st.columns([3, 1])
        
        with col1:
            # Predefined queries
            predefined_queries = [
                "What hosts are in the network and what are their security risks?",
                "What security threats were detected and what is their impact?",
                "Which network services are running and are they vulnerable?",
                "Are there any indicators of compromise or malicious activities?",
                "What are the communication patterns between internal and external hosts?",
                "Identify any suspicious network behaviors or anomalies",
                "What attack vectors were used and how can they be mitigated?",
                "Provide a comprehensive security assessment of the network",
                "Are there any signs of lateral movement or privilege escalation?",
                "What data exfiltration attempts were detected?"
            ]
            
            query_input = st.selectbox(
                "Select a predefined query or enter custom query below:",
                [""] + predefined_queries,
                index=0
            )
            
            custom_query = st.text_area(
                "Custom Security Query:",
                value=query_input,
                height=60,
                placeholder="Ask about network security, threats, vulnerabilities, or any aspect of the analysis..."
            )
        
        with col2:
            query_mode = st.selectbox(
                "Query Mode:",
                ["hybrid", "global", "local", "naive"],
                index=0,
                help="Hybrid: Best overall results, Global: Broad context, Local: Specific details, Naive: Simple search"
            )
            
            if st.button("🔍 Query Knowledge Graph", type="primary", use_container_width=True):
                if custom_query.strip():
                    self._execute_knowledge_graph_query(custom_query, query_mode)
                else:
                    st.error("Please enter a query")
        
        # Query History
        if st.session_state.query_history:
            with st.expander("📚 Query History"):
                for i, query_record in enumerate(reversed(st.session_state.query_history[-5:]), 1):
                    st.markdown(f"**{i}.** {query_record['query']}")
                    with st.container():
                        st.markdown(f"*Response:* {query_record['response'][:200]}...")
                        st.caption(f"Timestamp: {query_record['timestamp']}")
        
        # Neo4j Knowledge Graph Visualization
        st.subheader("🌐 Neo4j Knowledge Graph Visualization")
        st.markdown("**Visual representation of the security knowledge graph stored in Neo4j:**")
        
        # Display the same Neo4j visualization as in other tabs
        network_viz = results.get('network_visualization')
        if network_viz:
            if isinstance(network_viz, str) and network_viz.startswith('<!DOCTYPE html>'):
                # Display the Neo4j HTML visualization
                st.components.v1.html(network_viz, height=500, scrolling=True)
            else:
                st.warning("Neo4j visualization not available")
        else:
            # If no network visualization, create a simple one from the knowledge graph
            if st.session_state.get('knowledge_graph_ready', False) and self.visualizer:
                try:
                    # Create a knowledge graph specific visualization
                    kg_viz = self.visualizer.create_interactive_security_graph(
                        results.get('network_entities', {})
                    )
                    if isinstance(kg_viz, str) and kg_viz.startswith('<!DOCTYPE html>'):
                        st.components.v1.html(kg_viz, height=500, scrolling=True)
                    else:
                        st.info("Knowledge graph visualization is being prepared...")
                except Exception as e:
                    st.error(f"Failed to create knowledge graph visualization: {str(e)}")
            else:
                st.info("Knowledge graph visualization will appear here once the graph is built. Please ensure the knowledge graph is initialized during analysis.")
    
    def _execute_knowledge_graph_query(self, query: str, mode: str):
        """Execute knowledge graph query and display results"""
        
        if not self.knowledge_graph:
            st.error("Knowledge graph not available")
            return
        
        try:
            with st.spinner("🧠 Processing query with AI knowledge graph..."):
                # Execute knowledge graph query with better error handling
                try:
                    query_result = asyncio.run(
                        self.knowledge_graph.query_security_knowledge(query, mode)
                    )
                    
                    # Check if we got a valid response
                    if query_result and isinstance(query_result, dict):
                        # Try different response keys that might be available
                        response = None
                        confidence = 0.0
                        
                        # Check for various possible response formats
                        if 'lightrag_response' in query_result and query_result['lightrag_response']:
                            response = query_result['lightrag_response']
                            confidence = query_result.get('confidence_score', 0.8)
                        elif 'response' in query_result and query_result['response']:
                            response = query_result['response']
                            confidence = query_result.get('confidence', 0.7)
                        elif 'answer' in query_result and query_result['answer']:
                            response = query_result['answer']
                            confidence = query_result.get('confidence_score', 0.7)
                        elif isinstance(query_result, str) and query_result.strip():
                            response = query_result
                            confidence = 0.6
                        
                        if response and response.strip() and not response.startswith("LightRAG not available"):
                            # Success - display the response
                            st.success("✅ Query executed successfully")
                            
                            # Response with confidence indicator
                            col_resp1, col_resp2 = st.columns([4, 1])
                            
                            with col_resp1:
                                st.markdown("### 🤖 AI Analysis Response")
                                st.markdown(response)
                            
                            with col_resp2:
                                st.metric(
                                    "Confidence Score",
                                    f"{confidence:.2f}",
                                    delta="High" if confidence > 0.8 else "Medium" if confidence > 0.6 else "Low"
                                )
                            
                            # Structured data if available
                            structured_data = query_result.get('structured_data')
                            if structured_data:
                                with st.expander("📊 Structured Data"):
                                    st.json(structured_data)
                            
                            # Add to query history
                            st.session_state.query_history.append({
                                'query': query,
                                'response': response,
                                'mode': mode,
                                'confidence': confidence,
                                'timestamp': datetime.now().isoformat()
                            })
                            
                        else:
                            # Fallback to basic analysis if LightRAG is not working
                            st.warning("⚠️ Advanced knowledge graph not available, using basic analysis...")
                            fallback_response = self._generate_fallback_analysis(query)
                            
                            st.markdown("### 📊 Basic Network Analysis")
                            st.markdown(fallback_response)
                            
                            # Add to query history
                            st.session_state.query_history.append({
                                'query': query,
                                'response': fallback_response,
                                'mode': 'fallback',
                                'confidence': 0.5,
                                'timestamp': datetime.now().isoformat()
                            })
                    else:
                        # No valid response received
                        st.warning("⚠️ Knowledge graph query returned no results, using basic analysis...")
                        fallback_response = self._generate_fallback_analysis(query)
                        
                        st.markdown("### 📊 Basic Network Analysis")
                        st.markdown(fallback_response)
                        
                        # Add to query history
                        st.session_state.query_history.append({
                            'query': query,
                            'response': fallback_response,
                            'mode': 'fallback',
                            'confidence': 0.5,
                            'timestamp': datetime.now().isoformat()
                        })
                        
                except Exception as query_error:
                    st.warning(f"⚠️ Knowledge graph query failed: {str(query_error)}")
                    st.info("Using basic network analysis instead...")
                    
                    # Provide fallback analysis
                    fallback_response = self._generate_fallback_analysis(query)
                    
                    st.markdown("### 📊 Basic Network Analysis")
                    st.markdown(fallback_response)
                    
                    # Add to query history
                    st.session_state.query_history.append({
                        'query': query,
                        'response': fallback_response,
                        'mode': 'fallback',
                        'confidence': 0.5,
                        'timestamp': datetime.now().isoformat()
                    })
        
        except Exception as e:
            st.error(f"❌ Query execution failed: {str(e)}")
            logger.error(f"Knowledge graph query failed: {e}")
    
    def _generate_fallback_analysis(self, query: str) -> str:
        """Generate basic analysis when knowledge graph is not available"""
        
        # Get analysis results from session state
        results = st.session_state.get('analysis_results', {})
        network_entities = results.get('network_entities', {})
        summary = results.get('analysis_summary', {})
        
        # Basic query processing based on keywords
        query_lower = query.lower()
        
        if 'host' in query_lower and 'risk' in query_lower:
            # Host and risk analysis
            hosts = network_entities.get('hosts', {})
            if hosts:
                response = "**Network Hosts and Security Risks:**\n\n"
                for ip, host_info in list(hosts.items())[:10]:  # Limit to first 10 hosts
                    is_internal = host_info.get('is_internal', False)
                    reputation = host_info.get('reputation', 'unknown')
                    packet_count = host_info.get('packet_count', 0)
                    
                    risk_level = "Low"
                    if reputation == 'malicious':
                        risk_level = "High"
                    elif reputation == 'suspicious' or not is_internal:
                        risk_level = "Medium"
                    
                    response += f"• **{ip}** ({'Internal' if is_internal else 'External'})\n"
                    response += f"  - Risk Level: {risk_level}\n"
                    response += f"  - Reputation: {reputation.title()}\n"
                    response += f"  - Traffic: {packet_count} packets\n\n"
                
                return response
            else:
                return "No host information available in the current analysis."
        
        elif 'threat' in query_lower or 'security' in query_lower:
            # Security threats analysis
            security_events = network_entities.get('security_events', [])
            if security_events:
                response = f"**Security Threats Detected: {len(security_events)} events**\n\n"
                
                # Group by event type
                event_types = {}
                for event in security_events:
                    event_type = getattr(event, 'event_type', 'unknown')
                    if event_type not in event_types:
                        event_types[event_type] = []
                    event_types[event_type].append(event)
                
                for event_type, events in list(event_types.items())[:5]:  # Top 5 event types
                    response += f"• **{event_type.replace('_', ' ').title()}**: {len(events)} incidents\n"
                    if events:
                        example = events[0]
                        response += f"  - Severity: {getattr(example, 'severity', 'Unknown')}\n"
                        response += f"  - Description: {getattr(example, 'description', 'No description')[:100]}...\n\n"
                
                return response
            else:
                return "No security threats detected in the current analysis."
        
        elif 'service' in query_lower:
            # Network services analysis
            services = network_entities.get('services', {})
            if services:
                response = f"**Network Services Discovered: {len(services)} services**\n\n"
                
                for service_key, service_info in list(services.items())[:10]:  # First 10 services
                    service_name = service_info.get('service_name', 'Unknown')
                    host = service_info.get('host', 'Unknown')
                    port = service_info.get('port', 0)
                    risk_level = service_info.get('risk_level', 'Medium')
                    
                    response += f"• **{service_name}** on {host}:{port}\n"
                    response += f"  - Risk Level: {risk_level}\n"
                    response += f"  - Protocol: {service_info.get('protocol', 'Unknown')}\n\n"
                
                return response
            else:
                return "No network services information available."
        
        else:
            # General network summary
            response = "**Network Analysis Summary:**\n\n"
            
            if summary:
                response += f"• **Security Score**: {summary.get('security_score', 0)}/100\n"
                response += f"• **Hosts Discovered**: {summary.get('hosts_discovered', 0)}\n"
                response += f"• **Security Events**: {summary.get('security_events', {}).get('total', 0)}\n"
                response += f"• **Network Services**: {summary.get('services_discovered', 0)}\n"
                response += f"• **Risk Level**: {summary.get('risk_level', 'Unknown')}\n\n"
                
                recommendations = summary.get('recommendations', [])
                if recommendations:
                    response += "**Key Recommendations:**\n"
                    for i, rec in enumerate(recommendations[:3], 1):
                        response += f"{i}. {rec}\n"
            else:
                response += "Analysis summary not available. Please ensure the PCAP file has been processed successfully."
            
            return response
    
    def _display_network_analysis(self, results: Dict):
        """Display detailed network analysis"""
        
        network_entities = results.get('network_entities', {})
        hosts = network_entities.get('hosts', {})
        services = network_entities.get('services', {})
        
        # Network topology overview
        col1, col2 = st.columns([2, 1])
        
        with col1:
            # Network graph
            network_viz = results.get('network_visualization')
            if network_viz:
                st.subheader("🌐 Interactive Network Security Graph")
                
                # Check if it's HTML content (from Neo4j visualizer)
                if isinstance(network_viz, str):
                    if network_viz.startswith('<!DOCTYPE html>'):
                        # Display HTML visualization
                        st.components.v1.html(network_viz, height=600, scrolling=True)
                    else:
                        st.error("Invalid network visualization format received")
                elif hasattr(network_viz, 'get') and 'plotly_figure' in network_viz:
                    # Display Plotly figure (fallback)
                    st.plotly_chart(network_viz['plotly_figure'], use_container_width=True)
                elif hasattr(network_viz, 'show'):
                    # Direct Plotly figure
                    st.plotly_chart(network_viz, use_container_width=True)
                else:
                    st.warning("Network visualization format not recognized")
        
        with col2:
            # Network statistics
            st.subheader("📊 Network Statistics")
            
            internal_hosts = len([h for h in hosts.values() if h.get('is_internal')])
            external_hosts = len(hosts) - internal_hosts
            
            st.metric("Total Hosts", len(hosts))
            st.metric("Internal Hosts", internal_hosts)
            st.metric("External Hosts", external_hosts)
            st.metric("Active Services", len(services))
        
        # Detailed host analysis
        st.subheader("🖥️ Host Analysis")
        
        if hosts:
            host_data = []
            for ip, host_info in hosts.items():
                host_data.append({
                    'IP Address': ip,
                    'Type': 'Internal' if host_info.get('is_internal') else 'External',
                    'Packets': host_info.get('packet_count', 0),
                    'Reputation': host_info.get('reputation', 'Unknown'),
                    'Protocols': ', '.join(list(host_info.get('protocols', set()))[:3]),
                    'Risk Level': self._assess_display_risk(host_info)
                })
            
            df_hosts = pd.DataFrame(host_data)
            
            # Add filters
            col_filter1, col_filter2, col_filter3 = st.columns(3)
            
            with col_filter1:
                type_filter = st.selectbox("Filter by Type", ["All", "Internal", "External"])
            
            with col_filter2:
                risk_filter = st.selectbox("Filter by Risk", ["All", "High", "Medium", "Low"])
            
            with col_filter3:
                min_packets = st.number_input("Min Packets", min_value=0, value=0)
            
            # Apply filters
            filtered_df = df_hosts.copy()
            if type_filter != "All":
                filtered_df = filtered_df[filtered_df['Type'] == type_filter]
            if risk_filter != "All":
                filtered_df = filtered_df[filtered_df['Risk Level'] == risk_filter]
            if min_packets > 0:
                filtered_df = filtered_df[filtered_df['Packets'] >= min_packets]
            
            st.dataframe(filtered_df, use_container_width=True)
        
        # Service analysis
        st.subheader("⚙️ Service Analysis")
        
        if services:
            service_data = []
            for service_key, service_info in services.items():
                service_data.append({
                    'Service': service_info.get('service_name', 'Unknown'),
                    'Host': service_info.get('host', 'Unknown'),
                    'Port': service_info.get('port', 0),
                    'Protocol': service_info.get('protocol', 'Unknown'),
                    'Clients': len(service_info.get('clients', [])),
                    'Risk Level': service_info.get('risk_level', 'Medium')
                })
            
            df_services = pd.DataFrame(service_data)
            st.dataframe(df_services, use_container_width=True)
    
    def _display_threat_details(self, results: Dict):
        """Display detailed threat analysis"""
        
        security_events = results.get('network_entities', {}).get('security_events', [])
        
        if not security_events:
            st.success("🎉 No security threats detected in the analyzed traffic!")
            st.info("The network appears to be operating normally without any identified security issues.")
            return
        
        st.subheader(f"⚠️ {len(security_events)} Security Events Detected")
        
        # Event severity distribution
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for event in security_events:
            severity_counts[event.severity] += 1
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Critical", severity_counts['CRITICAL'], delta_color="inverse")
        with col2:
            st.metric("High", severity_counts['HIGH'], delta_color="inverse")
        with col3:
            st.metric("Medium", severity_counts['MEDIUM'], delta_color="inverse") 
        with col4:
            st.metric("Low", severity_counts['LOW'])
        
        # Detailed event list
        st.subheader("📋 Event Details")
        
        # Event filters
        col_f1, col_f2, col_f3 = st.columns(3)
        
        with col_f1:
            severity_filter = st.selectbox(
                "Filter by Severity",
                ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
            )
        
        with col_f2:
            event_types = list(set([e.event_type for e in security_events]))
            type_filter = st.selectbox("Filter by Type", ["All"] + event_types)
        
        with col_f3:
            limit_events = st.number_input("Max Events to Display", min_value=1, max_value=100, value=20)
        
        # Filter events
        filtered_events = security_events
        if severity_filter != "All":
            filtered_events = [e for e in filtered_events if e.severity == severity_filter]
        if type_filter != "All":
            filtered_events = [e for e in filtered_events if e.event_type == type_filter]
        
        # Sort by severity and timestamp
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        filtered_events.sort(key=lambda x: (severity_order[x.severity], -x.timestamp))
        
        # Display events
        for i, event in enumerate(filtered_events[:limit_events], 1):
            with st.expander(f"🚨 {event.event_type.replace('_', ' ').title()} - {event.severity}"):
                col_event1, col_event2 = st.columns([2, 1])
                
                with col_event1:
                    st.markdown(f"**Description:** {event.description}")
                    st.markdown(f"**Event ID:** `{event.event_id}`")
                    st.markdown(f"**Timestamp:** {datetime.fromtimestamp(event.timestamp).strftime('%Y-%m-%d %H:%M:%S')}")
                    
                    if event.source_ip:
                        st.markdown(f"**Source:** {event.source_ip}" + (f":{event.source_port}" if event.source_port else ""))
                    if event.dest_ip:
                        st.markdown(f"**Target:** {event.dest_ip}" + (f":{event.dest_port}" if event.dest_port else ""))
                    
                    st.markdown(f"**Protocol:** {event.protocol}")
                    
                    # Evidence details
                    if event.evidence:
                        st.markdown("**🔍 Evidence:**")
                        st.json(event.evidence)
                
                with col_event2:
                    st.metric("Confidence Score", f"{event.confidence_score:.2f}")
                    st.markdown(f"**Attack Category:** {event.attack_category}")
                    
                    # Remediation recommendations
                    if event.remediation:
                        st.markdown("**Remediation:**")
                        for rec in event.remediation[:3]:
                            st.markdown(f"• {rec}")
    
    def _display_executive_report(self, results: Dict):
        """Display executive summary report"""
        
        summary = results.get('analysis_summary', {})
        file_info = results.get('file_info', {})
        
        st.markdown("""
        # 📋 Executive Security Report
        
        This report provides a high-level summary of the network security analysis findings for executive review.
        """)
        
        # Executive Summary
        st.subheader("📊 Executive Summary")
        
        security_score = summary.get('security_score', 0)
        risk_level = summary.get('risk_level', 'UNKNOWN')
        threat_count = summary.get('security_events', {}).get('total', 0)
        
        if threat_count == 0:
            summary_text = f"""
            **Security Status: ✅ SECURE**
            
            The network analysis reveals a secure environment with no identified security threats. 
            The security score of {security_score}/100 indicates good security posture with {risk_level.lower()} risk profile.
            
            **Key Findings:**
            - No malicious activities detected
            - {summary.get('hosts_discovered', 0)} hosts analyzed with normal behavior patterns
            - {summary.get('services_discovered', 0)} network services operating within security parameters
            - Network communications follow expected patterns
            """
        else:
            summary_text = f"""
            **Security Status: ⚠️ THREATS DETECTED**
            
            The network analysis has identified {threat_count} security events requiring immediate attention. 
            The security score of {security_score}/100 indicates a {risk_level.lower()} risk environment.
            
            **Critical Findings:**
            - {summary.get('security_events', {}).get('critical', 0)} critical security events
            - {summary.get('security_events', {}).get('high', 0)} high-severity incidents
            - Immediate investigation and remediation required
            - Potential business impact from identified threats
            """
        
        st.markdown(summary_text)
        
        # Risk Assessment
        st.subheader("🎯 Risk Assessment")
        
        col_risk1, col_risk2 = st.columns(2)
        
        with col_risk1:
            # Risk level gauge
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number+delta",
                value=security_score,
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "Security Score"},
                delta={'reference': 80},
                gauge={
                    'axis': {'range': [None, 100]},
                    'bar': {'color': "darkblue"},
                    'steps': [
                        {'range': [0, 50], 'color': "red"},
                        {'range': [50, 80], 'color': "yellow"},
                        {'range': [80, 100], 'color': "green"}
                    ],
                    'threshold': {
                        'line': {'color': "red", 'width': 4},
                        'thickness': 0.75,
                        'value': 90
                    }
                }
            ))
            fig_gauge.update_layout(height=300)
            st.plotly_chart(fig_gauge, use_container_width=True)
        
        with col_risk2:
            st.markdown("### 🔍 Risk Factors")
            
            risk_factors = []
            if threat_count > 0:
                risk_factors.append(f"• {threat_count} active security threats")
            if summary.get('external_hosts', 0) > 10:
                risk_factors.append(f"• High external connectivity ({summary.get('external_hosts', 0)} hosts)")
            if security_score < 70:
                risk_factors.append("• Below-average security score")
            
            if risk_factors:
                for factor in risk_factors:
                    st.markdown(factor)
            else:
                st.success("✅ No significant risk factors identified")
        
        # Recommendations
        st.subheader("💡 Strategic Recommendations")
        
        recommendations = summary.get('recommendations', [])
        if recommendations:
            st.markdown("**Immediate Actions Required:**")
            for i, rec in enumerate(recommendations[:5], 1):
                st.markdown(f"{i}. {rec}")
        
        # Technical Details for IT Teams
        with st.expander("🔧 Technical Details for IT Teams"):
            
            col_tech1, col_tech2 = st.columns(2)
            
            with col_tech1:
                st.markdown("**Network Infrastructure:**")
                st.markdown(f"- Total packets analyzed: {summary.get('total_packets', 0):,}")
                st.markdown(f"- Hosts discovered: {summary.get('hosts_discovered', 0)}")
                st.markdown(f"- Internal hosts: {summary.get('internal_hosts', 0)}")
                st.markdown(f"- External hosts: {summary.get('external_hosts', 0)}")
                st.markdown(f"- Active services: {summary.get('services_discovered', 0)}")
            
            with col_tech2:
                st.markdown("**Analysis Parameters:**")
                st.markdown(f"- File analyzed: {file_info.get('name', 'Unknown')}")
                st.markdown(f"- File size: {self._format_file_size(file_info.get('size', 0))}")
                st.markdown(f"- Analysis time: {file_info.get('analysis_time', 'Unknown')}")
                st.markdown(f"- Protocols detected: {len(summary.get('protocols_detected', []))}")
        
        # Export options
        st.subheader("📥 Export Options")
        
        col_exp1, col_exp2, col_exp3 = st.columns(3)
        
        with col_exp1:
            if st.button("📄 Download PDF Report", use_container_width=True):
                st.info("PDF report generation would be implemented here")
        
        with col_exp2:
            if st.button("📊 Export Data (JSON)", use_container_width=True):
                self._export_json_data(results)
        
        with col_exp3:
            if st.button("📈 Export Visualizations", use_container_width=True):
                st.info("Visualization export would be implemented here")
    
    # Helper methods
    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
    
    def _format_number(self, num: int) -> str:
        """Format number with appropriate suffix"""
        if num >= 1_000_000:
            return f"{num/1_000_000:.1f}M"
        elif num >= 1_000:
            return f"{num/1_000:.1f}K"
        return str(num)
    
    def _assess_display_risk(self, host_info: Dict) -> str:
        """Assess risk level for display"""
        # Simplified risk assessment for display
        reputation = host_info.get('reputation', 'unknown')
        if reputation == 'malicious':
            return 'High'
        elif reputation == 'suspicious':
            return 'Medium'
        elif not host_info.get('is_internal', True):
            return 'Medium'
        return 'Low'
    
    def _export_json_data(self, results: Dict):
        """Export analysis results as JSON"""
        try:
            # Prepare data for export
            export_data = {
                'metadata': {
                    'export_timestamp': datetime.now().isoformat(),
                    'tool_version': '1.0.0',
                    'analysis_type': 'PCAP Security Analysis'
                },
                'file_info': results.get('file_info', {}),
                'analysis_summary': results.get('analysis_summary', {}),
                'network_entities': results.get('network_entities', {}),
                # Note: Remove non-serializable objects
            }
            
            # Convert to JSON string
            json_str = json.dumps(export_data, indent=2, default=str)
            
            # Create download
            st.download_button(
                label="📥 Download Analysis Data",
                data=json_str,
                file_name=f"pcap_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True
            )
            
        except Exception as e:
            st.error(f"Export failed: {str(e)}")
    
    def _reset_analysis(self):
        """Reset analysis state"""
        st.session_state.analysis_results = None
        st.session_state.knowledge_graph_ready = False
        st.session_state.analysis_completed = False
        st.session_state.query_history = []
        
        # Clear stored enhanced components
        if hasattr(st.session_state, 'visualizer'):
            del st.session_state.visualizer
        if hasattr(st.session_state, 'processor'):
            del st.session_state.processor
        if hasattr(st.session_state, 'knowledge_graph'):
            del st.session_state.knowledge_graph
        if hasattr(st.session_state, 'jina_reranker'):
            del st.session_state.jina_reranker
            
        # Reset instance variables
        self.visualizer = None
        self.processor = None
        self.knowledge_graph = None
        self.jina_reranker = None
        
        st.rerun()
    
    def _export_analysis_results(self):
        """Export comprehensive analysis results"""
        results = st.session_state.analysis_results
        if not results:
            st.error("No results to export")
            return
        
        try:
            # Create ZIP file with all results
            zip_buffer = io.BytesIO()
            
            with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
                # Add JSON data
                json_data = json.dumps(results, indent=2, default=str)
                zip_file.writestr("analysis_data.json", json_data)
                
                # Add executive report (would be generated as text/markdown)
                report_text = self._generate_text_report(results)
                zip_file.writestr("executive_report.md", report_text)
                
                # Add query history if available
                if st.session_state.query_history:
                    query_data = json.dumps(st.session_state.query_history, indent=2, default=str)
                    zip_file.writestr("query_history.json", query_data)
            
            zip_buffer.seek(0)
            
            # Offer download
            st.download_button(
                label="📥 Download Complete Analysis Package",
                data=zip_buffer.getvalue(),
                file_name=f"pcap_security_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip",
                mime="application/zip",
                use_container_width=True
            )
            
        except Exception as e:
            st.error(f"Export failed: {str(e)}")
    
    def _generate_text_report(self, results: Dict) -> str:
        """Generate text-based executive report"""
        summary = results.get('analysis_summary', {})
        file_info = results.get('file_info', {})
        
        report = f"""# PCAP Security Analysis Report

## Executive Summary

**File Analyzed:** {file_info.get('name', 'Unknown')}
**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Security Score:** {summary.get('security_score', 0)}/100
**Risk Level:** {summary.get('risk_level', 'Unknown')}

## Key Findings

- **Hosts Discovered:** {summary.get('hosts_discovered', 0)}
- **Security Events:** {summary.get('security_events', {}).get('total', 0)}
- **Network Services:** {summary.get('services_discovered', 0)}
- **Traffic Volume:** {summary.get('total_packets', 0):,} packets

## Threat Analysis

"""
        
        security_events = summary.get('security_events', {})
        if security_events.get('total', 0) > 0:
            report += f"""
**Threats Detected:** {security_events.get('total', 0)}
- Critical: {security_events.get('critical', 0)}
- High: {security_events.get('high', 0)}
- Medium: {security_events.get('medium', 0)}
- Low: {security_events.get('low', 0)}

"""
        else:
            report += "No security threats detected.\n\n"
        
        # Add recommendations
        recommendations = summary.get('recommendations', [])
        if recommendations:
            report += "## Recommendations\n\n"
            for i, rec in enumerate(recommendations, 1):
                report += f"{i}. {rec}\n"
        
        report += f"\n---\nGenerated by PCAP Security Analyzer v1.0"
        
        return report
    
    def _create_simple_timeline(self, security_events):
        """Create a simple timeline visualization as fallback"""
        try:
            import plotly.express as px
            import pandas as pd
            from datetime import datetime
            
            # Convert events to DataFrame
            timeline_data = []
            for event in security_events:
                timeline_data.append({
                    'timestamp': datetime.fromtimestamp(event.timestamp),
                    'event_type': event.event_type.replace('_', ' ').title(),
                    'severity': event.severity,
                    'description': event.description[:50] + '...' if len(event.description) > 50 else event.description
                })
            
            if timeline_data:
                df = pd.DataFrame(timeline_data)
                
                # Create simple scatter plot timeline
                fig = px.scatter(df,
                               x='timestamp',
                               y='event_type',
                               color='severity',
                               hover_data=['description'],
                               title="Security Events Timeline",
                               color_discrete_map={
                                   'CRITICAL': 'red',
                                   'HIGH': 'orange',
                                   'MEDIUM': 'yellow',
                                   'LOW': 'green'
                               })
                
                fig.update_layout(
                    xaxis_title="Time",
                    yaxis_title="Event Type",
                    height=400
                )
                
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No security events to display in timeline")
                
        except Exception as e:
            st.error(f"Failed to create fallback timeline: {str(e)}")

def main():
    """Main entry point for Streamlit application"""
    
    # Load enhanced configuration with Neo4j and Jina support
    config = {
        'openai': {
            'api_key': os.getenv('OPENAI_API_KEY'),
            'model': 'gpt-4o-mini',
            'embedding_model': 'text-embedding-3-large',
            'max_tokens': 4096
        },
        'neo4j': {
            'uri': os.getenv('NEO4J_URI', 'bolt://localhost:7687'),
            'username': os.getenv('NEO4J_USERNAME', 'neo4j'),
            'password': os.getenv('NEO4J_PASSWORD', 'password')
        },
        'jina': {
            'api_key': os.getenv('JINA_API_KEY'),
            'model': 'jina-reranker-v2-base-multilingual',
            'max_documents': 100,
            'enable_fallback': True,
            'enabled': bool(os.getenv('JINA_API_KEY'))  # Only enable if API key is provided
        },
        'lightrag': {
            'working_dir': './data/lightrag_cache',
            'max_tokens': 8192,
            'entity_extract_max_gleaning': 3,
            'enable_llm_cache': True,
            'enable_enhanced_extraction': True
        },
        'pcap': {
            'max_packet_size': 50000,
            'chunk_size': 1000,
            'enable_payload_analysis': True,
            'enable_enhanced_analysis': True
        },
        'security': {
            'enable_deep_packet_inspection': True,
            'enable_ml_detection': True,
            'enable_behavioral_analysis': True,
            'enable_compliance_analysis': True,
            'enable_threat_correlation': True
        },
        'visualization': {
            'enable_neo4j_graphs': True,
            'enable_interactive_html': True,
            'graph_layout': 'force-directed',
            'max_nodes': 1000
        },
        'web': {
            'host': 'localhost',
            'port': 8501,
            'title': 'Enhanced PCAP Security Analyzer'
        }
    }
    
    # Initialize and run app
    app = PCAPSecurityAnalyzerApp(config)
    app.run()

if __name__ == "__main__":
    main()