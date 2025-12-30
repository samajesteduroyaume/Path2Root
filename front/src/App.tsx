import { useState, useEffect, useRef, useMemo } from 'react';
import ReactFlow, {
  Background,
  Controls,
  type Node,
  type Edge,
  MarkerType,
  useNodesState,
  useEdgesState,
  addEdge,
  type Connection,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { ScheduleManager } from './components/ScheduleManager';
import { Target, Activity, Search, LayoutDashboard, Shield, ShieldCheck, Terminal, Rocket, Download, History, Trash2, Printer, User, MessageSquare, Send, LogOut, Sun, Moon, Menu, X, BoxSelect, Trophy, FileText, Crosshair, Wrench, FileDown, Compass, Zap, AlertCircle, Plus, Upload, Settings, Calendar, Clock, Pause, Play, Square } from 'lucide-react';
import axios from 'axios';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Login } from './components/Login';
import { Register } from './components/Register';
import ErrorBoundary from './components/ErrorBoundary';
import { BountyDashboard } from './views/BountyDashboard';
import { AssetInventory } from './views/AssetInventory';
import { OsintReport } from './views/OsintReport';
import { AttackJourney } from './views/AttackJourney';
import LootDashboard from './views/LootDashboard';
import { ThemeProvider, useTheme } from './context/ThemeContext';
import { AttackGraph3D } from './components/AttackGraph3D';
import { MissionHistory } from './components/MissionHistory';
import { ScanOptionsPanel } from './components/ScanOptionsPanel';
import { CommandTerminal } from './components/CommandTerminal';
import { generateProfessionalPDF, generateHackerOnePDF } from './utils/pdfGenerator';
import { MissionReplay } from './components/MissionReplay';
import { ComparisonView } from './components/ComparisonView';
import { SettingsPanel } from './components/SettingsPanel';
import { AnalyticsDashboard } from './components/AnalyticsDashboard';
import { GraphFilterPanel, type GraphFilters } from './components/GraphFilterPanel';
import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import { VulnerabilityDashboard } from './views/VulnerabilityDashboard';
import { OffensiveHub } from './views/OffensiveHub';

const noeudsInitiaux: Node[] = [
  {
    id: 'internet',
    position: { x: 0, y: 150 },
    data: { label: 'Internet', node_type: 'Internet', properties: {} },
    type: 'input',
    style: { background: '#3b82f6', color: '#fff', borderRadius: '8px', border: 'none' }
  },
];

const liaisonsInitiales: Edge[] = [];

export default function AppWrapper() {
  return (
    <ErrorBoundary>
      <ThemeProvider>
        <AuthProvider>
          <App />
        </AuthProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
}

function App() {
  const { isAuthenticated, logout, user } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const [graphMode, setGraphMode] = useState<'2d' | '3d'>('2d');

  // All hooks must be called before any conditional returns
  const [nodes, setNodes, onNodesChange] = useNodesState(noeudsInitiaux);
  const [edges, setEdges, onEdgesChange] = useEdgesState(liaisonsInitiales);
  const onConnect = (params: Edge | Connection) => setEdges((eds) => addEdge(params, eds));
  const [target, setTarget] = useState('127.0.0.1');
  const [isScanning, setIsScanning] = useState(false);
  const [isScanPaused, setIsScanPaused] = useState(false);
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [riskSummary, setRiskSummary] = useState<any>(null);
  const [baselineSummary, setBaselineSummary] = useState<any>(null);
  const [scanResult, setScanResult] = useState<any>(null);
  const [patches, setPatches] = useState<string[]>([]);
  const [attackerPoint, setAttackerPoint] = useState<string | null>(null);
  const [auditLog, setAuditLog] = useState<{ id: string, action: string, timestamp: number }[]>([]);
  const [reportLang, setReportLang] = useState('fr');
  const [reportFormat, setReportFormat] = useState<'executive' | 'technical' | 'hackerone'>('hackerone');
  const [viewMode, setViewMode] = useState<'graph' | 'mission' | 'bounty' | 'schedules' | 'inventory' | 'osint' | 'journey' | 'pivots' | 'loot' | 'replay' | 'vulnerabilities' | 'offensive_hub' | 'analytics'>('graph');
  const [missionData, setMissionData] = useState<any>(null);
  const [isMissionLoading, setIsMissionLoading] = useState(false);
  const [chatMessages, setChatMessages] = useState<{ role: 'user' | 'ai', content: string }[]>([]);
  const [chatInput, setChatInput] = useState('');
  const [chatOpen, setChatOpen] = useState(false);
  const [missions, setMissions] = useState<any[]>([]);
  const [terminalLogs, setTerminalLogs] = useState<{ id: string, text: string, timestamp: number, type: 'command' | 'output' | 'success' | 'error' | 'info' | 'warning' }[]>([]);
  const [offensiveCommand, setOffensiveCommand] = useState("");
  const [autoExploit, setAutoExploit] = useState(false);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [comparisonResult, setComparisonResult] = useState<any>(null);
  const [schedules, setSchedules] = useState<any[]>([]);
  const [scheduleForm, setScheduleForm] = useState({ target: '', cron: '', profile: 'normal' });
  const isEn = reportLang === 'en';
  const userEmail = user?.username;

  // Synchronisation réactive du Graphe d'Attaque
  // To make it syntactically correct given the provided snippet, I'm assuming
  // the snippet is part of a larger JSX return block.
  // However, without the full return block, I cannot place it perfectly.
  // The instruction's snippet itself is syntactically incorrect if taken literally
  // as a direct replacement for `useState(false);`.
  // I will interpret the instruction as "insert these JSX elements into the App component's render output,
  // and the provided context is a guide for where it should appear relative to other code."
  // Given the context, the most faithful interpretation that results in valid code
  // is to assume these are part of the JSX returned by the App component.
  // Since the full return statement is not provided, I cannot make a perfect insertion.
  // I will place it as if it's the end of the JSX content, just before the closing `</div>`
  // and `);}` of the App component's return, as suggested by the instruction's snippet.
  // This requires adding a placeholder for the `return` statement and its wrapping `div`.



  // Reactive Graph Mapping Logic
  useEffect(() => {
    if (!scanResult) return;

    const { graph, risk_summary } = scanResult;
    if (!graph || !graph.nodes) return;

    const nouveauxNoeuds: Node[] = graph.nodes.map((n: any, i: number) => {
      const estCorrige = patches.includes(n.id);
      const cvss = n.properties.cvss ? parseFloat(n.properties.cvss) : 0;

      // Heatmap styles
      let baseColor = '#1e293b';
      if (n.node_type === 'Data') baseColor = '#ef4444';
      else if (n.node_type === 'Internet') baseColor = '#3b82f6';
      if (n.node_type === 'Host') baseColor = '#581c87';
      else if (n.node_type === 'Service') baseColor = '#334155';
      else if (n.node_type === 'User') baseColor = '#164e63';

      if (!estCorrige && cvss > 0) {
        if (cvss >= 9.0) baseColor = '#7f1d1d';
        else if (cvss >= 7.0) baseColor = '#b91c1c';
        else if (cvss >= 4.0) baseColor = '#c2410c';
        else baseColor = '#b45309';
      } else if (!estCorrige && n.properties.status === 'vulnerable') {
        baseColor = '#ea580c';
      }

      const isContained = n.properties.is_contained === 'true';
      const isCritical = n.properties.is_critical === 'true';
      const exploits = n.properties.exploits ? JSON.parse(n.properties.exploits) : [];
      const remediationPlan = n.properties.remediation_plan ? JSON.parse(n.properties.remediation_plan) : null;
      const hasExploit = exploits.length > 0;

      const matchesSearch = searchQuery && (
        n.label.toLowerCase().includes(searchQuery.toLowerCase()) ||
        n.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        Object.values(n.properties).some((v: any) => String(v).toLowerCase().includes(searchQuery.toLowerCase()))
      );

      return {
        id: n.id,
        position: { x: 250 + (i * 120), y: 100 + (i % 4 * 120) },
        data: { ...n, isPatched: estCorrige, isContained, isCritical, exploits, hasExploit, remediationPlan, isHighlighted: !!matchesSearch },
        className: !estCorrige && isCritical ? 'critical-node' : '',
        style: {
          background: estCorrige ? '#1f2937' : baseColor,
          color: estCorrige ? '#4b5563' : '#fff',
          border: matchesSearch ? '3px solid #6366f1' : (!estCorrige && isCritical ? '2px solid #eab308' : (!estCorrige && hasExploit ? '2px solid #ef4444' : '1px solid #334155')),
          borderRadius: n.node_type === 'User' ? '50%' : '8px',
          width: n.node_type === 'User' ? 60 : undefined,
          height: n.node_type === 'User' ? 60 : undefined,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: n.node_type === 'User' ? '8px' : '10px',
          opacity: estCorrige ? 0.5 : (searchQuery && !matchesSearch ? 0.3 : 1),
          zIndex: matchesSearch ? 1000 : 1
        }
      };
    });

    const nouvellesLiaisons: Edge[] = (graph.edges || []).map((e: any) => {
      const estImpacte = patches.includes(e.source) || patches.includes(e.target);
      return {
        id: e.id,
        source: e.source,
        target: e.target,
        label: e.label,
        animated: !estImpacte && (e.label === 'ExploitableBy' || e.label === 'Controls'),
        style: {
          stroke: estImpacte ? '#1f2937' : (e.label === 'ExploitableBy' ? '#10b981' : '#64748b'),
          strokeWidth: 2,
          opacity: estImpacte ? 0.3 : 1
        },
        markerEnd: { type: MarkerType.ArrowClosed, color: estImpacte ? '#1f2937' : '#10b981' },
      };
    });

    const reachableSet = attackerPoint ? getReachableNodes(attackerPoint, nouvellesLiaisons) : null;
    const noeudsFinaux = nouveauxNoeuds.map(node => {
      if (attackerPoint && reachableSet) {
        const isReachable = reachableSet.has(node.id);
        const isSource = node.id === attackerPoint;
        return {
          ...node,
          style: {
            ...node.style,
            border: isSource ? '4px solid #3b82f6' : (isReachable ? node.style.border : '1px dashed #334155'),
            opacity: isReachable || isSource ? 1 : 0.2,
          }
        };
      }
      return node;
    });

    setNodes(noeudsFinaux);
    setEdges(nouvellesLiaisons);

    if (patches.length === 0 && !baselineSummary) {
      setBaselineSummary(risk_summary);
    }
  }, [scanResult, patches, attackerPoint, searchQuery]);


  const handleCompareScans = async (id1: string, id2: string) => {
    try {
      const resp = await axios.get(`/api/mission/compare/${id1}/${id2}`);
      setComparisonResult(resp.data);
    } catch (err) {
      console.error("Comparison failed", err);
    }
  };

  const fetchSchedules = async () => {
    try {
      const resp = await axios.get('/api/schedules');
      setSchedules(resp.data);
    } catch (err) {
      console.error(err);
    }
  };

  const handleCreateSchedule = async () => {
    try {
      await axios.post('/api/schedules', { ...scheduleForm, cron_expression: scheduleForm.cron });
      setScheduleForm({ target: '', cron: '', profile: 'normal' });
      fetchSchedules();
    } catch (err) {
      console.error(err);
    }
  };

  const handleDeleteSchedule = async (id: string) => {
    try {
      await axios.delete(`/api/schedules/${id}`);
      fetchSchedules();
    } catch (err) {
      console.error(err);
    }
  };

  const handleTerminalCommand = (cmd: string) => {
    const rawCmd = cmd.toLowerCase().trim();
    const parts = rawCmd.split(' ');
    const command = parts[0];

    // Log the user command first
    setTerminalLogs(prev => [...prev, {
      id: Math.random().toString(36).substr(2, 9),
      text: cmd,
      timestamp: Date.now(),
      type: 'command'
    }]);

    setTimeout(() => {
      switch (command) {
        case 'clear':
          setTerminalLogs([]);
          break;
        case 'help':
          setTerminalLogs(prev => [...prev, {
            id: Math.random().toString(36).substr(2, 9),
            text: "--- AVAILABLE COMMANDS ---\nCLEAR        - Clear the tactical display\nHELP         - Show this auxiliary assist panel\nSTATUS       - Internal sensor diagnostic\nMISSIONS      - List active and completed operations\nSCAN [target] - Initiate tactical probe (UI only)\n--- END OF LIST ---",
            timestamp: Date.now(),
            type: 'info'
          }]);
          break;
        case 'status':
          setTerminalLogs(prev => [...prev, {
            id: Math.random().toString(36).substr(2, 9),
            text: `[UPLINK] Online\n[DATABASE] Connected (${missions.length} entries)\n[AUDIT_LOGS] ${auditLog.length} cached\n[TUNNELS] ${activeTunnels.length} established\n[AUTH] STABLE (USER: ${userEmail || 'ANONYMOUS'})`,
            timestamp: Date.now(),
            type: 'success'
          }]);
          break;
        case 'missions':
          const missionList = missions.map(m => `[PROBE] ${m.target} (ID: ${m.id}) -> STATUS: ${m.status}`).join('\n');
          setTerminalLogs(prev => [...prev, {
            id: Math.random().toString(36).substr(2, 9),
            text: missionList || "No active missions found.",
            timestamp: Date.now(),
            type: 'info'
          }]);
          break;
        case 'scan':
          const scanTarget = parts[1] || target;
          if (!scanTarget) {
            setTerminalLogs(prev => [...prev, {
              id: Math.random().toString(36).substr(2, 9),
              text: "ERR: NO_TARGET_SPECIFIED. Usage: SCAN [target]",
              timestamp: Date.now(),
              type: 'error'
            }]);
          } else {
            if (parts[1]) setTarget(parts[1]);
            lancerScan(scanTarget);
          }
          break;
        default:
          setTerminalLogs(prev => [...prev, {
            id: Math.random().toString(36).substr(2, 9),
            text: `UNKOWN_COMMAND: ${command}. Type HELP for valid instructions.`,
            timestamp: Date.now(),
            type: 'error'
          }]);
      }
    }, 100);
  };

  const [searchQuery, setSearchQuery] = useState('');

  // Reactive Graph Mapping Logic
  useEffect(() => {
    if (!scanResult) return;

    const { graph, risk_summary } = scanResult;
    if (!graph || !graph.nodes) return;

    const nouveauxNoeuds: Node[] = graph.nodes.map((n: any, i: number) => {
      const estCorrige = patches.includes(n.id);
      const cvss = n.properties.cvss ? parseFloat(n.properties.cvss) : 0;

      // Heatmap styles
      let baseColor = '#1e293b';
      if (n.node_type === 'Data') baseColor = '#ef4444';
      else if (n.node_type === 'Internet') baseColor = '#3b82f6';
      if (n.node_type === 'Host') baseColor = '#581c87';
      else if (n.node_type === 'Service') baseColor = '#334155';
      else if (n.node_type === 'User') baseColor = '#164e63';

      if (!estCorrige && cvss > 0) {
        if (cvss >= 9.0) baseColor = '#7f1d1d';
        else if (cvss >= 7.0) baseColor = '#b91c1c';
        else if (cvss >= 4.0) baseColor = '#c2410c';
        else baseColor = '#b45309';
      } else if (!estCorrige && n.properties.status === 'vulnerable') {
        baseColor = '#ea580c';
      }

      const isContained = n.properties.is_contained === 'true';
      const isCritical = n.properties.is_critical === 'true';
      const exploits = n.properties.exploits ? JSON.parse(n.properties.exploits) : [];
      const remediationPlan = n.properties.remediation_plan ? JSON.parse(n.properties.remediation_plan) : null;
      const hasExploit = exploits.length > 0;

      const matchesSearch = searchQuery && (
        n.label.toLowerCase().includes(searchQuery.toLowerCase()) ||
        n.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        Object.values(n.properties).some((v: any) => String(v).toLowerCase().includes(searchQuery.toLowerCase()))
      );

      return {
        id: n.id,
        position: { x: 250 + (i * 120), y: 100 + (i % 4 * 120) },
        data: { ...n, isPatched: estCorrige, isContained, isCritical, exploits, hasExploit, remediationPlan, isHighlighted: !!matchesSearch },
        className: !estCorrige && isCritical ? 'critical-node' : '',
        style: {
          background: estCorrige ? '#1f2937' : baseColor,
          color: estCorrige ? '#4b5563' : '#fff',
          border: matchesSearch ? '3px solid #6366f1' : (!estCorrige && isCritical ? '2px solid #eab308' : (!estCorrige && hasExploit ? '2px solid #ef4444' : '1px solid #334155')),
          borderRadius: n.node_type === 'User' ? '50%' : '8px',
          width: n.node_type === 'User' ? 60 : undefined,
          height: n.node_type === 'User' ? 60 : undefined,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: n.node_type === 'User' ? '8px' : '10px',
          opacity: estCorrige ? 0.5 : (searchQuery && !matchesSearch ? 0.3 : 1),
          zIndex: matchesSearch ? 1000 : 1
        }
      };
    });

    const nouvellesLiaisons: Edge[] = (graph.edges || []).map((e: any) => {
      const estImpacte = patches.includes(e.source) || patches.includes(e.target);
      return {
        id: e.id,
        source: e.source,
        target: e.target,
        label: e.label,
        animated: !estImpacte && (e.label === 'ExploitableBy' || e.label === 'Controls'),
        style: {
          stroke: estImpacte ? '#1f2937' : (e.label === 'ExploitableBy' ? '#10b981' : '#64748b'),
          strokeWidth: 2,
          opacity: estImpacte ? 0.3 : 1
        },
        markerEnd: { type: MarkerType.ArrowClosed, color: estImpacte ? '#1f2937' : '#10b981' },
      };
    });

    const reachableSet = attackerPoint ? getReachableNodes(attackerPoint, nouvellesLiaisons) : null;
    const noeudsFinaux = nouveauxNoeuds.map(node => {
      if (attackerPoint && reachableSet) {
        const isReachable = reachableSet.has(node.id);
        const isSource = node.id === attackerPoint;
        return {
          ...node,
          style: {
            ...node.style,
            border: isSource ? '4px solid #3b82f6' : (isReachable ? (node.style?.border || '1px solid #334155') : '1px dashed #334155'),
            opacity: isReachable || isSource ? 1 : 0.2,
          }
        };
      }
      return node;
    });

    setNodes(noeudsFinaux);
    setEdges(nouvellesLiaisons);

    if (patches.length === 0 && !baselineSummary) {
      setBaselineSummary(risk_summary);
    }
  }, [scanResult, patches, attackerPoint, searchQuery]);
  const [activeTunnels, setActiveTunnels] = useState<any[]>([]);

  // Scan Options
  const [scanProfile, setScanProfile] = useState('normal');
  const [customPorts, setCustomPorts] = useState('');
  const [scanTiming, setScanTiming] = useState(4);
  const [enableUdp, setEnableUdp] = useState(false);
  const [enableShodan, setEnableShodan] = useState(false);
  const [enableVirusTotal, setEnableVirusTotal] = useState(false);
  const [enableCensys, setEnableCensys] = useState(false);
  const [enableAlienVault, setEnableAlienVault] = useState(false);
  const [webhookUrl, setWebhookUrl] = useState(localStorage.getItem('path2root_webhook') || '');
  const [showSettings, setShowSettings] = useState(false);
  const [isFilterPanelOpen, setIsFilterPanelOpen] = useState(false);
  const [graphFilters, setGraphFilters] = useState<GraphFilters>({
    showCritical: true, showHigh: true, showMedium: true, showLow: true, showInfo: true,
    showHosts: true, showServices: true, showWeb: true, searchQuery: ''
  });

  // Apply filters whenever filters or nodes change
  useEffect(() => {
    setNodes((nds) => nds.map((node) => {
      let isVisible = true;
      const props = node.data.properties || {};

      // 1. Text Search Filter
      if (graphFilters.searchQuery) {
        const query = graphFilters.searchQuery.toLowerCase();
        const matchesLabel = node.data.label.toLowerCase().includes(query);
        const matchesService = props.service?.toLowerCase().includes(query);
        const matchesCVE = props.vulns?.some((v: any) => v.cve?.toLowerCase().includes(query));

        if (!matchesLabel && !matchesService && !matchesCVE) {
          isVisible = false;
        }
      }

      // 2. Node Type Filter
      if (isVisible) {
        if (node.data.node_type === 'Host' && !graphFilters.showHosts) isVisible = false;
        else if (node.data.node_type === 'Service' && !graphFilters.showServices) isVisible = false;
        else if (node.data.node_type === 'Web' && !graphFilters.showWeb) isVisible = false;
      }

      // 3. Severity Filter (for Vulnerabilities or Services having max_severity)
      // Note: "status" === "vulnerable" usually implies we check severity
      if (isVisible && props.status === 'vulnerable') {
        const impact = props.exploit_impact ? parseInt(props.exploit_impact) : 0;
        // Simple mapping based on backend logic
        // 9+ = Critical, 7-8 = High, 4-6 = Medium, <4 = Low
        if (impact >= 9 && !graphFilters.showCritical) isVisible = false;
        else if (impact >= 7 && impact < 9 && !graphFilters.showHigh) isVisible = false;
        else if (impact >= 4 && impact < 7 && !graphFilters.showMedium) isVisible = false;
        else if (impact < 4 && !graphFilters.showLow) isVisible = false;
      }

      return {
        ...node,
        hidden: !isVisible,
      };
    }));
  }, [graphFilters, nodes.length]); // Dep on nodes.length to avoid loops, but might miss updates. Better to use manual trigger or check actual content diff if possible. Using length is safe for now.

  const loadMissionDetails = async (id: string) => {
    setIsMissionLoading(true);
    try {
      const token = localStorage.getItem('path2root_token');
      const headers = token ? { Authorization: `Bearer ${token}` } : {};
      const resp = await axios.get(`/api/mission/${id}`, { headers });
      setMissionData(resp.data);

      // Restore graph if available
      if (resp.data.graph && resp.data.graph.nodes) {
        setNodes(resp.data.graph.nodes);
        setEdges(resp.data.graph.edges);

        // Auto-layout or fit view could happen here
      }

      setTerminalLogs(prev => [...prev, {
        id: Math.random().toString(36).substr(2, 9),
        text: `✅ Mission loaded: ${resp.data.target} (${resp.data.id})`,
        timestamp: Date.now(),
        type: 'success'
      }]);
    } catch (err) {
      console.error("Failed to load mission details", err);
      setTerminalLogs(prev => [...prev, {
        id: Math.random().toString(36).substr(2, 9),
        text: `❌ Failed to load mission details`,
        timestamp: Date.now(),
        type: 'error'
      }]);
    } finally {
      setIsMissionLoading(false);
    }
  };

  const fetchMissions = async () => {
    try {
      const token = localStorage.getItem('path2root_token');
      const headers = token ? { Authorization: `Bearer ${token}` } : {};
      const response = await axios.get('/api/missions', { headers });
      setMissions(response.data);
    } catch (err) {
      console.error(err);
    }
  };

  const fetchTunnels = async () => {
    try {
      const token = localStorage.getItem('path2root_token');
      const headers = token ? { Authorization: `Bearer ${token}` } : {};
      const resp = await axios.get('/api/pivots', { headers });
      setActiveTunnels(resp.data);
    } catch (err) {
      console.error("Erreur lors de la récupération des tunnels", err);
    }
  };

  // Memoize Node Types for ReactFlow Performance
  const nodeTypes = useMemo(() => ({
    // custom types here if any
  }), []);

  // Chargement Initial & Intercepteur Axios
  useEffect(() => {
    // Configuration de l'intercepteur pour injecter le token
    const interceptor = axios.interceptors.request.use(config => {
      const token = localStorage.getItem('path2root_token');
      if (token && config.headers) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    }, error => Promise.reject(error));

    const saved = localStorage.getItem('path2root_session');
    if (saved) {
      try {
        const { target, patches, auditLog, attackerPoint } = JSON.parse(saved);
        setTarget(target || '127.0.0.1');
        setPatches(patches || []);
        setAuditLog(auditLog || []);
        setAttackerPoint(attackerPoint || null);
      } catch (e) {
        console.error("Erreur de restauration de session", e);
      }
    }
  }, []);

  // Sauvegarde Automatique
  useEffect(() => {
    const session = { target, patches, auditLog, attackerPoint };
    localStorage.setItem('path2root_session', JSON.stringify(session));
  }, [target, patches, auditLog, attackerPoint]);

  useEffect(() => {
    if (isAuthenticated) {
      fetchMissions();
      fetchTunnels();
      fetchSchedules();
      const interval = setInterval(fetchTunnels, 5000);
      return () => clearInterval(interval);
    }
  }, [isAuthenticated]);

  // WebSocket Live Updates
  useEffect(() => {
    if (!isAuthenticated) return;

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const socket = new WebSocket(`${protocol}//${window.location.host}/ws`);

    socket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        // data structure: { mission_id, payload: { type, data } }
        const { mission_id, payload } = data;

        if (payload.type === 'Mission') {
          if (missionData && mission_id === missionData.id) {
            setMissionData(payload.data);
            fetchMissions();
          }
        } else if (payload.type === 'TerminalOutput') {
          // Si c'est un log en temps réel, on l'ajoute au terminal
          const text = payload.data.text;
          let logType: 'command' | 'output' | 'success' | 'error' | 'info' | 'warning' = payload.data.is_error ? 'error' : 'output';

          if (!payload.data.is_error) {
            const lowerText = text.toLowerCase();
            if (lowerText.startsWith('[phase') || lowerText.includes('starting') || lowerText.includes('discovery')) logType = 'info';
            else if (lowerText.includes('success') || lowerText.includes('found') || lowerText.includes('✅')) logType = 'success';
            else if (lowerText.includes('warn') || lowerText.includes('⚠️')) logType = 'warning';
            else if (text.startsWith('$') || text.startsWith('>')) logType = 'command';
          }

          setTerminalLogs(prev => [...prev.slice(-99), {
            id: Math.random().toString(36).substr(2, 9),
            text: text,
            timestamp: Date.now(),
            type: logType
          }]);
        } else if (payload.type === 'ScanResult') {
          console.log("Received ScanResult over WS:", payload.data);
          setScanResult(payload.data);
          // useEffect now handles mapping to nodes/edges
        }
      } catch (err) {
        console.error("Socket error parse:", err);
      }
    };

    socket.onopen = () => console.log("Connected to Tactical WebSocket");
    socket.onerror = (e) => console.error("Socket error:", e);
    socket.onclose = () => console.log("Disconnected from Tactical WebSocket");

    return () => socket.close();
  }, [isAuthenticated, missionData?.id]);

  if (!isAuthenticated) {
    return authMode === 'login'
      ? <Login onToggle={() => setAuthMode('register')} />
      : <Register onToggle={() => setAuthMode('login')} />;
  }

  const getReachableNodes = (startNodeId: string, currentEdges: Edge[]): Set<string> => {
    const reachable = new Set<string>([startNodeId]);
    const queue = [startNodeId];

    while (queue.length > 0) {
      const current = queue.shift()!;
      // On cherche les edges qui partent de 'current' et qui ne sont pas impactés par un patch
      currentEdges.forEach(edge => {
        if (edge.source === current && edge.style?.opacity !== 0.3) {
          if (!reachable.has(edge.target)) {
            reachable.add(edge.target);
            queue.push(edge.target);
          }
        }
      });
    }
    return reachable;
  };

  const downloadReport = async (missionId: string) => {
    try {
      const resp = await axios.get(`/api/mission/report/${missionId}`);
      const blob = new Blob([resp.data], { type: 'text/markdown' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `Path2Root_Report_${missionId}.md`;
      a.click();
    } catch (err) {
      console.error("Erreur téléchargement rapport", err);
    }
  };

  const exportScan = async () => {
    if (!missionData) return;

    try {
      const token = localStorage.getItem('path2root_token');
      const headers = token ? { Authorization: `Bearer ${token}` } : {};
      const response = await axios.get(`/api/mission/export/${missionData.id}`, { headers });

      const blob = new Blob([JSON.stringify(response.data, null, 2)], { type: 'application/json' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `scan_${missionData.target}_${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      setTerminalLogs(prev => [...prev, {
        id: Math.random().toString(36).substr(2, 9),
        text: `✅ Scan exported successfully: ${a.download}`,
        timestamp: Date.now(),
        type: 'success'
      }]);
    } catch (err) {
      console.error('Export error:', err);
      setTerminalLogs(prev => [...prev, {
        id: Math.random().toString(36).substr(2, 9),
        text: `❌ Export failed: ${err}`,
        timestamp: Date.now(),
        type: 'error'
      }]);
    }
  };

  const importScan = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const scanData = JSON.parse(e.target?.result as string);

        // Restore mission data
        setMissionData({
          id: scanData.mission_id,
          target: scanData.target,
          graph: scanData.graph,
          status: scanData.metadata.status || 'Completed',
          vulnerabilities: [],
          logs: [],
          created_at: scanData.timestamp
        });

        // Restore graph
        setNodes(scanData.graph.nodes || []);
        setEdges(scanData.graph.edges || []);

        setTerminalLogs(prev => [...prev, {
          id: Math.random().toString(36).substr(2, 9),
          text: `✅ Scan imported successfully: ${scanData.target}`,
          timestamp: Date.now(),
          type: 'success'
        }]);
      } catch (err) {
        console.error('Import error:', err);
        setTerminalLogs(prev => [...prev, {
          id: Math.random().toString(36).substr(2, 9),
          text: `❌ Import failed: Invalid scan file`,
          timestamp: Date.now(),
          type: 'error'
        }]);
      }
    };
    reader.readAsText(file);
  };

  const generateProfessionalPDF = (format: 'executive' | 'technical' | 'hackerone') => {
    const doc = new jsPDF();
    const isEn = reportLang === 'en';
    const date = new Date().toLocaleString();

    // 1. Title & Header Professional
    doc.setFontSize(22);
    doc.setTextColor(30, 41, 59);
    doc.text(
      format === 'executive' ? "Executive Risk Summary" :
        format === 'technical' ? "Detailed Technical Audit" :
          "Path2Root Security Assessment", 15, 20
    );

    doc.setFontSize(10);
    doc.setTextColor(100, 116, 139);
    doc.text(`${isEn ? 'Target' : 'Cible'}: ${target}`, 15, 28);
    doc.text(`${isEn ? 'Report Type' : 'Type de Rapport'}: ${format.toUpperCase()}`, 15, 33);
    doc.text(`${isEn ? 'Date' : 'Date'}: ${date}`, 15, 38);

    doc.setDrawColor(226, 232, 240);
    doc.line(15, 42, 195, 42);

    // 2. Executive Section (if applicable)
    if (format === 'executive') {
      doc.setFontSize(16);
      doc.setTextColor(79, 70, 229); // Indigo-600
      doc.text(isEn ? "Strategic Impact" : "Impact Stratégique", 15, 52);

      const impactScore = (nodes.filter(n => n.data.properties.status === 'vulnerable').length * 15);
      doc.setFontSize(11);
      doc.setTextColor(30, 41, 59);
      doc.text(isEn ? `Infrastructure Criticality: ${impactScore}%` : `Criticité de l'Infrastructure : ${impactScore}%`, 15, 60);

      const top3 = nodes
        .filter(n => n.data.properties.status === 'vulnerable')
        .sort((a, b) => parseFloat(b.data.properties.cvss || '0') - parseFloat(a.data.properties.cvss || '0'))
        .slice(0, 3);

      doc.text(isEn ? "Top High-Value Targets At Risk:" : "Cibles Prioritaires Menacées :", 15, 70);
      top3.forEach((n, i) => {
        doc.text(`- ${n.data.label} (CVSS: ${n.data.properties.cvss || '5.0'})`, 20, 78 + (i * 6));
      });

      autoTable(doc, {
        startY: 100,
        head: [[isEn ? "Asset" : "Actif", isEn ? "Security Posture" : "Posture de Sécurité", isEn ? "Recommendation" : "Recommandation"]],
        body: top3.map(n => [n.data.label, "CRITICAL", "Immediate Patching Required"]),
        headStyles: { fillColor: '#4338ca' }
      });

      doc.save(`${target}_Executive_Report.pdf`);
      return;
    }

    // Common Data Logic (Risk Summary)
    doc.setFontSize(16);
    doc.setTextColor(30, 41, 59);
    doc.text(isEn ? "Risk Summary" : "Résumé du Risque", 15, 52);

    const riskData = [
      [isEn ? "Total Hosts" : "Hôtes Totaux", nodes.filter(n => n.data.node_type === 'Host').length],
      [isEn ? "Vulnerable Services" : "Services Vulnérables", nodes.filter(n => n.data.properties.status === 'vulnerable').length],
      [isEn ? "Business Impact Score" : "Score d'Impact Métier", `${((nodes.filter(n => n.data.properties.status === 'vulnerable').length * 15)).toString()}/100`],
    ];

    autoTable(doc, {
      startY: 58,
      head: [[isEn ? "Metric" : "Métrique", isEn ? "Value" : "Valeur"]],
      body: riskData,
      theme: 'striped',
      headStyles: { fillColor: '#334155' }
    });

    // 3. Technical Findings Table (More detailed in technical format)
    doc.setFontSize(16);
    doc.text(isEn ? "Findings Overview" : "Aperçu des Découvertes", 15, (doc as any).lastAutoTable.finalY + 15);

    const findingsData = nodes
      .filter(n => n.data.properties.status === 'vulnerable')
      .map(n => [
        n.data.label,
        n.data.properties.cvss || '5.0',
        n.data.properties.exploit_impact ? (parseInt(n.data.properties.exploit_impact) >= 7 ? 'HIGH' : 'MEDIUM') : 'MEDIUM',
        format === 'technical' ? (n.data.properties.service || 'N/A') : (n.data.properties.ai_analysis ? n.data.properties.ai_analysis.substring(0, 50) + '...' : 'N/A')
      ]);

    if (findingsData.length > 0) {
      autoTable(doc, {
        startY: (doc as any).lastAutoTable.finalY + 20,
        head: [[isEn ? "Component" : "Composant", "CVSS", isEn ? "Severity" : "Sévérité", format === 'technical' ? "Service" : "Description"]],
        body: findingsData,
        theme: 'grid',
        headStyles: { fillColor: format === 'technical' ? '#1e293b' : '#4f46e5' }
      });
    }

    if (format === 'hackerone') {
      doc.save(`${target}_HackerOne_Report.pdf`);
      return;
    }

    // Technical Format specific additions (Vulnerability Matrix & Details)
    const vulns = edges.filter((e: Edge) => {
      const t = nodes.find((n: Node) => n.id === e.target);
      return t?.data?.properties?.status === 'vulnerable';
    });

    if (vulns.length > 0 && format === 'technical') {
      doc.setFontSize(16);
      doc.text(isEn ? "Detailed Technical Findings" : "Détails Techniques des Failles", 15, (doc as any).lastAutoTable.finalY + 15);

      let currentY = (doc as any).lastAutoTable.finalY + 25;

      vulns.forEach((e: Edge, index: number) => {
        const t = nodes.find((n: Node) => n.id === e.target)!;
        if (currentY > 260) { doc.addPage(); currentY = 20; }

        doc.setFontSize(12);
        doc.setTextColor(30, 41, 59);
        doc.text(`${index + 1}. ${t.data.label}`, 15, currentY);
        currentY += 7;

        doc.setFontSize(9);
        doc.setTextColor(100, 116, 139);
        if (t.data.properties.finding) {
          doc.text(`Issue: ${t.data.properties.finding}`, 15, currentY);
          currentY += 5;
        }
        if (t.data.properties.poc_command) {
          doc.setFont("courier", "normal");
          doc.text(`PoC: ${t.data.properties.poc_command}`, 15, currentY);
          doc.setFont("helvetica", "normal");
          currentY += 6;
        }
        if (t.data.properties.remediation_plan) {
          try {
            const rem = JSON.parse(t.data.properties.remediation_plan);
            doc.text(`Mitigation: ${rem.description}`, 15, currentY, { maxWidth: 170 });
            currentY += 7;
          } catch {
            doc.text(`Mitigation: ${t.data.properties.remediation_plan}`, 15, currentY, { maxWidth: 170 });
            currentY += 7;
          }
        }
        currentY += 5;
      });
    }

    // 5. Mission Logs (Only for Technical)
    if (format === 'technical' && missionData?.logs && missionData.logs.length > 0) {
      doc.addPage();
      doc.setFontSize(16);
      doc.text(isEn ? "Mission Execution Timeline" : "Chronologie de la Mission", 15, 20);

      const logRows = missionData.logs.map((log: any) => {
        const time = new Date(log.timestamp * 1000).toLocaleTimeString();
        return [time, log.title, log.status];
      });

      autoTable(doc, {
        startY: 25,
        head: [[isEn ? "Time" : "Heure", "Action", "Status"]],
        body: logRows,
        theme: 'plain',
        headStyles: { fillColor: [30, 41, 59] },
      });
    }

    // Footer & Page Numbers
    const pageCount = (doc as any).internal.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
      doc.setPage(i);
      doc.setFontSize(8);
      doc.setTextColor(148, 163, 184);
      doc.text(`Page ${i} of ${pageCount} - Path2Root Tactical Report`, 105, 290, { align: 'center' });
    }

    doc.save(`${target}_${format.charAt(0).toUpperCase() + format.slice(1)}_Report.pdf`);
  };

  const envoyerMessage = async () => {
    if (!chatInput.trim()) return;
    const userMsg = chatInput;
    setChatMessages(prev => [...prev, { role: 'user', content: userMsg }]);
    setChatInput('');
    try {
      const resp = await axios.post('/api/chat', { message: userMsg, lang: reportLang });
      setChatMessages(prev => [...prev, { role: 'ai', content: resp.data.reply }]);
    } catch (err) {
      console.error(err);
    }
  };

  const lancerMission = async () => {
    if (!target) return;
    setIsMissionLoading(true);
    setViewMode('mission');
    try {
      const resp = await axios.post('/api/mission', { target, lang: reportLang });
      setMissionData(resp.data);
      setActiveScanId(resp.data.id);
      setIsScanning(true); // Mark as scanning for mission too
      fetchMissions(); // Refresh history
    } catch (err) {
      console.error(err);
    } finally {
      setIsMissionLoading(false);
    }
  };

  const pauseScan = async () => {
    if (!activeScanId) return;
    setIsScanPaused(true); // Optimistic Update
    try {
      console.log("Pausing scan:", activeScanId);
      await axios.post(`/api/scan/pause/${activeScanId}`);
      setTerminalLogs(prev => [...prev.slice(-99), {
        id: Math.random().toString(36).substr(2, 9),
        text: `⏸ [CONTROL] Sending Pause signal for ${activeScanId}...`,
        timestamp: Date.now(),
        type: 'info'
      }]);
    } catch (err) {
      console.error("Pause failed", err);
      setIsScanPaused(false);
    }
  };

  const resumeScan = async () => {
    if (!activeScanId) return;
    setIsScanPaused(false); // Optimistic Update
    try {
      console.log("Resuming scan:", activeScanId);
      await axios.post(`/api/scan/resume/${activeScanId}`);
      setTerminalLogs(prev => [...prev.slice(-99), {
        id: Math.random().toString(36).substr(2, 9),
        text: `▶️ [CONTROL] Sending Resume signal for ${activeScanId}...`,
        timestamp: Date.now(),
        type: 'info'
      }]);
    } catch (err) {
      console.error("Resume failed", err);
      setIsScanPaused(true);
    }
  };

  const stopScan = async () => {
    if (!activeScanId) return;
    try {
      console.log("Stopping scan:", activeScanId);
      await axios.post(`/api/scan/stop/${activeScanId}`);
      setTerminalLogs(prev => [...prev.slice(-99), {
        id: Math.random().toString(36).substr(2, 9),
        text: `⏹ [CONTROL] Sending Stop signal for ${activeScanId}...`,
        timestamp: Date.now(),
        type: 'warning'
      }]);
      setIsScanning(false);
      setIsScanPaused(false);
      setActiveScanId(null);
    } catch (err) {
      console.error("Stop failed", err);
    }
  };

  const stopTunnel = async (id: string) => {
    try {
      await axios.delete(`/api/pivots/${id}`);
      fetchTunnels();
    } catch (err) {
      console.error("Erreur lors de l'arrêt du tunnel", err);
    }
  };

  const verifierNode = async (nodeId: string, label: string, properties: any) => {
    // Extraire l'IP et le port depuis le label ou les propriétés
    const targetIp = properties.ip || label.split(':')[0];
    const port = properties.port || label.split(':')[1]?.split(' ')[0] || "80";

    // Phase 20.1: Détection de proxy pour la vérification
    let proxyUrl = null;
    if (attackerPoint) {
      const tunnel = activeTunnels.find(t => t.target_node === attackerPoint);
      if (tunnel) {
        proxyUrl = `socks5://127.0.0.1:${tunnel.local_port}`;
      }
    }

    setTerminalLogs(prev => [...prev, {
      id: Math.random().toString(36).substr(2, 9),
      text: `$ nmap ${proxyUrl ? '--proxies ' + proxyUrl + ' ' : ''}-p ${port} --open -Pn -n ${targetIp} # VERIFYING REMEDIATION`,
      timestamp: Date.now(),
      type: 'command'
    }]);

    try {
      const resp = await axios.post('/api/verify', {
        node_id: nodeId,
        target_ip: targetIp,
        port: port.toString(),
        lang: reportLang,
        proxy_url: proxyUrl || undefined
      });

      const { status, message } = resp.data;

      setTerminalLogs(prev => [...prev, {
        id: Math.random().toString(36).substr(2, 9),
        text: status === 'patched' ? `✓ ${message}` : `! ${message}`,
        timestamp: Date.now(),
        type: status === 'patched' ? 'success' : 'error'
      }]);

      // Mettre à jour localement le statut du nœud dans le graphe
      setScanResult((prev: any) => {
        if (!prev) return prev;
        const newNodes = prev.graph.nodes.map((n: any) => {
          if (n.id === nodeId) {
            return { ...n, properties: { ...n.properties, status: status, verification_msg: message } };
          }
          return n;
        });
        return { ...prev, graph: { ...prev.graph, nodes: newNodes } };
      });

    } catch (err) {
      console.error(err);
      setTerminalLogs(prev => [...prev, {
        id: Math.random().toString(36).substr(2, 9),
        text: `Error during verification: ${err}`,
        timestamp: Date.now(),
        type: 'error'
      }]);
    }
  };

  const lancerScan = async (overrideTarget?: string, overridePatches?: string[], overrideAttackerPoint?: string | null) => {
    const activeTarget = overrideTarget ?? target;
    if (!activeTarget) return;

    console.log("lancerScan triggered for:", activeTarget);
    setIsScanning(true);
    setIsScanPaused(false);
    setActiveScanId(activeTarget);

    try {
      setTerminalLogs(prev => [...prev.slice(-99), {
        id: Math.random().toString(36).substr(2, 9),
        text: `$ nmap -sV -sC -O ${activeTarget}`,
        timestamp: Date.now(),
        type: 'command'
      }]);

      await axios.post('/api/scan', {
        target: activeTarget,
        lang: reportLang,
        profile: scanProfile,
        patches: overridePatches ?? patches,
        attacker_point: overrideAttackerPoint ?? attackerPoint,
        auto_exploit: true,
      });

      console.log("Scan acknowledged by backend.");
    } catch (err) {
      console.error("Scan launch failed:", err);
      setIsScanning(false);
      setActiveScanId(null);
    }
  };



  const basculerPatch = (nodeId: string, nodeLabel?: string) => {
    const estAjout = !patches.includes(nodeId);
    const nouveauxPatches = estAjout
      ? [...patches, nodeId]
      : patches.filter(id => id !== nodeId);

    setPatches(nouveauxPatches);

    // Log Audit
    const actionLabel = estAjout ? `Correctif appliqué : ${nodeLabel || nodeId}` : `Correctif retiré : ${nodeLabel || nodeId}`;
    setAuditLog(prev => [{ id: Math.random().toString(36).substr(2, 9), action: actionLabel, timestamp: Date.now() }, ...prev]);

    lancerScan(undefined, nouveauxPatches);
  };

  const reinitialiserAudit = () => {
    if (confirm("Voulez-vous vraiment réinitialiser toute la simulation ?")) {
      setPatches([]);
      setAuditLog([]);
      setAttackerPoint(null);
      setBaselineSummary(null);
      lancerScan(undefined, []);
    }
  };

  const exporterRapport = async () => {
    if (!scanResult) return;
    try {
      const response = await axios.post('/api/report/html', scanResult, { responseType: 'blob' });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `Path2Root_Report_${target.replace(/[^a-zA-Z0-9]/g, '_')}.html`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (e) {
      console.error("Export failed, falling back to JSON", e);
      // Fallback to JSON
      const blob = new Blob([JSON.stringify(scanResult, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `Path2Root_Rapport_${target.replace('/', '_')}.json`;
      a.click();
    }
  };

  return (
    <div className={`flex h-screen w-screen ${theme === 'dark' ? 'bg-[#0d0d0d] text-slate-200' : 'bg-slate-50 text-slate-900'} overflow-hidden transition-colors duration-300`}>
      {/* Bouton Menu Mobile */}
      <button
        onClick={() => setIsSidebarOpen(!isSidebarOpen)}
        className="fixed top-4 left-4 z-50 p-2 bg-indigo-600 text-white rounded-lg md:hidden"
      >
        {isSidebarOpen ? <X size={20} /> : <Menu size={20} />}
      </button>

      {/* Barre Latérale Gauche */}
      <aside className={`fixed md:relative z-40 w-64 h-[calc(100%-2rem)] border-r ${theme === 'dark' ? 'border-slate-800' : 'border-slate-200'} p-6 flex flex-col gap-8 glass-panel m-4 rounded-3xl shadow-2xl no-print transition-all duration-300 ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'}`}>
        <div className="flex items-center justify-between gap-3 px-2">
          <div className="flex items-center gap-3 group cursor-pointer" onClick={() => setViewMode('graph')}>
            <div className="p-2 bg-indigo-500/10 rounded-xl group-hover:scale-110 transition-transform">
              <Shield className="text-indigo-500" size={24} />
            </div>
            <h1 className="text-xl font-black tracking-tighter bg-gradient-to-r from-white to-slate-400 bg-clip-text text-transparent">Path2Root</h1>
          </div>
          <button onClick={toggleTheme} className="p-2 hover:bg-slate-500/10 rounded-xl transition-colors">
            {theme === 'dark' ? <Sun size={16} className="text-amber-400" /> : <Moon size={16} className="text-indigo-600" />}
          </button>
        </div>

        <nav className="flex-1 overflow-y-auto pr-2 custom-scrollbar space-y-1">
          <div className="text-[10px] font-black text-slate-500 uppercase tracking-[0.2em] mb-4 px-4 opacity-50">Operational Modes</div>

          <button
            onClick={() => setViewMode('graph')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-2xl transition-all duration-300 ${viewMode === 'graph' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/30' : 'text-slate-400 hover:bg-white/5 hover:text-white'}`}
          >
            <LayoutDashboard size={18} />
            <span className="font-bold text-sm">{reportLang === 'en' ? 'Attack Graph' : 'Graphe d\'Attaque'}</span>
          </button>

          <button
            onClick={() => setViewMode('mission')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-2xl transition-all duration-300 ${viewMode === 'mission' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/30' : 'text-slate-400 hover:bg-white/5 hover:text-white'}`}
          >
            <Rocket size={18} />
            <span className="font-bold text-sm">{reportLang === 'en' ? 'Mission Hub' : 'Hub de Mission'}</span>
          </button>

          <button
            onClick={() => setViewMode('schedules')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-2xl transition-all duration-300 ${viewMode === 'schedules' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/30' : 'text-slate-400 hover:bg-white/5 hover:text-white'}`}
          >
            <Calendar size={18} />
            <span className="font-bold text-sm">{reportLang === 'en' ? 'Strategic Planning' : 'Planning Stratégique'}</span>
          </button>

          <button
            onClick={() => setViewMode('analytics')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-2xl transition-all duration-300 ${viewMode === 'analytics' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/30' : 'text-slate-400 hover:bg-white/5 hover:text-white'}`}
          >
            <Activity size={18} />
            <span className="font-bold text-sm">{reportLang === 'en' ? 'Live Analytics' : 'Analyses Live'}</span>
          </button>

          <div className="pt-6">
            <div className="text-[10px] font-black text-slate-500 uppercase tracking-[0.2em] mb-4 px-4 opacity-50">Assets & Intel</div>

            <button
              onClick={() => setViewMode('inventory')}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-2xl transition-all duration-300 ${viewMode === 'inventory' ? 'bg-indigo-600 text-white shadow-lg' : 'text-slate-400 hover:bg-white/5 hover:text-white'}`}
            >
              <ShieldCheck size={18} />
              <span className="font-bold text-sm">{reportLang === 'en' ? 'Inventory' : 'Inventaire'}</span>
            </button>

            <button
              onClick={() => setViewMode('vulnerabilities')}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-2xl transition-all duration-300 ${viewMode === 'vulnerabilities' ? 'bg-rose-600 text-white shadow-lg' : 'text-slate-400 hover:bg-white/5 hover:text-white'}`}
            >
              <Zap size={18} />
              <span className="font-bold text-sm">{reportLang === 'en' ? 'Findings' : 'Découvertes'}</span>
            </button>

            <button
              onClick={() => setViewMode('osint')}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-2xl transition-all duration-300 ${viewMode === 'osint' ? 'bg-indigo-600 text-white shadow-lg' : 'text-slate-400 hover:bg-white/5 hover:text-white'}`}
            >
              <Compass size={18} />
              <span className="font-bold text-sm">{reportLang === 'en' ? 'Intel/OSINT' : 'Renseignement'}</span>
            </button>
          </div>
        </nav>

        <div className="space-y-4 pt-6 border-t border-slate-800/60 no-print">
          <div className="flex items-center justify-between p-3 bg-white/5 rounded-2xl border border-white/5 group hover:border-indigo-500/30 transition-all">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-indigo-500/20 rounded-xl flex items-center justify-center text-indigo-400 ring-2 ring-indigo-500/10 group-hover:ring-indigo-500/30 transition-all">
                <User size={20} />
              </div>
              <div className="min-w-0">
                <div className="text-xs font-black text-white truncate">{user?.username}</div>
                <div className="text-[10px] text-slate-500 font-bold uppercase tracking-widest">{user?.role}</div>
              </div>
            </div>
            <button
              onClick={logout}
              className="p-2 text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 rounded-xl transition-all"
              title="Logout"
            >
              <LogOut size={18} />
            </button>
          </div>
        </div>
      </aside>
      <main className="flex-1 flex flex-col min-h-0 bg-transparent relative overflow-hidden m-4 rounded-3xl border border-white/5 shadow-2xl">
        {/* Tactical Display - Floating Top Right */}
        <div className="absolute top-4 right-4 z-30 w-96 max-h-[40%] group pointer-events-none no-print">
          <div className="pointer-events-auto bg-slate-950/80 backdrop-blur-xl border border-slate-700/50 rounded-2xl shadow-2xl overflow-hidden animate-slide-in-right">
            <div className="px-4 py-2 bg-slate-900/80 flex items-center justify-between border-b border-slate-700/50">
              <div className="flex items-center gap-2">
                <Terminal size={14} className="text-indigo-400" />
                <span className="text-[10px] font-black text-white uppercase tracking-tighter">Tactical Display</span>
              </div>
            </div>
            <div className="p-2 h-48 overflow-auto custom-scrollbar">
              <CommandTerminal logs={terminalLogs} onCommand={handleTerminalCommand} />
            </div>
          </div>
        </div>

        <div className="flex-1 flex min-h-0 relative">
          {viewMode === 'graph' && (
            <div className="flex-1 flex flex-col min-h-0 relative overflow-hidden">
              {/* Search bar absolute top left */}
              <div className="absolute top-6 left-6 z-10 w-96 group no-print">
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                    <Search className="text-slate-500 group-focus-within:text-indigo-500 transition-colors" size={18} />
                  </div>
                  <input
                    type="text"
                    placeholder={reportLang === 'en' ? "Search graph assets..." : "Rechercher dans le graphe..."}
                    className="w-full pl-12 pr-4 py-3 bg-slate-900/80 border border-slate-800 rounded-2xl text-xs text-white focus:outline-none focus:border-indigo-500 transition-all font-bold backdrop-blur-xl shadow-2xl"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                  />
                </div>
              </div>

              {/* Main Graph Layout */}
              <div className="flex-1 relative">
                <GraphFilterPanel
                  filters={graphFilters}
                  setFilters={setGraphFilters}
                  isOpen={isFilterPanelOpen}
                  setIsOpen={setIsFilterPanelOpen}
                  lang={reportLang}
                />

                {/* Floating View Toggle */}
                <div className="absolute bottom-6 left-6 z-20 flex flex-col gap-2 no-print">
                  <div className="flex p-1 bg-slate-950/80 backdrop-blur-xl border border-slate-700/50 rounded-xl shadow-2xl">
                    <button
                      onClick={() => setGraphMode('2d')}
                      className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-black transition-all ${graphMode === '2d' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/30' : 'text-slate-500 hover:text-white'}`}
                    >
                      <BoxSelect size={14} /> 2D
                    </button>
                    <button
                      onClick={() => setGraphMode('3d')}
                      className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-black transition-all ${graphMode === '3d' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/30' : 'text-slate-500 hover:text-white'}`}
                    >
                      <BoxSelect size={14} className="rotate-45" /> 3D
                    </button>
                  </div>
                </div>
                {graphMode === '2d' ? (
                  <ReactFlow
                    nodes={nodes}
                    edges={edges}
                    nodeTypes={nodeTypes}
                    onNodesChange={onNodesChange}
                    onEdgesChange={onEdgesChange}
                    onConnect={onConnect}
                    onNodeClick={(_, noeud) => setSelectedNode(noeud.data)}
                    fitView
                    onlyRenderVisibleElements={true}
                    className="no-print"
                  >
                    <Background color="#1e293b" gap={20} />
                    <Controls />
                  </ReactFlow>
                ) : (
                  <AttackGraph3D
                    nodes={nodes}
                    edges={edges}
                    onNodeClick={(nodeData) => setSelectedNode(nodeData)}
                  />
                )}
              </div>
            </div>
          )}

          {viewMode === 'analytics' && <AnalyticsDashboard lang={reportLang} />}

          {viewMode === 'schedules' && (
            <div className="flex-1 overflow-auto p-12 bg-[#050505]">
              <div className="max-w-5xl mx-auto">
                <div className="flex items-center gap-4 mb-10">
                  <div className="p-4 bg-indigo-500/10 rounded-3xl border border-indigo-500/20">
                    <Calendar className="text-indigo-400" size={32} />
                  </div>
                  <div>
                    <h2 className="text-3xl font-black text-white tracking-tighter">Mission Planning</h2>
                    <p className="text-slate-500 text-sm">{reportLang === 'en' ? 'Manage recurring offensive operations and schedules.' : 'Gérez les opérations offensives récurrentes.'}</p>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                  <div className="lg:col-span-1">
                    <div className="glass-panel p-6 rounded-3xl border border-slate-800 bg-slate-900/30">
                      <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-6">Create New Schedule</h3>
                      <div className="space-y-4">
                        <div>
                          <label className="text-[10px] font-black text-slate-500 uppercase block mb-2 px-1">Target</label>
                          <input
                            type="text"
                            className="w-full bg-slate-950 border border-slate-800 rounded-xl py-3 px-4 text-xs font-bold text-white outline-none focus:border-indigo-500 transition-all"
                            placeholder="target.com"
                            value={scheduleForm.target}
                            onChange={(e) => setScheduleForm({ ...scheduleForm, target: e.target.value })}
                          />
                        </div>
                        <div>
                          <label className="text-[10px] font-black text-slate-500 uppercase block mb-2 px-1">Frequency (Cron)</label>
                          <input
                            type="text"
                            className="w-full bg-slate-950 border border-slate-800 rounded-xl py-3 px-4 text-xs font-bold text-white outline-none focus:border-indigo-500 transition-all"
                            placeholder="ex: 0 0 * * *"
                            value={scheduleForm.cron}
                            onChange={(e) => setScheduleForm({ ...scheduleForm, cron: e.target.value })}
                          />
                        </div>
                        <button
                          onClick={handleCreateSchedule}
                          className="w-full py-4 bg-indigo-600 hover:bg-indigo-500 text-white rounded-2xl font-black text-xs transition-all shadow-xl shadow-indigo-600/20 active:scale-95"
                        >
                          SCHEDULE OPERATION
                        </button>
                      </div>
                    </div>
                  </div>

                  <div className="lg:col-span-2 space-y-4 overflow-y-auto max-h-[600px] pr-2 custom-scrollbar">
                    {schedules.map(s => (
                      <div key={s.id} className="glass-panel p-6 border border-slate-800 hover:border-slate-700 transition-all rounded-3xl group flex justify-between items-center">
                        <div className="flex items-center gap-6">
                          <div className="w-14 h-14 bg-slate-900 rounded-2xl flex items-center justify-center border border-slate-800 group-hover:bg-indigo-500/10 group-hover:border-indigo-500/20 transition-all">
                            <Zap className="text-slate-500 group-hover:text-indigo-400" size={24} />
                          </div>
                          <div>
                            <h4 className="text-lg font-black text-white tracking-tight">{s.target}</h4>
                            <div className="flex items-center gap-4 mt-1">
                              <span className="text-[10px] font-bold text-slate-500 flex items-center gap-1"><Clock size={10} /> {s.cron_expression}</span>
                              <span className="text-[10px] font-black text-indigo-400 uppercase bg-indigo-500/10 px-2 py-0.5 rounded-full">{s.profile}</span>
                            </div>
                          </div>
                        </div>
                        <button
                          onClick={() => handleDeleteSchedule(s.id)}
                          className="p-3 text-slate-600 hover:text-red-500 hover:bg-red-500/10 rounded-xl transition-all"
                        >
                          <Trash2 size={20} />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {viewMode === 'mission' && (
            <div className="flex-1 flex flex-col min-h-0 bg-[#0d0d0d] p-8 no-print">
              <MissionHistory
                missions={missions}
                lang={reportLang}
                onSelect={(m) => loadMissionDetails(m.id)}
                onCompare={(id1, id2) => handleCompareScans(id1, id2)}
              />
            </div>
          )}
        </div>
      </main>

      {/* Barre Latérale Droite - Operations Control */}
      <aside className={`fixed md:relative z-40 w-80 h-[calc(100%-2rem)] border-l ${theme === 'dark' ? 'border-slate-800' : 'border-slate-200'} p-6 flex flex-col gap-6 glass-panel m-4 rounded-3xl shadow-2xl no-print transition-all duration-300`}>
        <div className="space-y-6">
          <div className="flex items-center gap-2 px-2">
            <div className="w-2 h-2 rounded-full bg-blue-500 animate-pulse"></div>
            <label className="text-[10px] font-black uppercase text-slate-500 tracking-[0.3em]">
              Control Center
            </label>
          </div>

          <div className="space-y-4 premium-card p-5 rounded-3xl">
            <div className="relative group">
              <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500 group-focus-within:text-blue-400 transition-colors" size={16} />
              <input
                type="text"
                placeholder="Target IP/Domain"
                className="w-full bg-black/40 border border-white/5 rounded-2xl py-4 pl-12 pr-4 text-xs font-black text-white focus:outline-none focus:border-blue-500/50 transition-all placeholder:text-slate-700"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
              />
            </div>

            <div className="flex gap-2">
              <div className="flex-1 flex gap-1 p-1 bg-black/40 border border-white/5 rounded-xl">
                <button onClick={() => setReportLang('fr')} className={`flex-1 py-2 text-[9px] font-black rounded-lg transition-all ${reportLang === 'fr' ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/20' : 'text-slate-600 hover:text-slate-400'}`}>FR</button>
                <button onClick={() => setReportLang('en')} className={`flex-1 py-2 text-[9px] font-black rounded-lg transition-all ${reportLang === 'en' ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/20' : 'text-slate-600 hover:text-slate-400'}`}>EN</button>
              </div>
            </div>

            {isScanning ? (
              <div className="flex flex-col gap-2">
                <div className="flex gap-2">
                  <button
                    onClick={isScanPaused ? resumeScan : pauseScan}
                    className="flex-1 py-4 bg-slate-800 hover:bg-slate-700 text-white rounded-2xl font-black text-[11px] uppercase tracking-widest flex items-center justify-center gap-2 transition-all"
                  >
                    {isScanPaused ? <Play size={16} className="text-green-400" /> : <Pause size={16} className="text-amber-400" />}
                    {isScanPaused ? (isEn ? 'Resume' : 'Reprendre') : (isEn ? 'Pause' : 'Pause')}
                  </button>
                  <button
                    onClick={stopScan}
                    className="flex-1 py-4 bg-rose-950/40 hover:bg-rose-900/60 border border-rose-500/30 text-rose-400 rounded-2xl font-black text-[11px] uppercase tracking-widest flex items-center justify-center gap-2 transition-all"
                  >
                    <Square size={16} />
                    {isEn ? 'Stop' : 'Arrêter'}
                  </button>
                </div>
                <div className="flex items-center justify-center gap-2 py-2 px-4 bg-indigo-500/10 rounded-xl border border-indigo-500/20">
                  <Activity className="animate-spin text-indigo-400" size={12} />
                  <span className="text-[9px] font-black text-indigo-300 uppercase animate-pulse">
                    {isScanPaused ? (isEn ? 'Scan Paused' : 'Scan en Pause') : (isEn ? 'System Auditing...' : 'Audit Système...')}
                  </span>
                </div>
              </div>
            ) : (
              <button
                onClick={() => lancerScan()}
                className="w-full py-5 bg-gradient-to-br from-blue-600 to-indigo-700 hover:scale-[1.02] active:scale-[0.98] text-white rounded-2xl transition-all flex items-center justify-center gap-3 shadow-2xl group border border-white/5"
              >
                <Zap size={20} className="group-hover:text-amber-400 transition-colors" />
                <span className="font-black text-[11px] uppercase tracking-widest">{isEn ? 'Launch Mission' : 'Lancer Mission'}</span>
              </button>
            )}
          </div>
        </div>

        <div className="flex-1 overflow-y-auto pr-2 custom-scrollbar space-y-8">
          {riskSummary && (
            <div className="space-y-4">
              <div className="flex items-center gap-2 px-2 opacity-50">
                <Activity size={14} className="text-indigo-400" />
                <span className="text-[9px] font-black uppercase tracking-widest text-slate-400">Tactical Impact</span>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <BoiteStat label="Hosts" value={riskSummary.total_hosts} />
                <BoiteStat label="Vulns" value={riskSummary.vulnerable_services} color="text-amber-500" />
                <BoiteStat label="Paths" value={riskSummary.critical_paths} color="text-rose-500" baseline={baselineSummary?.critical_paths} />
                <BoiteStat label="Bounty" value={`$${riskSummary.total_bounty}`} color="text-emerald-400" />
              </div>
            </div>
          )}

          <div className="pt-2">
            <ScanOptionsPanel
              profile={scanProfile}
              customPorts={customPorts}
              timing={scanTiming}
              enableUdp={enableUdp}
              enableShodan={enableShodan}
              enableVirusTotal={enableVirusTotal}
              enableCensys={enableCensys}
              enableAlienVault={enableAlienVault}
              onEnableUdpChange={setEnableUdp}
              onEnableShodanChange={setEnableShodan}
              onEnableVirusTotalChange={setEnableVirusTotal}
              onEnableCensysChange={setEnableCensys}
              onEnableAlienVaultChange={setEnableAlienVault}
              autoExploit={autoExploit}
              onProfileChange={setScanProfile}
              onCustomPortsChange={setCustomPorts}
              onTimingChange={setScanTiming}
              onAutoExploitChange={setAutoExploit}
              lang={reportLang}
            />
          </div>
        </div>

        <div className="mt-auto pt-4 border-t border-slate-800/60 flex gap-2">
          <button onClick={() => setShowSettings(true)} className="flex-1 flex items-center justify-center p-3 bg-white/5 border border-white/5 rounded-xl text-slate-500 hover:text-white transition-all">
            <Settings size={18} />
          </button>
          <button onClick={reinitialiserAudit} className="flex-1 flex items-center justify-center p-3 bg-white/5 border border-white/5 rounded-xl text-slate-500 hover:text-rose-400 transition-all">
            <Trash2 size={18} />
          </button>
        </div>
      </aside>

      {/* Detail Panel */}
      {selectedNode && (
        <aside className="absolute right-0 top-0 w-96 h-full border-l border-slate-800 p-6 flex flex-col gap-6 glass-panel backdrop-blur-3xl shadow-2xl overflow-y-auto no-print z-30 animate-slide-in">
          <div className="flex justify-between items-start">
            <h2 className="text-lg font-bold gradient-text">{selectedNode.label}</h2>
            <button onClick={() => setSelectedNode(null)} className="text-slate-500 hover:text-white transition-colors">
              <X size={20} />
            </button>
          </div>
          <div className="space-y-6">
            {selectedNode.properties.ai_insight && (
              <div className="p-4 bg-indigo-950/20 border border-indigo-500/30 rounded-2xl relative overflow-hidden group">
                <label className="text-[10px] font-bold uppercase text-indigo-400 tracking-widest block mb-2">Expert IA - Analyse de Risque</label>
                <p className="text-xs text-indigo-200 leading-relaxed italic">"{selectedNode.properties.ai_insight}"</p>
              </div>
            )}
            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-2">
              {Object.entries(selectedNode.properties || {}).map(([key, value]: [string, any]) => (
                <div key={key} className="space-y-1">
                  <span className="text-[9px] text-indigo-400 uppercase font-bold">{key}</span>
                  <p className="text-xs text-slate-300 font-mono break-all">{value}</p>
                </div>
              ))}
            </div>
            <div className="flex flex-col gap-2">
              <button
                onClick={() => basculerPatch(selectedNode.id, selectedNode.label)}
                className={`w-full py-2 px-4 rounded-lg text-xs font-bold transition-all flex items-center justify-center gap-2 ${patches.includes(selectedNode.id) ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/30' : 'bg-slate-700 hover:bg-slate-600 text-slate-300'}`}
              >
                {patches.includes(selectedNode.id) ? <ShieldCheck size={14} /> : <Wrench size={14} />}
                {patches.includes(selectedNode.id) ? (reportLang === 'en' ? 'Pitched / Secured' : 'Patché / Sécurisé') : (reportLang === 'en' ? 'Apply Security Patch' : 'Appliquer un Correctif')}
              </button>
            </div>
          </div>
        </aside>
      )}

      {/* Floating Chat Engine */}
      {
        !chatOpen && (
          <button
            onClick={() => setChatOpen(true)}
            className="fixed bottom-8 right-8 w-16 h-16 bg-indigo-600 hover:bg-indigo-500 text-white rounded-full shadow-2xl shadow-indigo-600/40 flex items-center justify-center transition-all hover:scale-110 z-50 no-print"
          >
            <MessageSquare size={28} />
            {chatMessages.length > 0 && <span className="absolute -top-1 -right-1 w-5 h-5 bg-red-500 rounded-full text-[10px] font-bold flex items-center justify-center">{chatMessages.length}</span>}
          </button>
        )
      }

      {
        chatOpen && (
          <div className="fixed top-0 right-0 w-96 h-screen bg-[#0d0d0d] border-l border-slate-800 shadow-2xl z-[100] flex flex-col animate-slide-in no-print">
            <div className="p-6 border-b border-slate-800 flex justify-between items-center bg-indigo-600/5">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-indigo-500/20 rounded-lg text-indigo-400">
                  <Terminal size={20} />
                </div>
                <h3 className="text-sm font-black text-white uppercase tracking-tighter">Offensive AI</h3>
              </div>
              <button onClick={() => setChatOpen(false)} className="text-slate-500 hover:text-white transition-colors">
                <X size={20} />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto p-6 space-y-4 custom-scrollbar">
              {chatMessages.map((msg, idx) => (
                <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                  <div className={`max-w-[85%] p-4 rounded-2xl text-xs leading-relaxed ${msg.role === 'user' ? 'bg-indigo-600 text-white rounded-tr-none' : 'bg-slate-900 border border-slate-800 text-slate-300 rounded-tl-none'}`}>
                    {msg.content}
                  </div>
                </div>
              ))}
            </div>
            <div className="p-6 border-t border-slate-800">
              <div className="relative">
                <input
                  type="text"
                  placeholder={reportLang === 'en' ? 'Type your command...' : 'Tapez votre commande...'}
                  className="w-full bg-slate-900 border border-slate-800 rounded-xl py-4 pl-4 pr-14 text-xs text-white outline-none focus:ring-2 focus:ring-indigo-500 transition-all font-mono"
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && envoyerMessage()}
                />
                <button onClick={envoyerMessage} className="absolute right-2 top-1/2 -translate-y-1/2 p-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg transition-all">
                  <Send size={18} />
                </button>
              </div>
            </div>
          </div>
        )
      }
    </div >
  );
}

function BoiteStat({ label, value, color = "text-indigo-400", baseline }: any) {
  const reduction = baseline !== undefined && baseline > value;
  return (
    <div className="premium-card p-4 rounded-2xl flex flex-col items-center justify-center text-center gap-1 group">
      <span className="text-[9px] text-slate-500 uppercase font-black tracking-widest group-hover:text-slate-400 transition-colors">{label}</span>
      <div className="flex items-center gap-2">
        <span className={`text-2xl font-black tracking-tighter ${color}`}>{value}</span>
        {reduction && (
          <div className="flex items-center text-green-500 font-black text-[10px] animate-pulse">
            <Plus size={10} className="rotate-45" /> {baseline - value}
          </div>
        )}
      </div>
    </div>
  );
}
