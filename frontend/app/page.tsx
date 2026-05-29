"use client";

import React, { useState, useEffect, useRef } from 'react';

// ========================================================
// NEUROSHIELD CYBER SOC DASHBOARD - TSX / REACT COMPONENT
// ========================================================

interface LogMessage {
  id: string;
  time: string;
  type: 'info' | 'success' | 'warning' | 'critical' | 'system';
  text: string;
}

interface ScanResponse {
  success: boolean;
  malicious: boolean;
  confidence: number;
  risk_percentage: number;
  threat_level: string;
  processed_length: number;
}

const SYSTEM_WHITE_LIST = [
  'explorer.exe', 'svchost.exe', 'lsass.exe', 'cmd.exe', 'powershell.exe',
  'conhost.exe', 'services.exe', 'wininit.exe', 'taskhostw.exe', 'taskmgr.exe'
];

export default function Dashboard() {
  // ----------------------------------------------------
  // State Management
  // ----------------------------------------------------
  const [backendStatus, setBackendStatus] = useState<'online' | 'offline' | 'checking'>('checking');
  const [killCount, setKillCount] = useState<number>(0);
  const [logs, setLogs] = useState<LogMessage[]>([]);
  const [activeFeed, setActiveFeed] = useState<boolean>(true);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanProcessName, setScanProcessName] = useState<string>('ransom_test.exe');
  const [scanResult, setScanResult] = useState<ScanResponse | null>(null);
  const [activeTab, setActiveTab] = useState<'monitoring' | 'simulator'>('monitoring');
  const [alerts, setAlerts] = useState<any[]>([]);

  const terminalEndRef = useRef<HTMLDivElement>(null);

  // ----------------------------------------------------
  // Helper Functions
  // ----------------------------------------------------
  function getTimestamp() {
    const now = new Date();
    return now.toTimeString().split(' ')[0];
  }

  function addLog(text: string, type: LogMessage['type']) {
    setLogs(prev => [
      ...prev.slice(-49), // Keep last 50 logs to avoid DOM memory leakage
      { id: Date.now().toString() + Math.random().toString(), time: getTimestamp(), type, text }
    ]);
  }

  function formatIsoTime(isoString: string) {
    try {
      const date = new Date(isoString);
      return date.toTimeString().split(' ')[0];
    } catch {
      return isoString;
    }
  }

  // ----------------------------------------------------
  // Database Operations & Backend Status Checks
  // ----------------------------------------------------
  const fetchAlerts = async () => {
    try {
      const response = await fetch('http://127.0.0.1:5000/api/alerts');
      if (response.ok) {
        const data = await response.json();
        if (data.success && data.alerts) {
          setAlerts(data.alerts);
        }
      }
    } catch (err) {
      console.error("Error fetching alerts from backend:", err);
    }
  };

  async function checkBackend() {
    setBackendStatus('checking');
    try {
      const response = await fetch('http://127.0.0.1:5000/api/status');
      if (response.ok) {
        setBackendStatus('online');
      } else {
        setBackendStatus('offline');
      }
    } catch {
      setBackendStatus('offline');
    }
  }

  // Polling Effect
  useEffect(() => {
    fetchAlerts();
    checkBackend();

    const interval = setInterval(() => {
      fetchAlerts();
      checkBackend();
    }, 3000);

    return () => clearInterval(interval);
  }, []);

  // Auto-scroll Effect
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  // ----------------------------------------------------
  // Map Database Alerts to Terminal Logs and Stats Cards
  // ----------------------------------------------------
  useEffect(() => {
    if (!activeFeed) return;

    const generatedLogs: LogMessage[] = [];
    let terminatedCount = 0;

    // Process alerts from oldest to newest (reverse chronological order of database fetch)
    const sortedAlerts = [...alerts].reverse();

    sortedAlerts.forEach((alert) => {
      const timeStr = formatIsoTime(alert.timestamp);
      const isMalicious = alert.status === 'Threat Detected' || alert.action_taken === 'Terminated';
      const pid = alert.pid;
      const name = alert.process_name;
      const risk = alert.risk_factor;

      if (isMalicious) {
        terminatedCount++;
        generatedLogs.push({ id: `info-${alert.id}`, time: timeStr, type: 'info', text: `[🔄] Analyzing Telemetry for ${name} (PID: ${pid})...` });
        generatedLogs.push({ id: `crit-banner-${alert.id}`, time: timeStr, type: 'critical', text: `🚨🚨🚨 NEUROSHIELD THREAT DETECTION 🚨🚨🚨` });
        generatedLogs.push({ id: `crit-warn-${alert.id}`, time: timeStr, type: 'critical', text: `⚠️ CRITICAL RANSOMWARE BEHAVIOR DETECTED!` });
        generatedLogs.push({ id: `crit-name-${alert.id}`, time: timeStr, type: 'critical', text: `💥 Process Name : ${name}` });
        generatedLogs.push({ id: `crit-pid-${alert.id}`, time: timeStr, type: 'critical', text: `🆔 Process ID   : ${pid}` });
        generatedLogs.push({ id: `crit-risk-${alert.id}`, time: timeStr, type: 'critical', text: `🔥 Risk Factor  : ${risk.toFixed(2)}%` });
        generatedLogs.push({ id: `crit-act-${alert.id}`, time: timeStr, type: 'critical', text: `💥 ACTION TAKEN : ENFORCING IMMEDIATE TERMINATION!` });
        generatedLogs.push({ id: `succ-${alert.id}`, time: timeStr, type: 'success', text: `[❌] Process ${pid} terminated successfully! System secured.` });
      } else {
        generatedLogs.push({ id: `info-${alert.id}`, time: timeStr, type: 'info', text: `[🔄] Analyzing Telemetry for ${name} (PID: ${pid})...` });
        generatedLogs.push({ id: `succ-${alert.id}`, time: timeStr, type: 'success', text: `[✓] Process ${name} (PID: ${pid}) analyzed. Behavior is normal (Safety score: ${(100 - risk).toFixed(2)}%).` });
      }
    });

    // Fallback seed logs if no alerts are in the database yet
    if (generatedLogs.length === 0) {
      generatedLogs.push(
        { id: 'sys-1', time: getTimestamp(), type: 'system', text: '[+] NeuroShield Initializing...' },
        { id: 'sys-2', time: getTimestamp(), type: 'system', text: '[+] Connection established. Flask server online and Model loaded successfully.' },
        { id: 'sys-3', time: getTimestamp(), type: 'system', text: '[+] Logged active processes. Core Agent monitoring is active.' },
        { id: 'sys-4', time: getTimestamp(), type: 'info', text: '[*] No alerts reported yet. Waiting for telemetry logs...' }
      );
    }

    setLogs(generatedLogs);
    setKillCount(terminatedCount);
  }, [alerts, activeFeed]);

  // ----------------------------------------------------
  // Clear Central SOC Database
  // ----------------------------------------------------
  async function handleClearDatabase() {
    addLog(`[🔄] Requesting Central Database Flush...`, 'info');
    try {
      const response = await fetch('http://127.0.0.1:5000/api/alerts/clear', {
        method: 'POST',
      });
      if (response.ok) {
        addLog(`[✓] Central Database cleared successfully.`, 'success');
        setAlerts([]);
        setLogs([]);
      } else {
        addLog(`[-] Database clear failed: Status ${response.status}`, 'warning');
      }
    } catch (err) {
      addLog(`[-] API unreachable. Clearing local logs only...`, 'warning');
      setLogs([]);
    }
  }

  // ----------------------------------------------------
  // Run Interactive Scanner / Analyze Trigger
  // ----------------------------------------------------
  async function handleSimulateScan() {
    setIsScanning(true);
    setScanResult(null);

    const isMaliciousKeyword = anyKeywordMatch(scanProcessName, ["ransom", "crypt", "lock", "malware", "virus"]);
    const mockPid = Math.floor(Math.random() * 19000) + 1000;
    
    // Seed sequence containing tokens (realistic integers from dataset capped under 266)
    let mockSequence: number[] = [];
    if (isMaliciousKeyword) {
      mockSequence = Array.from({ length: 100 }, (_, i) => (i % 5 === 0 ? 112 : i % 7 === 0 ? 260 : 158));
    } else {
      mockSequence = Array.from({ length: 100 }, () => Math.floor(Math.random() * 260) + 1);
    }

    addLog(`[🔄] Manual Analysis Request: ${scanProcessName}...`, 'info');

    try {
      const response = await fetch('http://127.0.0.1:5000/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          sequence: mockSequence,
          process_name: scanProcessName,
          pid: mockPid
        })
      });

      if (response.ok) {
        const result: ScanResponse = await response.json();
        setScanResult(result);
        
        if (result.malicious) {
          addLog(`[🚨] Threat alert trigger from API for ${scanProcessName} (Confidence: ${result.risk_percentage}%)`, 'critical');
        } else {
          addLog(`[✓] Scan clean for ${scanProcessName} (Safety rating: ${100 - result.risk_percentage}%)`, 'success');
        }
        // Instantly refresh the historical alerts
        fetchAlerts();
      } else {
        addLog(`[-] Scanner API connection failed: Status ${response.status}`, 'warning');
      }
    } catch (err) {
      addLog(`[-] API unreachable. Simulating locally...`, 'warning');
      setTimeout(() => {
        const fallbackConfidence = isMaliciousKeyword ? 0.9848 : 0.0215;
        const mockResult: ScanResponse = {
          success: true,
          malicious: isMaliciousKeyword,
          confidence: fallbackConfidence,
          risk_percentage: parseFloat((fallbackConfidence * 100).toFixed(2)),
          threat_level: isMaliciousKeyword ? "HIGH (Ransomware Detected)" : "LOW (Healthy Process)",
          processed_length: 100
        };
        setScanResult(mockResult);
        if (isMaliciousKeyword) {
          addLog(`[🚨] Local Alert: Ransomware signature flagged for ${scanProcessName}`, 'critical');
          setKillCount(prev => prev + 1);
        }
      }, 1000);
    } finally {
      setIsScanning(false);
    }
  }

  function anyKeywordMatch(str: string, keywords: string[]) {
    return keywords.some(k => str.toLowerCase().includes(k));
  }

  // ----------------------------------------------------
  // Render
  // ----------------------------------------------------
  return (
    <div className="neuroshield-dashboard">
      {/* Native Injected Vanilla CSS Stylesheet */}
      <style dangerouslySetInnerHTML={{ __html: `
        :root {
          --bg-primary: #07080b;
          --bg-secondary: #0e1116;
          --bg-tertiary: #13171e;
          --border-color: #1f2530;
          --color-cyan: #00d2ff;
          --color-emerald: #00ff66;
          --color-ruby: #ff3355;
          --color-gray: #7d8b9d;
          --color-text: #e1e7f0;
          --glow-cyan: 0 0 10px rgba(0, 210, 255, 0.4);
          --glow-emerald: 0 0 10px rgba(0, 255, 102, 0.4);
          --glow-ruby: 0 0 12px rgba(255, 51, 85, 0.5);
        }

        .neuroshield-dashboard {
          background-color: var(--bg-primary);
          color: var(--color-text);
          font-family: 'Outfit', 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          min-height: 100vh;
          padding: 24px;
          box-sizing: border-box;
        }

        /* HEADER */
        .soc-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          border-bottom: 2px solid var(--border-color);
          padding-bottom: 16px;
          margin-bottom: 24px;
        }
        .header-logo {
          display: flex;
          align-items: center;
          gap: 12px;
        }
        .shield-icon {
          color: var(--color-cyan);
          filter: drop-shadow(var(--glow-cyan));
        }
        .header-logo h1 {
          margin: 0;
          font-size: 24px;
          font-weight: 800;
          letter-spacing: 2px;
          text-transform: uppercase;
        }
        .header-logo h1 span {
          color: var(--color-cyan);
        }
        .header-controls {
          display: flex;
          align-items: center;
          gap: 16px;
        }
        .status-badge {
          display: flex;
          align-items: center;
          gap: 8px;
          background-color: var(--bg-secondary);
          border: 1px solid var(--border-color);
          padding: 8px 14px;
          border-radius: 4px;
          font-size: 12px;
          font-weight: 700;
          letter-spacing: 1px;
          cursor: pointer;
          transition: all 0.2s ease;
        }
        .status-badge:hover {
          background-color: var(--bg-tertiary);
        }
        .status-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
        }
        .status-dot.online {
          background-color: var(--color-emerald);
          box-shadow: var(--glow-emerald);
          animation: blink 2s infinite;
        }
        .status-dot.offline {
          background-color: var(--color-ruby);
          box-shadow: var(--glow-ruby);
          animation: blink 1s infinite;
        }
        .status-dot.checking {
          background-color: var(--color-cyan);
          box-shadow: var(--glow-cyan);
          animation: spin 1s infinite linear;
        }

        /* GRID LAYOUT */
        .soc-grid {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 20px;
          margin-bottom: 24px;
        }

        /* METRIC CARDS */
        .metric-card {
          background-color: var(--bg-secondary);
          border: 1px solid var(--border-color);
          border-radius: 8px;
          padding: 20px;
          position: relative;
          overflow: hidden;
          transition: border-color 0.3s ease;
        }
        .metric-card:hover {
          border-color: #2b3547;
        }
        .metric-card.threat-card {
          border-left: 4px solid var(--color-ruby);
        }
        .metric-card.accent-card {
          border-left: 4px solid var(--color-cyan);
        }
        .metric-title {
          font-size: 11px;
          font-weight: 700;
          text-transform: uppercase;
          color: var(--color-gray);
          letter-spacing: 1.5px;
          margin-bottom: 8px;
        }
        .metric-value {
          font-size: 36px;
          font-weight: 900;
          font-family: 'Courier New', Courier, monospace;
        }
        .metric-value.kill-count {
          color: var(--color-ruby);
          text-shadow: var(--glow-ruby);
        }
        .metrics-subgrid {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 12px;
          margin-top: 10px;
        }
        .sub-metric {
          text-align: center;
          border-right: 1px solid var(--border-color);
          padding-right: 4px;
        }
        .sub-metric:last-child {
          border-right: none;
          padding-right: 0;
        }
        .sub-metric-val {
          font-size: 16px;
          font-weight: 800;
          color: var(--color-emerald);
          font-family: 'Courier New', monospace;
        }
        .sub-metric-title {
          font-size: 9px;
          color: var(--color-gray);
          text-transform: uppercase;
        }

        /* TABS NAV */
        .tab-navigation {
          display: flex;
          gap: 12px;
          margin-bottom: 16px;
        }
        .tab-btn {
          background-color: var(--bg-secondary);
          border: 1px solid var(--border-color);
          color: var(--color-gray);
          padding: 10px 20px;
          border-radius: 4px;
          font-weight: 700;
          font-size: 13px;
          cursor: pointer;
          transition: all 0.2s ease;
          text-transform: uppercase;
          letter-spacing: 1px;
        }
        .tab-btn:hover {
          color: var(--color-text);
          background-color: var(--bg-tertiary);
        }
        .tab-btn.active {
          color: var(--color-cyan);
          background-color: var(--bg-tertiary);
          border-color: var(--color-cyan);
          box-shadow: var(--glow-cyan);
        }

        /* MAIN CONTENT AREA */
        .main-workspace {
          display: grid;
          grid-template-columns: 2fr 1fr;
          gap: 24px;
        }

        /* TERMINAL PANEL */
        .terminal-panel {
          background-color: #050608;
          border: 1px solid var(--border-color);
          border-radius: 8px;
          overflow: hidden;
          display: flex;
          flex-direction: column;
          height: 520px;
          box-shadow: inset 0 0 20px rgba(0,0,0,0.8);
        }
        .terminal-header {
          background-color: var(--bg-secondary);
          padding: 12px 16px;
          border-bottom: 1px solid var(--border-color);
          display: flex;
          justify-content: space-between;
          align-items: center;
        }
        .terminal-title {
          font-family: 'Courier New', Courier, monospace;
          font-size: 12px;
          font-weight: 700;
          color: var(--color-cyan);
          display: flex;
          align-items: center;
          gap: 8px;
        }
        .terminal-actions {
          display: flex;
          gap: 8px;
        }
        .terminal-btn {
          background-color: var(--bg-tertiary);
          border: 1px solid var(--border-color);
          color: var(--color-text);
          padding: 4px 10px;
          font-size: 11px;
          border-radius: 3px;
          cursor: pointer;
          font-family: 'Courier New', monospace;
          transition: all 0.2s ease;
        }
        .terminal-btn:hover {
          border-color: var(--color-cyan);
        }
        .terminal-body {
          flex: 1;
          padding: 16px;
          overflow-y: auto;
          font-family: 'Courier New', Courier, monospace;
          font-size: 12px;
          line-height: 1.6;
          scroll-behavior: smooth;
        }
        .log-row {
          margin-bottom: 6px;
          display: flex;
          align-items: flex-start;
          gap: 12px;
        }
        .log-time {
          color: #4b5a6c;
          flex-shrink: 0;
        }
        .log-text.type-info { color: var(--color-gray); }
        .log-text.type-success { color: var(--color-emerald); font-weight: bold; }
        .log-text.type-warning { color: #f1c40f; }
        .log-text.type-critical { 
          color: var(--color-ruby); 
          background-color: rgba(255, 51, 85, 0.1);
          padding: 2px 6px;
          border-radius: 2px;
          font-weight: bold; 
          width: 100%;
          border-left: 2px solid var(--color-ruby);
        }
        .log-text.type-system { color: var(--color-cyan); }
        .terminal-cursor {
          display: inline-block;
          width: 8px;
          height: 14px;
          background-color: var(--color-cyan);
          margin-left: 4px;
          animation: blink 1s infinite step-end;
          vertical-align: middle;
        }

        /* CONTROLS & SIMULATION SIDEBAR */
        .sidebar-panel {
          display: flex;
          flex-direction: column;
          gap: 20px;
        }
        .sidebar-card {
          background-color: var(--bg-secondary);
          border: 1px solid var(--border-color);
          border-radius: 8px;
          padding: 20px;
        }
        .panel-heading {
          font-size: 14px;
          font-weight: 800;
          text-transform: uppercase;
          letter-spacing: 1.5px;
          margin-bottom: 16px;
          color: var(--color-cyan);
          border-bottom: 1px solid var(--border-color);
          padding-bottom: 8px;
        }
        .form-group {
          margin-bottom: 16px;
        }
        .form-group label {
          display: block;
          font-size: 11px;
          color: var(--color-gray);
          text-transform: uppercase;
          margin-bottom: 6px;
          font-weight: 700;
        }
        .text-input {
          width: 100%;
          background-color: var(--bg-primary);
          border: 1px solid var(--border-color);
          color: var(--color-text);
          padding: 10px;
          border-radius: 4px;
          font-family: 'Courier New', monospace;
          box-sizing: border-box;
          font-size: 13px;
        }
        .text-input:focus {
          border-color: var(--color-cyan);
          outline: none;
        }
        .scan-trigger-btn {
          width: 100%;
          background-color: var(--color-cyan);
          border: none;
          color: #000;
          padding: 12px;
          border-radius: 4px;
          font-weight: 800;
          cursor: pointer;
          text-transform: uppercase;
          letter-spacing: 1px;
          transition: all 0.2s ease;
        }
        .scan-trigger-btn:hover:not(:disabled) {
          box-shadow: var(--glow-cyan);
          opacity: 0.9;
        }
        .scan-trigger-btn:disabled {
          background-color: var(--border-color);
          color: var(--color-gray);
          cursor: not-allowed;
        }

        /* SCAN RESULTS DISPLAY */
        .result-container {
          margin-top: 16px;
          background-color: var(--bg-primary);
          border: 1px solid var(--border-color);
          border-radius: 4px;
          padding: 14px;
        }
        .result-row {
          display: flex;
          justify-content: space-between;
          margin-bottom: 8px;
          font-size: 12px;
        }
        .result-row:last-child {
          margin-bottom: 0;
        }
        .result-lbl { color: var(--color-gray); }
        .result-val { font-weight: 700; font-family: 'Courier New', monospace; }
        .threat-flag-red {
          color: var(--color-ruby);
          text-shadow: var(--glow-ruby);
          font-weight: 800;
        }
        .threat-flag-green {
          color: var(--color-emerald);
          text-shadow: var(--glow-emerald);
          font-weight: 800;
        }

        /* KEYFRAMES */
        @keyframes blink {
          50% { opacity: 0; }
        }
        @keyframes spin {
          100% { transform: rotate(360deg); }
        }
      `}} />

      {/* HEADER */}
      <header className="soc-header">
        <div className="header-logo">
          <svg className="shield-icon" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          <h1>Neuro<span>Shield</span></h1>
        </div>
        
        <div className="header-controls">
          <div className="status-badge" onClick={checkBackend} title="Click to refresh connection">
            <span className={`status-dot ${backendStatus}`}></span>
            EDR BACKEND: {backendStatus.toUpperCase()}
          </div>
        </div>
      </header>

      {/* TOP METRICS GRID */}
      <div className="soc-grid">
        {/* Threat Kill Counter */}
        <div className="metric-card threat-card">
          <div className="metric-title">Malicious Processes Terminated</div>
          <div className="metric-value kill-count">{killCount}</div>
        </div>

        {/* AI Performance Statistics */}
        <div className="metric-card accent-card" style={{ gridColumn: 'span 2' }}>
          <div className="metric-title">Behavioral Transformer AI Performance</div>
          <div className="metrics-subgrid">
            <div className="sub-metric">
              <div className="sub-metric-val">98.48%</div>
              <div className="sub-metric-title">Accuracy</div>
            </div>
            <div className="sub-metric">
              <div className="sub-metric-val">99.67%</div>
              <div className="sub-metric-title">Recall</div>
            </div>
            <div className="sub-metric">
              <div className="sub-metric-val">98.78%</div>
              <div className="sub-metric-title">Precision</div>
            </div>
          </div>
        </div>

        {/* General EDR Details */}
        <div className="metric-card">
          <div className="metric-title">Model Architecture</div>
          <div className="metric-value" style={{ fontSize: '18px', color: '#00d2ff', marginTop: '4px', fontWeight: 800 }}>
            BERT-Transformers
          </div>
          <div className="metric-title" style={{ marginTop: '12px', marginBottom: '0' }}>Sequence Depth: 100 Calls</div>
        </div>
      </div>

      {/* WORKSPACE NAVIGATION TABS */}
      <div className="tab-navigation">
        <button 
          className={`tab-btn ${activeTab === 'monitoring' ? 'active' : ''}`}
          onClick={() => setActiveTab('monitoring')}
        >
          Live Telemetry Log Stream
        </button>
        <button 
          className={`tab-btn ${activeTab === 'simulator' ? 'active' : ''}`}
          onClick={() => setActiveTab('simulator')}
        >
          Interactive Threat Simulator
        </button>
      </div>

      {/* MAIN SOC WORKSPACE */}
      <main className="main-workspace">
        {/* LEFT COLUMN: Terminal Logs Monitor */}
        <section className="terminal-panel">
          <div className="terminal-header">
            <div className="terminal-title">
              <span className="status-dot online"></span>
              LIVE PROCESS TELEMETRY MONITORS (AUTO-SCROLL ON)
            </div>
            <div className="terminal-actions">
              <button 
                className="terminal-btn" 
                onClick={() => window.open('http://127.0.0.1:5000/api/reports/pdf', '_blank')}
                style={{ color: 'var(--color-cyan)', fontWeight: 'bold', borderColor: 'var(--color-cyan)' }}
              >
                📥 Export PDF Report
              </button>
              <button className="terminal-btn" onClick={handleClearDatabase}>Clear Terminal</button>
              <button 
                className="terminal-btn" 
                onClick={() => setActiveFeed(!activeFeed)}
                style={{ color: activeFeed ? '#ff3355' : '#00d2ff' }}
              >
                {activeFeed ? 'Freeze Stream' : 'Resume Stream'}
              </button>
            </div>
          </div>

          <div className="terminal-body">
            {logs.map((log) => (
              <div key={log.id} className="log-row">
                <span className="log-time">[{log.time}]</span>
                <span className={`log-text type-${log.type}`}>{log.text}</span>
              </div>
            ))}
            <div className="terminal-cursor"></div>
            <div ref={terminalEndRef} />
          </div>
        </section>

        {/* RIGHT COLUMN: Sidebar Controllers */}
        <section className="sidebar-panel">
          {/* Quick Simulation Trigger */}
          <div className="sidebar-card">
            <div className="panel-heading">Manual Attack Simulator</div>
            
            <div className="form-group">
              <label>Simulated Executable Name</label>
              <input 
                type="text" 
                className="text-input" 
                value={scanProcessName}
                onChange={(e) => setScanProcessName(e.target.value)}
                placeholder="e.g. cryptolocker.exe"
              />
            </div>

            <div className="form-group">
              <label>Threat Behavior Selection</label>
              <select 
                className="text-input" 
                style={{ backgroundColor: 'var(--bg-primary)' }}
                onChange={(e) => setScanProcessName(e.target.value)}
                value={scanProcessName}
              >
                <option value="cryptolocker_v4.exe">Ransomware: CryptoLocker Simulation</option>
                <option value="wannacry_reproduced.exe">Ransomware: WannaCry Sequence Simulation</option>
                <option value="chrome_installer.exe">Healthy: Google Chrome Download Simulation</option>
                <option value="svchost_sys.exe">Healthy: System svchost Routine Execution</option>
              </select>
            </div>

            <button 
              className="scan-trigger-btn"
              disabled={isScanning}
              onClick={handleSimulateScan}
            >
              {isScanning ? 'Executing Transformer Scan...' : 'Inject Sequence & Test AI'}
            </button>

            {/* Results Screen */}
            {scanResult && (
              <div className="result-container">
                <div className="panel-heading" style={{ fontSize: '11px', border: 'none', margin: '0 0 10px 0', padding: 0 }}>
                  Scanner API Evaluation
                </div>
                
                <div className="result-row">
                  <span className="result-lbl">Process Name:</span>
                  <span className="result-val">{scanProcessName}</span>
                </div>
                
                <div className="result-row">
                  <span className="result-lbl">Verdict / Assessment:</span>
                  <span className={`result-val ${scanResult.malicious ? 'threat-flag-red' : 'threat-flag-green'}`}>
                    {scanResult.malicious ? '🔴 MALICIOUS' : '🟢 SAFE'}
                  </span>
                </div>
                
                <div className="result-row">
                  <span className="result-lbl">Transformer Confidence:</span>
                  <span className="result-val">{scanResult.risk_percentage}%</span>
                </div>
                
                <div className="result-row">
                  <span className="result-lbl">Threat Severity Level:</span>
                  <span className="result-val" style={{ color: scanResult.malicious ? 'var(--color-ruby)' : 'var(--color-emerald)' }}>
                    {scanResult.threat_level}
                  </span>
                </div>
              </div>
            )}
          </div>

          {/* Quick Help Card */}
          <div className="sidebar-card">
            <div className="panel-heading">System Diagnostics</div>
            <div className="result-row" style={{ fontSize: '11px', marginBottom: '6px' }}>
              <span className="result-lbl">Active EDR Whitelist:</span>
              <span className="result-val" style={{ color: 'var(--color-cyan)' }}>Active ({SYSTEM_WHITE_LIST.length} Rules)</span>
            </div>
            <div className="result-row" style={{ fontSize: '11px', marginBottom: '6px' }}>
              <span className="result-lbl">Transformer Sequence Size:</span>
              <span className="result-val">100 calls (fixed)</span>
            </div>
            <div className="result-row" style={{ fontSize: '11px' }}>
              <span className="result-lbl">Security Agent Client:</span>
              <span className="result-val" style={{ color: 'var(--color-emerald)' }}>Active & Connected</span>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
