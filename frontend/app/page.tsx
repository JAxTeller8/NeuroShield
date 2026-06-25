"use client";

import React, { useState, useEffect, useRef } from 'react';
import { createClient } from '@supabase/supabase-js';
import { AdvancedThreatSimulator, AttackConfig } from './AdvancedThreatSimulator';

const supabaseUrl = "https://irtopfmptbwhrbkmezuw.supabase.co";
const supabaseAnonKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImlydG9wZm1wdGJ3aHJia21lenV3Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODIwNDk4NDEsImV4cCI6MjA5NzYyNTg0MX0.WpXrSO9-UZlZlqO1tkTm65_ZAusLwx4TZZslZrxiX8k";
const supabase = createClient(supabaseUrl, supabaseAnonKey);


const BACKEND_URL = "https://neuroshield-sx07.onrender.com";

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
      const { data, error } = await supabase
        .from('neuroshield_alerts')
        .select('*')
        .order('timestamp', { ascending: false });

      if (error) throw error;
      if (data) {
        setAlerts(data);
      }
    } catch (err) {
      console.error("Error fetching alerts from Supabase:", err);
    }
  };

  async function checkBackend() {
    setBackendStatus('checking');
    try {
      const { error } = await supabase
        .from('neuroshield_alerts')
        .select('id')
        .limit(1);

      if (error) throw error;
      setBackendStatus('online');
    } catch {
      // Fallback: Check Render backend status if Supabase client check fails
      try {
        const response = await fetch(`${BACKEND_URL}/api/status`);
        if (response.ok) {
          setBackendStatus('online');
        } else {
          setBackendStatus('offline');
        }
      } catch {
        setBackendStatus('offline');
      }
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

  const lastAlertRef = useRef<{ pid: number; time: string } | null>(null);

  // Real-time EDR Agent Polling Alert Effect
  useEffect(() => {
    const fetchLatestTelemetry = async () => {
      try {
        const response = await fetch(`${BACKEND_URL}/api/latest-alert`);
        if (!response.ok) return;

        const data = await response.json();

        if (data && data.process_name) {
          const alertKey = `${data.pid}-${data.timestamp}`;
          if (lastAlertRef.current && lastAlertRef.current.pid === data.pid && lastAlertRef.current.time === data.timestamp) {
            return;
          }
          lastAlertRef.current = { pid: data.pid, time: data.timestamp };

          // 1. Update scanning states to light up Cognitive Threat Mapper
          setScanResult({
            success: true,
            malicious: data.malicious,
            confidence: data.confidence,
            risk_percentage: data.confidence,
            threat_level: data.malicious ? "HIGH (Ransomware Detected)" : "LOW (Healthy Process)",
            processed_length: 100
          });
          setScanProcessName(data.process_name);

          // 2. Append critical log banner dynamically
          const timestamp = new Date().toTimeString().split(' ')[0];
          const newLogText = data.malicious 
            ? `🚨 CRITICAL THREAT: ${data.process_name} (PID: ${data.pid}) evaluated as MALICIOUS!`
            : `🟢 CLEAN PROCESS: ${data.process_name} (PID: ${data.pid}) evaluated as SAFE.`;

          setLogs((prevLogs) => {
            if (prevLogs.some(l => l.text === newLogText)) return prevLogs;
            
            const newLogMsg: LogMessage = {
              id: `latest-alert-${data.pid}-${Date.now()}`,
              time: timestamp,
              type: data.malicious ? 'critical' : 'success',
              text: newLogText
            };
            return [...prevLogs.slice(-49), newLogMsg];
          });
        }
      } catch (error) {
        console.error("Error fetching telemetry polling:", error);
      }
    };

    const interval = setInterval(fetchLatestTelemetry, 2000);
    return () => clearInterval(interval);
  }, []);

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
      const response = await fetch(`${BACKEND_URL}/api/alerts/clear`, {
        method: 'POST',
      });
      if (response.ok) {
        addLog(`[✓] Central Database cleared successfully.`, 'success');
        setAlerts([]);
        setLogs([]);
        return;
      }
    } catch (err) {
      console.warn("Backend clear failed, falling back to direct Supabase clear:", err);
    }

    try {
      const { error } = await supabase.from('neuroshield_alerts').delete().neq('id', 0);
      if (error) throw error;
      addLog(`[✓] Supabase database cleared directly.`, 'success');
      setAlerts([]);
      setLogs([]);
    } catch (err) {
      addLog(`[-] Database clear failed: ${err.message}`, 'warning');
    }
  }

  // ----------------------------------------------------
  // Run Interactive Scanner / Analyze Trigger
  // ----------------------------------------------------
  async function handleSimulateScan(config: AttackConfig) {
    setIsScanning(true);
    setScanResult(null);
    setScanProcessName(config.executableName);

    const isMalicious = !config.threatType.toLowerCase().includes('safe');
    const mockPid = Math.floor(Math.random() * 19000) + 1000;

    // Seed sequence containing tokens (realistic integers from dataset capped under 266)
    let mockSequence: number[] = [];
    if (isMalicious) {
      mockSequence = Array.from({ length: 100 }, (_, i) => (i % 5 === 0 ? 112 : i % 7 === 0 ? 260 : 158));
    } else {
      mockSequence = Array.from({ length: 100 }, () => Math.floor(Math.random() * 260) + 1);
    }

    addLog(`[🔄] Manual Attack Simulation: Injected '${config.executableName}' with '${config.threatType}' (${config.attackSpeed} speed)...`, 'info');

    if (config.policies.networkIsolation) {
      addLog(`[🛡️] AI policy active: Automated Network Isolation is armed`, 'system');
    }
    if (config.policies.killProcessTree) {
      addLog(`[🛡️] AI policy active: Kill Process Tree is armed`, 'system');
    }
    if (config.policies.autoRollback) {
      addLog(`[🛡️] AI policy active: VSS Auto Rollback is armed`, 'system');
    }

    try {
      const response = await fetch(`${BACKEND_URL}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sequence: mockSequence,
          process_name: config.executableName,
          pid: mockPid,
          malicious: isMalicious,
          risk_percentage: isMalicious ? 98.48 : 2.15,
          status: isMalicious ? 'Threat Detected' : 'Healthy',
          action_taken: isMalicious && config.policies.killProcessTree ? 'Terminated' : 'Allowed'
        })
      });

      if (response.ok) {
        const result: ScanResponse = await response.json();
        setScanResult(result);

        if (result.malicious) {
          addLog(`[🚨] Threat alert trigger from API for ${config.executableName} (Confidence: ${result.risk_percentage}%)`, 'critical');
          if (config.policies.killProcessTree) {
            addLog(`[❌] Process ${mockPid} terminated successfully by Kill Process Tree policy!`, 'success');
          }
          if (config.policies.networkIsolation) {
            addLog(`[🔒] Host isolated from network due to ransomware detection!`, 'critical');
          }
        } else {
          addLog(`[✓] Scan clean for ${config.executableName} (Safety rating: ${(100 - result.risk_percentage).toFixed(2)}%)`, 'success');
        }
        // Instantly refresh the historical alerts
        fetchAlerts();
      } else {
        addLog(`[-] Scanner API connection failed: Status ${response.status}`, 'warning');
      }
    } catch (err) {
      addLog(`[-] API unreachable. Simulating locally...`, 'warning');
      setTimeout(() => {
        const fallbackConfidence = isMalicious ? 0.9848 : 0.0215;
        const mockResult: ScanResponse = {
          success: true,
          malicious: isMalicious,
          confidence: fallbackConfidence,
          risk_percentage: parseFloat((fallbackConfidence * 100).toFixed(2)),
          threat_level: isMalicious ? "HIGH (Ransomware Detected)" : "LOW (Healthy Process)",
          processed_length: 100
        };
        setScanResult(mockResult);
        if (isMalicious) {
          addLog(`[🚨] Local Alert: Ransomware signature flagged for ${config.executableName}`, 'critical');
          setKillCount(prev => prev + 1);
          if (config.policies.killProcessTree) {
            addLog(`[❌] Process ${mockPid} terminated successfully by Local Watchdog!`, 'success');
          }
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
      <style dangerouslySetInnerHTML={{
        __html: `
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

        /* Advanced Threat Simulator Styles */
        .ats-container {
          background-color: var(--bg-secondary);
          border: 1px solid var(--border-color);
          border-radius: 12px;
          padding: 20px;
          display: flex;
          flex-direction: column;
        }
        .ats-tabs {
          display: flex;
          border-bottom: 1px solid var(--border-color);
          margin-bottom: 20px;
          gap: 12px;
        }
        .ats-tab-btn {
          flex: 1;
          background: none;
          border: none;
          padding-bottom: 12px;
          font-size: 11px;
          font-weight: 700;
          color: var(--color-gray);
          cursor: pointer;
          transition: all 0.2s ease;
          text-align: center;
        }
        .ats-tab-btn.active-attack {
          color: var(--color-emerald);
          border-bottom: 2px solid var(--color-emerald);
        }
        .ats-tab-btn.active-policies {
          color: var(--color-cyan);
          border-bottom: 2px solid var(--color-cyan);
        }
        .ats-tab-btn:hover:not(.active-attack):not(.active-policies) {
          color: var(--color-text);
        }
        .ats-subtitle {
          color: var(--color-gray);
          font-size: 9px;
          margin-bottom: 15px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
        .ats-content {
          flex: 1;
          display: flex;
          flex-direction: column;
          gap: 16px;
        }
        .ats-form-group {
          display: flex;
          flex-direction: column;
          gap: 8px;
        }
        .ats-label {
          font-size: 10px;
          color: var(--color-gray);
          text-transform: uppercase;
          font-weight: 700;
          letter-spacing: 1px;
        }
        .ats-input {
          width: 100%;
          background-color: var(--bg-primary);
          border: 1px solid var(--border-color);
          color: var(--color-text);
          padding: 10px 14px;
          border-radius: 6px;
          font-family: 'Courier New', monospace;
          box-sizing: border-box;
          font-size: 13px;
        }
        .ats-input:focus {
          border-color: var(--color-cyan);
          outline: none;
        }
        .ats-speed-grid {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 8px;
          background-color: var(--bg-primary);
          padding: 6px;
          border-radius: 8px;
          border: 1px solid var(--border-color);
        }
        .ats-speed-btn {
          background: none;
          border: 1px solid transparent;
          color: var(--color-gray);
          padding: 8px;
          border-radius: 6px;
          font-size: 11px;
          font-weight: 700;
          text-transform: capitalize;
          cursor: pointer;
          transition: all 0.2s ease;
        }
        .ats-speed-btn:hover:not(.active) {
          color: var(--color-text);
        }
        .ats-speed-btn.active {
          background-color: rgba(0, 255, 102, 0.1);
          border-color: var(--color-emerald);
          color: var(--color-emerald);
          box-shadow: 0 0 8px rgba(0, 255, 102, 0.2);
        }
        .ats-checkbox-list {
          display: flex;
          flex-direction: column;
          gap: 10px;
          background-color: var(--bg-primary);
          padding: 12px;
          border-radius: 8px;
          border: 1px solid var(--border-color);
        }
        .ats-checkbox-label {
          display: flex;
          align-items: center;
          gap: 10px;
          font-size: 11px;
          color: var(--color-text);
          cursor: pointer;
        }
        .ats-checkbox {
          accent-color: var(--color-emerald);
          width: 15px;
          height: 15px;
          cursor: pointer;
        }
        .ats-policy-card {
          display: flex;
          align-items: center;
          justify-content: space-between;
          background-color: var(--bg-primary);
          padding: 12px 16px;
          border-radius: 8px;
          border: 1px solid var(--border-color);
        }
        .ats-policy-info {
          display: flex;
          flex-direction: column;
          gap: 2px;
        }
        .ats-policy-title {
          font-size: 11px;
          font-weight: 700;
          color: var(--color-text);
        }
        .ats-policy-desc {
          font-size: 9px;
          color: var(--color-gray);
        }
        .ats-policy-checkbox {
          accent-color: var(--color-cyan);
          width: 15px;
          height: 15px;
          cursor: pointer;
        }
        .ats-note {
          background-color: rgba(0, 210, 255, 0.05);
          border: 1px solid rgba(0, 210, 255, 0.2);
          border-radius: 8px;
          padding: 12px;
          font-size: 11px;
          color: var(--color-cyan);
          line-height: 1.5;
        }
        .ats-inject-btn {
          width: 100%;
          background-color: var(--color-emerald);
          border: none;
          color: #000;
          padding: 14px;
          border-radius: 8px;
          font-weight: 800;
          cursor: pointer;
          text-transform: uppercase;
          letter-spacing: 1px;
          transition: all 0.2s ease;
          font-size: 12px;
          box-shadow: var(--glow-emerald);
        }
        .ats-inject-btn:hover {
          background-color: var(--color-cyan);
          box-shadow: var(--glow-cyan);
        }

        /* Visual Threat Mapper Styles */
        .vtm-container {
          background-color: var(--bg-secondary);
          border: 1px solid var(--border-color);
          border-radius: 12px;
          padding: 24px;
          height: 520px;
          box-sizing: border-box;
          display: flex;
          flex-direction: column;
          justify-content: space-between;
          animation: fadeIn 0.4s ease;
        }
        .vtm-header {
          border-bottom: 1px solid var(--border-color);
          padding-bottom: 12px;
        }
        .vtm-title {
          margin: 0;
          font-size: 13px;
          font-weight: 800;
          color: var(--color-cyan);
          letter-spacing: 1px;
          text-transform: uppercase;
        }
        .vtm-desc {
          margin: 4px 0 0 0;
          font-size: 10px;
          color: var(--color-gray);
        }
        .vtm-graph {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 16px;
          position: relative;
          margin: auto 0;
        }
        .vtm-node {
          background-color: var(--bg-primary);
          border: 1px solid var(--border-color);
          padding: 16px;
          border-radius: 10px;
          text-align: center;
          position: relative;
          z-index: 10;
          transition: border-color 0.3s ease;
        }
        .vtm-node:hover {
          border-color: #2b3547;
        }
        .vtm-node-emoji {
          font-size: 20px;
          margin-bottom: 6px;
        }
        .vtm-node-title {
          margin: 0;
          font-size: 11px;
          font-weight: 700;
          color: var(--color-text);
        }
        .vtm-badge {
          display: inline-block;
          font-size: 9px;
          margin-top: 10px;
          padding: 2px 8px;
          border-radius: 4px;
          font-weight: 700;
          text-transform: uppercase;
        }
        .vtm-badge.observed {
          color: var(--color-emerald);
          background-color: rgba(0, 255, 102, 0.1);
          border: 1px solid rgba(0, 255, 102, 0.2);
        }
        .vtm-badge.warning {
          color: #f1c40f;
          background-color: rgba(241, 196, 15, 0.1);
          border: 1px solid rgba(241, 196, 15, 0.2);
          animation: blink 2s infinite;
        }
        .vtm-badge.critical {
          color: var(--color-ruby);
          background-color: rgba(255, 51, 85, 0.1);
          border: 1px solid rgba(255, 51, 85, 0.2);
        }
        .vtm-badge.mitigation {
          color: var(--color-cyan);
          background-color: rgba(0, 210, 255, 0.1);
          border: 1px solid rgba(0, 210, 255, 0.2);
        }
        .vtm-badge.idle {
          color: var(--color-gray);
          background-color: var(--bg-tertiary);
          border: 1px solid transparent;
        }
        .vtm-connector-line {
          position: absolute;
          top: 50%;
          left: 0;
          right: 0;
          height: 2px;
          background-color: var(--border-color);
          transform: translateY(-50%);
          z-index: 1;
        }
        .vtm-verdict-card {
          padding: 16px;
          border-radius: 10px;
          border: 1px solid var(--border-color);
          display: flex;
          justify-content: space-between;
          align-items: center;
          background-color: var(--bg-primary);
        }
        .vtm-verdict-card.malicious {
          background-color: rgba(255, 51, 85, 0.05);
          border-color: rgba(255, 51, 85, 0.2);
        }
        .vtm-verdict-info {
          font-size: 11px;
          display: flex;
          flex-direction: column;
          gap: 4px;
        }
        .vtm-verdict-score {
          text-align: right;
        }
        .vtm-verdict-score-lbl {
          font-size: 9px;
          color: var(--color-gray);
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
        .vtm-verdict-score-val {
          font-size: 18px;
          font-weight: 800;
          font-family: 'Courier New', monospace;
        }
        .vtm-verdict-score-val.malicious {
          color: var(--color-ruby);
          text-shadow: var(--glow-ruby);
        }
        .vtm-verdict-score-val.safe {
          color: var(--color-emerald);
          text-shadow: var(--glow-emerald);
        }

        /* Dynamic Simulator & Tailwind Mapping */
        .terminal-container {
          background-color: #070d16;
          border: 1px solid #1f2937;
          border-radius: 1rem;
          padding: 1.25rem;
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
          height: 500px;
          overflow-y: auto;
        }
        .terminal-container .flex {
          display: flex;
        }
        .terminal-container .items-center {
          align-items: center;
        }
        .terminal-container .justify-between {
          justify-content: space-between;
        }
        .terminal-container .mb-4 {
          margin-bottom: 1rem;
        }
        .terminal-container .border-b {
          border-bottom: 1px solid;
        }
        .terminal-container .border-gray-800 {
          border-color: #1f2937;
        }
        .terminal-container .pb-3 {
          padding-bottom: 0.75rem;
        }
        .terminal-container .text-\[\#10b981\] {
          color: #10b981;
        }
        .terminal-container .text-xs {
          font-size: 0.75rem;
        }
        .terminal-container .gap-2 {
          gap: 0.5rem;
        }
        .terminal-container .w-2 {
          width: 0.5rem;
        }
        .terminal-container .h-2 {
          height: 0.5rem;
        }
        .terminal-container .rounded-full {
          border-radius: 9999px;
        }
        .terminal-container .bg-\[\#10b981\] {
          background-color: #10b981;
        }
        .terminal-container .space-y-2 > * + * {
          margin-top: 0.5rem;
        }
        .terminal-container .text-gray-400 {
          color: #9ca3af;
        }

        .visual-simulator-container {
          background-color: #070d16;
          border: 1px solid #1f2937;
          border-radius: 1rem;
          padding: 1.5rem;
          height: 500px;
          display: flex;
          flex-direction: column;
          justify-content: space-between;
          animation: fadeIn 0.4s ease;
          color: white;
          box-sizing: border-box;
        }
        .visual-simulator-container .border-b {
          border-bottom: 1px solid;
        }
        .visual-simulator-container .border-gray-800 {
          border-color: #1f2937;
        }
        .visual-simulator-container .pb-4 {
          padding-bottom: 1rem;
        }
        .visual-simulator-container .text-sm {
          font-size: 0.875rem;
        }
        .visual-simulator-container .font-bold {
          font-weight: bold;
        }
        .visual-simulator-container .text-\[\#0ea5e9\] {
          color: #0ea5e9;
        }
        .visual-simulator-container .tracking-wide {
          letter-spacing: 0.025em;
        }
        .visual-simulator-container .uppercase {
          text-transform: uppercase;
        }
        .visual-simulator-container .text-xs {
          font-size: 0.75rem;
        }
        .visual-simulator-container .text-gray-500 {
          color: #6b7280;
        }
        .visual-simulator-container .mt-1 {
          margin-top: 0.25rem;
        }
        .visual-simulator-container .grid {
          display: grid;
        }
        .visual-simulator-container .grid-cols-4 {
          grid-template-columns: repeat(4, 1fr);
        }
        .visual-simulator-container .gap-4 {
          gap: 1rem;
        }
        .visual-simulator-container .my-auto {
          margin-top: auto;
          margin-bottom: auto;
        }
        .visual-simulator-container .relative {
          position: relative;
        }
        .visual-simulator-container .absolute {
          position: absolute;
        }
        .visual-simulator-container .top-1/2 {
          top: 50%;
        }
        .visual-simulator-container .left-0 {
          left: 0;
        }
        .visual-simulator-container .right-0 {
          right: 0;
        }
        .visual-simulator-container .h-0.5 {
          height: 2px;
        }
        .visual-simulator-container .-translate-y-1/2 {
          transform: translateY(-50%);
        }
        .visual-simulator-container .z-0 {
          z-index: 0;
        }
        .visual-simulator-container .z-10 {
          z-index: 10;
        }
        .visual-simulator-container .bg-\[\#0c1420\] {
          background-color: #0c1420;
        }
        .visual-simulator-container .p-4 {
          padding: 1rem;
        }
        .visual-simulator-container .rounded-xl {
          border-radius: 0.75rem;
        }
        .visual-simulator-container .text-center {
          text-align: center;
        }
        .visual-simulator-container .text-xl {
          font-size: 1.25rem;
        }
        .visual-simulator-container .mb-1 {
          margin-bottom: 0.25rem;
        }
        .visual-simulator-container .text-gray-300 {
          color: #d1d5db;
        }
        .visual-simulator-container .text-\[10px\] {
          font-size: 10px;
        }
        .visual-simulator-container .text-\[\#10b981\] {
          color: #10b981;
        }
        .visual-simulator-container .mt-1\.5 {
          margin-top: 0.375rem;
        }
        .visual-simulator-container .bg-\[\#10b981\]\/10 {
          background-color: rgba(16, 185, 129, 0.1);
        }
        .visual-simulator-container .py-0\.5 {
          padding-top: 0.125rem;
          padding-bottom: 0.125rem;
        }
        .visual-simulator-container .rounded {
          border-radius: 0.25rem;
        }
        .visual-simulator-container .border-\[\#10b981\]\/20 {
          border-color: rgba(16, 185, 129, 0.2);
        }
        .visual-simulator-container .border-gray-800 {
          border-color: #1f2937;
        }
        .visual-simulator-container .text-orange-400 {
          color: #fb923c;
        }
        .visual-simulator-container .bg-orange-400\/10 {
          background-color: rgba(251, 146, 60, 0.1);
        }
        .visual-simulator-container .border-orange-400\/20 {
          border-color: rgba(251, 146, 60, 0.2);
        }
        .visual-simulator-container .bg-gray-900 {
          background-color: #111827;
        }
        .visual-simulator-container .border-transparent {
          border-color: transparent;
        }
        .visual-simulator-container .text-red-400 {
          color: #f87171;
        }
        .visual-simulator-container .bg-red-400\/10 {
          background-color: rgba(248, 113, 113, 0.1);
        }
        .visual-simulator-container .border-red-400\/30 {
          border-color: rgba(248, 113, 113, 0.3);
        }
        .visual-simulator-container .bg-\[\#0ea5e9\]\/10 {
          background-color: rgba(14, 165, 233, 0.1);
        }
        .visual-simulator-container .border-\[\#0ea5e9\]\/30 {
          border-color: rgba(14, 165, 233, 0.3);
        }
        .visual-simulator-container .border {
          border: 1px solid;
        }
        .visual-simulator-container .bg-red-950\/20 {
          background-color: rgba(69, 10, 10, 0.2);
        }
        .visual-simulator-container .border-red-900\/50 {
          border-color: rgba(127, 29, 29, 0.5);
        }
        .visual-simulator-container .text-red-200 {
          color: #fecaca;
        }
        .visual-simulator-container .bg-slate-900\/50 {
          background-color: rgba(15, 23, 42, 0.5);
        }
        .visual-simulator-container .flex {
          display: flex;
        }
        .visual-simulator-container .items-center {
          align-items: center;
        }
        .visual-simulator-container .justify-between {
          justify-content: space-between;
        }
        .visual-simulator-container .space-y-1 > * + * {
          margin-top: 0.25rem;
        }
        .visual-simulator-container .text-right {
          text-align: right;
        }
        .visual-simulator-container .tracking-wider {
          letter-spacing: 0.05em;
        }
        .visual-simulator-container .text-lg {
          font-size: 1.125rem;
        }
        .visual-simulator-container .font-mono {
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
        }
        .visual-simulator-container .text-red-500 {
          color: #ef4444;
        }
        .visual-simulator-container .text-\[\#10b981\] {
          color: #10b981;
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
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
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
        {/* LEFT COLUMN: Conditional Central Display Panel */}
        {activeTab === 'monitoring' ? (
          /* 1️⃣ الخيار الأول: شاشة الـ Terminal النصية الحالية */
          <div className="terminal-container bg-[#070d16] border border-gray-800 rounded-2xl p-5 font-mono h-[500px] overflow-y-auto">
            <div className="flex items-center justify-between mb-4 border-b border-gray-800 pb-3">
              <span className="text-[#10b981] text-xs flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-[#10b981] animate-pulse"></span>
                LIVE PROCESS TELEMETRY MONITORS (AUTO-SCROLL ON)
              </span>
              {/* terminal actions */}
              <div className="flex gap-2">
                <button
                  className="terminal-btn"
                  onClick={() => window.open(`${BACKEND_URL}/api/reports/pdf`, '_blank')}
                  style={{ color: 'var(--color-cyan)', fontWeight: 'bold', borderColor: 'var(--color-cyan)', background: 'transparent' }}
                >
                  📥 Export PDF Report
                </button>
                <button className="terminal-btn" style={{ background: 'transparent' }} onClick={handleClearDatabase}>Clear Terminal</button>
                <button
                  className="terminal-btn"
                  onClick={() => setActiveFeed(!activeFeed)}
                  style={{ color: activeFeed ? '#ff3355' : '#00d2ff', background: 'transparent', borderColor: activeFeed ? '#ff3355' : '#00d2ff' }}
                >
                  {activeFeed ? 'Freeze Stream' : 'Resume Stream'}
                </button>
              </div>
            </div>
            
            <div className="space-y-2 text-xs">
              {logs.map((log) => (
                <div key={log.id} className="log-row">
                  <span className="log-time">[{log.time}]</span>
                  <span className={`log-text type-${log.type}`}>{log.text}</span>
                </div>
              ))}
              <div className="terminal-cursor"></div>
              <div ref={terminalEndRef} />
            </div>
          </div>
        ) : (
          /* 2️⃣ الخيار الثاني الجديد: شاشة المحاكاة المرئية الفخمة (Interactive Threat Map) */
          <div className="visual-simulator-container bg-[#070d16] border border-gray-800 rounded-2xl p-6 h-[500px] flex flex-col justify-between animate-fadeIn text-white">
            
            {/* الرأس - الهوية */}
            <div className="border-b border-gray-800 pb-4">
              <h3 className="text-sm font-bold text-[#0ea5e9] tracking-wide uppercase">⚡ AI-NeuroShield Cognitive Threat Mapper</h3>
              <p className="text-xs text-gray-500 mt-1">Visualizing Transformer Self-Attention weights during runtime sequence telemetry.</p>
            </div>

            {/* الخريطة المرئية المتسلسلة - Attack Chain Node Graph */}
            <div className="grid grid-cols-4 gap-4 my-auto relative">
              
              {/* المرحلة 1 */}
              <div className="bg-[#0c1420] border border-gray-800 p-4 rounded-xl text-center relative z-10">
                <div className="text-xl mb-1">🔍</div>
                <h4 className="text-xs font-bold text-gray-300">1. Recon & Access</h4>
                <div className="text-[10px] text-[#10b981] mt-1.5 bg-[#10b981]/10 py-0.5 rounded border border-[#10b981]/20">API Observed</div>
              </div>

              {/* المرحلة 2 */}
              <div className="bg-[#0c1420] border border-gray-800 p-4 rounded-xl text-center relative z-10">
                <div className="text-xl mb-1">🚷</div>
                <h4 className="text-xs font-bold text-gray-300">2. Evasion Tactic</h4>
                <div className={`text-[10px] mt-1.5 py-0.5 rounded border ${scanResult?.malicious ? 'text-orange-400 bg-orange-400/10 border-orange-400/20 animate-pulse' : 'text-gray-500 bg-gray-900 border-transparent'}`}>
                  {scanResult?.malicious ? 'Suspicious Call' : 'Idle State'}
                </div>
              </div>

              {/* المرحلة 3 */}
              <div className="bg-[#0c1420] border border-gray-800 p-4 rounded-xl text-center relative z-10">
                <div className="text-xl mb-1">🧠</div>
                <h4 className="text-xs font-bold text-gray-300">3. Transformer AI</h4>
                <div className={`text-[10px] mt-1.5 py-0.5 rounded border ${scanResult?.malicious ? 'text-red-400 bg-red-400/10 border-red-400/30' : 'text-gray-500 bg-gray-900 border-transparent'}`}>
                  {scanResult?.malicious ? 'Attention Triggered' : 'Scrutinizing'}
                </div>
              </div>

              {/* المرحلة 4 */}
              <div className="bg-[#0c1420] border border-gray-800 p-4 rounded-xl text-center relative z-10">
                <div className="text-xl mb-1">🛡️</div>
                <h4 className="text-xs font-bold text-gray-300">4. Active Mitigation</h4>
                <div className={`text-[10px] mt-1.5 py-0.5 rounded border ${scanResult?.malicious ? 'text-[#0ea5e9] bg-[#0ea5e9]/10 border-[#0ea5e9]/30' : 'text-gray-500 bg-gray-900 border-transparent'}`}>
                  {scanResult?.malicious ? 'Enforcing Policy' : 'Safe Baseline'}
                </div>
              </div>

              {/* خط الخلفية الواصل بين المراحل */}
              <div className="absolute top-1/2 left-0 right-0 h-0.5 bg-gray-800 -translate-y-1/2 z-0"></div>
            </div>

            {/* كرت الاستنتاج اللحظي السفلي */}
            <div className={`p-4 rounded-xl border ${scanResult?.malicious ? 'bg-red-950/20 border-red-900/50 text-red-200' : 'bg-slate-900/50 border-gray-800 text-gray-300'} flex items-center justify-between`}>
              <div className="text-xs space-y-1">
                <div><strong>Current Evaluation Node:</strong> {scanProcessName || 'None'}</div>
                <div><strong>Behavioral Sequence Verdict:</strong> {scanResult?.malicious ? '🚨 Malicious Signature Match' : '🟢 Verified Safe Execution Baseline'}</div>
              </div>
              <div className="text-right">
                <div className="text-[10px] uppercase text-gray-500 tracking-wider">AI Confidence Score</div>
                <div className={`text-lg font-mono font-bold ${scanResult?.malicious ? 'text-red-500' : 'text-[#10b981]'}`}>
                  {scanResult ? `${scanResult.risk_percentage}%` : '0.00%'}
                </div>
              </div>
            </div>

          </div>
        )}

        {/* RIGHT COLUMN: Sidebar Controllers */}
        <section className="sidebar-panel">
          {/* Advanced Attack Simulator Component */}
          <AdvancedThreatSimulator onInjectSequence={handleSimulateScan} />

          {/* Results Screen */}
          {scanResult && (
            <div className="sidebar-card">
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
