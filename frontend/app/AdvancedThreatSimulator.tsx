import React, { useState } from 'react';

// Configuration type definitions for advanced attack simulations
export type AttackConfig = {
  executableName: string;
  threatType: string;
  attackSpeed: 'low' | 'medium' | 'aggressive';
  defenseEvasion: {
    deleteBackups: boolean;
    registryInjection: boolean;
    disableFirewall: boolean;
  };
  policies: {
    networkIsolation: boolean;
    killProcessTree: boolean;
    autoRollback: boolean;
    alertSyslog: boolean;
  };
};

export function AdvancedThreatSimulator({ onInjectSequence }: { onInjectSequence: (config: AttackConfig) => void }) {
  const [activeTab, setActiveTab] = useState<'attack' | 'policies'>('attack');
  
  // Default threat scenario and defense configuration
  const [config, setConfig] = useState<AttackConfig>({
    executableName: 'ransom_test.exe',
    threatType: 'Ransomware: WannaCry (File Encryption)',
    attackSpeed: 'medium',
    defenseEvasion: {
      deleteBackups: true,
      registryInjection: false,
      disableFirewall: false,
    },
    policies: {
      networkIsolation: true,
      killProcessTree: true,
      autoRollback: false,
      alertSyslog: true,
    }
  });

  const handleInject = () => {
    // Dispatch the configuration block to the central parent handler
    onInjectSequence(config);
  };

  return (
    <div className="ats-container">
      
      {/* Tabs Navigation Switcher */}
      <div className="ats-tabs">
        <button
          onClick={() => setActiveTab('attack')}
          type="button"
          className={`ats-tab-btn ${activeTab === 'attack' ? 'active-attack' : ''}`}
        >
          💥 Advanced Attack Simulation
        </button>
        <button
          onClick={() => setActiveTab('policies')}
          type="button"
          className={`ats-tab-btn ${activeTab === 'policies' ? 'active-policies' : ''}`}
        >
          🛡️ AI Defense Policies
        </button>
      </div>

      <p className="ats-subtitle">Powered by NeuroShield AI Antigravity Core</p>

      {/* Content Area */}
      <div className="ats-content">
        {activeTab === 'attack' && (
          <>
            {/* Simulated Executable Name */}
            <div className="ats-form-group">
              <label className="ats-label">Simulated Executable Name</label>
              <input
                type="text"
                value={config.executableName}
                onChange={(e) => setConfig({...config, executableName: e.target.value})}
                className="ats-input"
              />
            </div>

            {/* Threat Behavior Selection */}
            <div className="ats-form-group">
              <label className="ats-label">Threat Behavior Selection</label>
              <select
                value={config.threatType}
                onChange={(e) => setConfig({...config, threatType: e.target.value})}
                className="ats-input"
                style={{ backgroundColor: 'var(--bg-primary)' }}
              >
                {[
                  'Ransomware: WannaCry (File Encryption)',
                  'Advanced Threat: Emotet Botnet',
                  'Credential Theft: Mimikatz LSASS',
                  'Vulnerability: Apache Log4j',
                  'Exploit: Zero-Day Adobe Acrobat',
                  'Healthy OS Process: svchost (Safe)'
                ].map(threat => (
                  <option key={threat} value={threat}>{threat}</option>
                ))}
              </select>
            </div>

            {/* Execution Intensity (Speed) */}
            <div className="ats-form-group">
              <label className="ats-label">Execution Intensity (Speed)</label>
              <div className="ats-speed-grid">
                {(['low', 'medium', 'aggressive'] as const).map((speed) => (
                  <button
                    key={speed}
                    type="button"
                    onClick={() => setConfig({...config, attackSpeed: speed})}
                    className={`ats-speed-btn ${config.attackSpeed === speed ? 'active' : ''}`}
                  >
                    {speed}
                  </button>
                ))}
              </div>
            </div>

            {/* Defense Evasion Tactics (MITRE ATT&CK) */}
            <div className="ats-form-group">
              <label className="ats-label">Defense Evasion Tactics (MITRE)</label>
              <div className="ats-checkbox-list">
                <label className="ats-checkbox-label">
                  <input
                    type="checkbox"
                    checked={config.defenseEvasion.deleteBackups}
                    onChange={(e) => setConfig({...config, defenseEvasion: {...config.defenseEvasion, deleteBackups: e.target.checked}})}
                    className="ats-checkbox"
                  />
                  Inhibit System Recovery (vssadmin delete shadows)
                </label>
                <label className="ats-checkbox-label">
                  <input
                    type="checkbox"
                    checked={config.defenseEvasion.registryInjection}
                    onChange={(e) => setConfig({...config, defenseEvasion: {...config.defenseEvasion, registryInjection: e.target.checked}})}
                    className="ats-checkbox"
                  />
                  Boot or Logon Autostart (Registry Run Keys)
                </label>
                <label className="ats-checkbox-label">
                  <input
                    type="checkbox"
                    checked={config.defenseEvasion.disableFirewall}
                    onChange={(e) => setConfig({...config, defenseEvasion: {...config.defenseEvasion, disableFirewall: e.target.checked}})}
                    className="ats-checkbox"
                  />
                  Impair Defenses (Disable Firewall)
                </label>
              </div>
            </div>
          </>
        )}

        {activeTab === 'policies' && (
          <>
            <p style={{ color: 'var(--color-gray)', fontSize: '11px', margin: '0 0 10px 0', lineHeight: 1.5 }}>
              Configure automated mitigation playbooks triggered instantly by the Transformer Behavioral Model.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {/* Automated Network Isolation */}
              <div className="ats-policy-card">
                <div className="ats-policy-info">
                  <span className="ats-policy-title">Automated Network Isolation</span>
                  <span className="ats-policy-desc">Disconnect host from network upon malicious flag</span>
                </div>
                <input
                  type="checkbox"
                  checked={config.policies.networkIsolation}
                  onChange={(e) => setConfig({...config, policies: {...config.policies, networkIsolation: e.target.checked}})}
                  className="ats-policy-checkbox"
                />
              </div>

              {/* Kill Process Tree */}
              <div className="ats-policy-card">
                <div className="ats-policy-info">
                  <span className="ats-policy-title">Kill Process Tree</span>
                  <span className="ats-policy-desc">Terminate offending PID and all spawned children</span>
                </div>
                <input
                  type="checkbox"
                  checked={config.policies.killProcessTree}
                  onChange={(e) => setConfig({...config, policies: {...config.policies, killProcessTree: e.target.checked}})}
                  className="ats-policy-checkbox"
                />
              </div>

              {/* VSS Automated Rollback */}
              <div className="ats-policy-card">
                <div className="ats-policy-info">
                  <span className="ats-policy-title">VSS Automated Rollback</span>
                  <span className="ats-policy-desc">Restore encrypted files from shadow copies automatically</span>
                </div>
                <input
                  type="checkbox"
                  checked={config.policies.autoRollback}
                  onChange={(e) => setConfig({...config, policies: {...config.policies, autoRollback: e.target.checked}})}
                  className="ats-policy-checkbox"
                />
              </div>

              {/* Forward to Cloud SIEM */}
              <div className="ats-policy-card">
                <div className="ats-policy-info">
                  <span className="ats-policy-title">Forward to Cloud SIEM</span>
                  <span className="ats-policy-desc">Stream JSON telemetry to centralized logs</span>
                </div>
                <input
                  type="checkbox"
                  checked={config.policies.alertSyslog}
                  onChange={(e) => setConfig({...config, policies: {...config.policies, alertSyslog: e.target.checked}})}
                  className="ats-policy-checkbox"
                />
              </div>
            </div>

            <div className="ats-note">
              💡 <strong>Enterprise Note:</strong> Active policies enforce rules at the kernel level via the NeuroShield Core Agent client.
            </div>
          </>
        )}
      </div>

      {/* Fixed Inject Action Button */}
      <div style={{ marginTop: '20px' }}>
        <button onClick={handleInject} type="button" className="ats-inject-btn">
          Inject Attack Sequence & Test AI
        </button>
      </div>
    </div>
  );
}
