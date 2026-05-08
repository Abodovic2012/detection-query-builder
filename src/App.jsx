import React, { useEffect, useMemo, useState } from 'react';

const detectionTemplates = {
  suspicious_process_injection: {
    title: 'Suspicious Process Injection',
    description:
      'Detect process injection techniques such as hollowing, remote thread creation, or unusual parent-child relationships.',
    fields: {
      table: 'DeviceProcessEvents',
      processField: 'process_name',
      parentProcessField: 'parent_process_name',
      commandField: 'process_command_line',
    },
    splunk: ({ table, processField, parentProcessField, commandField }) => `${table}
| search ${processField}="*" OR ${commandField}="*"
| where ${parentProcessField}="explorer.exe" AND (${processField}="powershell.exe" OR ${processField}="rundll32.exe")
| table _time ${processField} ${parentProcessField} ${commandField}`,
    kql: ({ table, processField, parentProcessField, commandField }) => `${table}
| where ${parentProcessField} =~ "explorer.exe"
| where ${processField} in~ ("powershell.exe","rundll32.exe","regsvr32.exe")
| project TimeGenerated, ${processField}, ${parentProcessField}, ${commandField}`,
    wazuh: ({ processField, parentProcessField }) => `index=wazuh-alerts-*
| search rule.groups:sysmon OR rule.groups:windows
| search ${parentProcessField}:explorer.exe AND (${processField}:powershell.exe OR ${processField}:rundll32.exe)
| stats count by ${processField}, ${parentProcessField}`,
  },

  phishing_email_detection: {
    title: 'Phishing Email Indicators',
    description:
      'Detect suspicious email activity such as spoofed senders, suspicious subjects, and mass email campaigns.',
    fields: {
      table: 'EmailLogs',
      senderField: 'SenderFromAddress',
      subjectField: 'Subject',
      recipientField: 'RecipientAddress',
      threshold: '50',
    },
    splunk: ({ table, senderField, subjectField, threshold }) => `${table}
| stats count by ${senderField}, ${subjectField}
| where count >= ${threshold}
| sort - count`,
    kql: ({ table, senderField, subjectField, threshold }) => `${table}
| summarize EmailCount=count() by ${senderField}, ${subjectField}
| where EmailCount >= ${threshold}
| order by EmailCount desc`,
    wazuh: ({ senderField, subjectField, threshold }) => `index=wazuh-alerts-*
| search rule.groups:email OR rule.groups:office365
| stats count by ${senderField}, ${subjectField}
| where count >= ${threshold}`,
  },

  data_exfiltration_dns: {
    title: 'DNS Data Exfiltration Detection',
    description:
      'Detect large or abnormal DNS queries potentially used for data exfiltration.',
    fields: {
      table: 'DnsLogs',
      queryField: 'query_name',
      bytesField: 'query_size',
      threshold: '1000',
    },
    splunk: ({ table, queryField, bytesField, threshold }) => `${table}
| stats sum(${bytesField}) as total_bytes by ${queryField}
| where total_bytes >= ${threshold}
| sort - total_bytes`,
    kql: ({ table, queryField, bytesField, threshold }) => `${table}
| summarize TotalBytes=sum(${bytesField}) by ${queryField}
| where TotalBytes >= ${threshold}
| order by TotalBytes desc`,
    wazuh: ({ queryField, threshold }) => `index=wazuh-alerts-*
| search rule.groups:dns
| stats sum(bytes) as total_bytes by ${queryField}
| where total_bytes >= ${threshold}`,
  },

  failed_login_spike: {
    title: 'Failed Login Spike (User / IP)',
    description:
      'Detect sudden spikes in failed authentication attempts indicating brute force or password spraying.',
    fields: {
      table: 'SigninLogs',
      usernameField: 'UserPrincipalName',
      ipField: 'IPAddress',
      threshold: '20',
    },
    splunk: ({ table, usernameField, ipField, threshold }) => `${table}
| where status="failure"
| stats count by ${usernameField}, ${ipField}
| where count >= ${threshold}
| sort - count`,
    kql: ({ table, usernameField, ipField, threshold }) => `${table}
| where ResultType != 0
| summarize FailCount=count() by ${usernameField}, ${ipField}
| where FailCount >= ${threshold}
| order by FailCount desc`,
    wazuh: ({ usernameField, ipField, threshold }) => `index=wazuh-alerts-*
| search rule.groups:authentication_failed
| stats count by ${usernameField}, ${ipField}
| where count >= ${threshold}
| sort - count`,
  },

  privilege_escalation_activity: {
    title: 'Privilege Escalation Activity',
    description:
      'Detect creation of new admin accounts or elevation of privileges.',
    fields: {
      table: 'AuditLogs',
      actorField: 'InitiatedBy',
      actionField: 'Operation',
    },
    splunk: ({ table, actionField, actorField }) => `${table}
| search ${actionField}="Add member to role" OR ${actionField}="Add admin"
| table _time ${actorField} ${actionField}`,
    kql: ({ table, actionField, actorField }) => `${table}
| where ${actionField} has_any ("Add member to role", "Add admin")
| project TimeGenerated, ${actorField}, ${actionField}`,
    wazuh: ({ actorField, actionField }) => `index=wazuh-alerts-*
| search rule.groups:policy OR rule.groups:authentication
| search ${actionField}:*admin* OR ${actionField}:*role*
| stats count by ${actorField}, ${actionField}`,
  },

  lateral_movement_detection: {
    title: 'Lateral Movement Detection',
    description:
      'Detect potential lateral movement via remote execution tools and SMB/WinRM activity.',
    fields: {
      table: 'DeviceProcessEvents',
      processField: 'process_name',
      commandField: 'process_command_line',
      hostField: 'DeviceName',
    },
    splunk: ({ table, processField, commandField }) => `${table}
| search ${processField}="psexec.exe" OR ${processField}="wmic.exe" OR ${commandField}="*\\*"
| table _time ${processField} ${commandField}`,
    kql: ({ table, processField, commandField, hostField }) => `${table}
| where ${processField} in~ ('psexec.exe','wmic.exe') or ${commandField} has '\\'
| project TimeGenerated, ${hostField}, ${processField}, ${commandField}`,
    wazuh: ({ processField, commandField }) => `index=wazuh-alerts-*
| search rule.groups:sysmon OR rule.groups:windows
| search ${processField}:psexec.exe OR ${processField}:wmic.exe OR ${commandField}:"*\\*"
| stats count by ${processField}, ${commandField}`,
  },

  brute_force_authentication: {
    title: 'Brute Force Authentication',
    description:
      'Detect repeated failed authentication attempts against a single account or endpoint.',
    fields: {
      index: 'auth_logs',
      table: 'SigninLogs',
      usernameField: 'user',
      sourceIpField: 'src_ip',
      threshold: '10',
    },
    splunk: ({ index, usernameField, sourceIpField, threshold }) => `index=${index} action=failure
| stats count by ${usernameField}, ${sourceIpField}
| where count >= ${threshold}
| sort - count`,
    kql: ({ table, usernameField, sourceIpField, threshold }) => `${table}
| where ResultType != 0
| summarize FailedAttempts=count() by ${usernameField}, ${sourceIpField}
| where FailedAttempts >= ${threshold}
| order by FailedAttempts desc`,
    wazuh: ({ usernameField, sourceIpField, threshold }) => `index=wazuh-alerts-*
| search rule.groups:authentication_failed
| stats count by ${usernameField}, ${sourceIpField}
| where count >= ${threshold}`,
  },
};

const styles = {
  page: {
    minHeight: '100vh',
    background: '#020617',
    color: '#e2e8f0',
    padding: '24px',
    fontFamily: 'Arial, sans-serif',
  },
  container: {
    maxWidth: '1400px',
    margin: '0 auto',
  },
  header: { marginBottom: '24px' },
  title: { fontSize: '36px', fontWeight: '700', marginBottom: '12px' },
  subtitle: { color: '#94a3b8', lineHeight: '1.6' },
  grid: {
    display: 'grid',
    gridTemplateColumns: '350px 1fr',
    gap: '24px',
  },
  panel: {
    background: '#0f172a',
    border: '1px solid #1e293b',
    borderRadius: '16px',
    padding: '20px',
  },
  label: { display: 'block', marginBottom: '8px', fontSize: '14px', fontWeight: '600' },
  input: {
    width: '100%',
    background: '#020617',
    border: '1px solid #334155',
    borderRadius: '8px',
    color: '#e2e8f0',
    padding: '10px 12px',
    marginBottom: '16px',
    boxSizing: 'border-box',
  },
  textarea: {
    width: '100%',
    minHeight: '300px',
    background: '#020617',
    border: '1px solid #334155',
    borderRadius: '8px',
    color: '#22d3ee',
    padding: '16px',
    fontFamily: 'monospace',
    fontSize: '14px',
    boxSizing: 'border-box',
  },
  button: {
    background: '#0891b2',
    color: '#fff',
    border: 'none',
    borderRadius: '8px',
    padding: '10px 16px',
    cursor: 'pointer',
    fontWeight: '600',
  },
  select: {
    width: '100%',
    background: '#020617',
    border: '1px solid #334155',
    borderRadius: '8px',
    color: '#e2e8f0',
    padding: '10px 12px',
    marginBottom: '16px',
  },
  tabs: { display: 'flex', gap: '12px', marginBottom: '16px' },
  tab: {
    padding: '10px 16px',
    borderRadius: '8px',
    border: '1px solid #334155',
    cursor: 'pointer',
    background: '#0f172a',
    color: '#e2e8f0',
  },
  activeTab: { background: '#0891b2', border: '1px solid #0891b2' },
  footer: {
    marginTop: '24px',
    textAlign: 'center',
    color: '#64748b',
    fontSize: '14px',
  },
};

export default function DetectionQueryBuilder() {
  const [selectedDetection, setSelectedDetection] = useState('failed_login_spike');
  const [activeTab, setActiveTab] = useState('splunk');
  const [copyMessage, setCopyMessage] = useState('');

  const activeTemplate = detectionTemplates[selectedDetection];
  const [formState, setFormState] = useState(activeTemplate.fields);

  useEffect(() => {
    setFormState(detectionTemplates[selectedDetection].fields);
  }, [selectedDetection]);

  const updateField = (field, value) => {
    setFormState((prev) => ({ ...prev, [field]: value }));
  };

  const splunkQuery = useMemo(() => activeTemplate.splunk(formState), [activeTemplate, formState]);
  const kqlQuery = useMemo(() => activeTemplate.kql(formState), [activeTemplate, formState]);
  const wazuhQuery = useMemo(() => activeTemplate.wazuh(formState), [activeTemplate, formState]);

  const activeQuery = activeTab === 'splunk'
    ? splunkQuery
    : activeTab === 'kql'
      ? kqlQuery
      : wazuhQuery;

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(activeQuery);
      setCopyMessage('Copied');
      setTimeout(() => setCopyMessage(''), 1500);
    } catch {
      setCopyMessage('Copy failed');
    }
  };

  return (
    <div style={styles.page}>
      <div style={styles.container}>
        <div style={styles.header}>
          <h1 style={styles.title}>Splunk / KQL / Wazuh Detection Query Builder</h1>
          <p style={styles.subtitle}>SOC detection engineering query generator</p>
        </div>

        <div style={styles.grid}>
          <div style={styles.panel}>
            <label style={styles.label}>Detection</label>
            <select
              style={styles.select}
              value={selectedDetection}
              onChange={(e) => setSelectedDetection(e.target.value)}
            >
              {Object.entries(detectionTemplates).map(([k, v]) => (
                <option key={k} value={k}>{v.title}</option>
              ))}
            </select>

            {Object.entries(formState).map(([field, value]) => (
              <div key={field}>
                <label style={styles.label}>{field}</label>
                <input style={styles.input} value={value}
                  onChange={(e) => updateField(field, e.target.value)}
                />
              </div>
            ))}
          </div>

          <div style={styles.panel}>
            <div style={styles.tabs}>
              <button style={{ ...styles.tab, ...(activeTab === 'splunk' ? styles.activeTab : {}) }} onClick={() => setActiveTab('splunk')}>Splunk</button>
              <button style={{ ...styles.tab, ...(activeTab === 'kql' ? styles.activeTab : {}) }} onClick={() => setActiveTab('kql')}>KQL</button>
              <button style={{ ...styles.tab, ...(activeTab === 'wazuh' ? styles.activeTab : {}) }} onClick={() => setActiveTab('wazuh')}>Wazuh</button>
            </div>

            <button style={styles.button} onClick={copyToClipboard}>Copy</button>

            {copyMessage && <div style={{ color: '#22c55e' }}>{copyMessage}</div>}

            <textarea style={styles.textarea} value={activeQuery} readOnly />

            <div style={styles.footer}>Programmed by Msc Eng Abdul Rahman Hawa</div>
          </div>
        </div>
      </div>
    </div>
  );
}

// -------------------- BASIC TESTS --------------------
console.assert(typeof detectionTemplates.failed_login_spike.wazuh === 'function', 'Wazuh exists');
console.assert(Object.keys(detectionTemplates).length >= 4, 'Templates loaded');
console.assert(typeof detectionTemplates.lateral_movement_detection.wazuh === 'function', 'Lateral wazuh exists');

