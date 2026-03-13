import { useState, useRef, useCallback } from "react";

const C = {
  bg: "#07090e", surface: "#0d1018", raised: "#131822",
  border: "#1a2233", bright: "#243049",
  text: "#c8d8ee", muted: "#4a6080", dim: "#1a2233",
  CRITICAL: "#ff2d55", HIGH: "#ff6b1a", MEDIUM: "#f5c400", LOW: "#28d47a",
  accent: "#3d8eff", green: "#28d47a", purple: "#8b5cf6",
};
const SEV    = s => C[s] || C.muted;
const SEV_BG = s => s ? `${SEV(s)}15` : "transparent";
const SEV_BD = s => s ? `${SEV(s)}35` : C.border;

// ── Log Parser ────────────────────────────────────────────────────────────────
function parseLogFile(filename, content) {
  const clean = content.replace(/^\uFEFF/, "").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const entries = [];
  try {
    const parsed = JSON.parse(clean);
    const items = Array.isArray(parsed) ? parsed
      : parsed.records ? parsed.records
      : parsed.hits?.hits ? parsed.hits.hits.map(h => h._source || h)
      : parsed.events ? parsed.events : null;
    if (items) { for (const item of items) { const e = normalizeJSON(item, filename); if (e) entries.push(e); } return entries; }
  } catch {}
  const lines = clean.split("\n");
  let buf = "";
  for (const raw of lines) {
    const line = raw.trim();
    if (!line) { buf = ""; continue; }
    if (line.startsWith("{") || buf) {
      buf += (buf ? "\n" : "") + line;
      try { const obj = JSON.parse(buf); buf = ""; const e = normalizeJSON(obj, filename); if (e) entries.push(e); }
      catch { if (buf.length > 50000) buf = ""; }
      continue;
    }
    buf = "";
    if (line.startsWith("<Event") || line.includes("<EventID>")) { const e = normalizeXML(line); if (e) entries.push(e); continue; }
    const authM = line.match(/^(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s*(.+)$/);
    if (authM) { entries.push({ timestamp: authM[1], source_type: "linux_auth", host: authM[2], service: authM[3], message: authM[4], raw: line }); continue; }
    if (line.includes(",")) entries.push({ raw: line, source_type: "csv", message: line });
  }
  return entries;
}

function normalizeJSON(obj, filename) {
  if (obj._source) obj = obj._source;
  const evType = obj.event_type || obj.type || obj["@type"] || "";
  const isSuricata = evType || obj.src_ip || obj.dest_ip || obj.flow_id || obj.proto;
  if (isSuricata && !obj.winlog && !obj.EventID && !obj.event?.code) {
    return { timestamp: obj.timestamp || obj["@timestamp"], source_type: "suricata",
      host: (typeof obj.host === "object" ? obj.host?.name : obj.host) || obj.sensor || "unknown",
      event_type: evType, src_ip: obj.src_ip || obj.src || "", dest_ip: obj.dest_ip || obj.dst || obj.dest || "",
      dest_port: obj.dest_port || obj.dp || "", src_port: obj.src_port || "",
      proto: obj.proto || obj.protocol || "",
      alert_signature: obj.alert?.signature || obj.alert?.msg || obj.signature || "",
      alert_category: obj.alert?.category || "", alert_severity: obj.alert?.severity ?? obj.severity,
      dns_query: obj.dns?.rrname || obj.dns?.query?.[0]?.rrname || obj.dns_query || "",
      dns_type: obj.dns?.type || "", http_url: obj.http?.url || "", http_ua: obj.http?.http_user_agent || "",
      http_status: obj.http?.status || "", http_method: obj.http?.http_method || "",
      tls_sni: obj.tls?.sni || "", tls_issuer: obj.tls?.issuer || "",
      app_proto: obj.app_proto || "", payload_printable: obj.payload_printable || "",
      ssh_client: obj.ssh?.client?.software_version || "", ssh_server: obj.ssh?.server?.software_version || "",
      raw: obj };
  }
  if (obj.winlog || obj.EventID || obj.event?.code) {
    const winlog = obj.winlog || {};
    const evdata = winlog.event_data || obj.event_data || {};
    const eventId = String(winlog.event_id || obj.EventID || obj.event?.code || "");
    const channel = (winlog.channel || obj.Channel || "").toLowerCase();
    return { timestamp: obj["@timestamp"] || obj.timestamp || obj.TimeCreated,
      source_type: channel.includes("sysmon") ? "sysmon" : "winauth",
      host: obj.host?.name || obj.computer_name || obj.beat?.hostname || "unknown",
      user: evdata.SubjectUserName || evdata.TargetUserName || obj.user?.name || "",
      event_id: eventId, command_line: evdata.CommandLine || "",
      process_image: evdata.Image || "", parent_image: evdata.ParentImage || "",
      dest_ip: evdata.DestinationIp || evdata.IpAddress || "",
      dest_port: evdata.DestinationPort || "", failure_reason: evdata.FailureReason || "",
      service_name: evdata.ServiceName || "", ticket_encryption: evdata.TicketEncryptionType || "",
      target_filename: evdata.TargetFilename || "", hashes: evdata.Hashes || "",
      logon_type: evdata.LogonType || "", registry_key: evdata.TargetObject || "",
      pipe_name: evdata.PipeName || "", raw: obj };
  }
  return { timestamp: obj["@timestamp"] || obj.timestamp || new Date().toISOString(),
    source_type: "generic",
    host: (typeof obj.host === "object" ? obj.host?.name : obj.host) || "unknown",
    user: (typeof obj.user === "object" ? obj.user?.name : obj.user) || "",
    message: obj.message || JSON.stringify(obj).slice(0, 200), raw: obj };
}

function normalizeXML(line) {
  const eventId  = (line.match(/<EventID[^>]*>(\d+)</) || [])[1] || "";
  const computer = (line.match(/<Computer>([^<]+)</) || [])[1] || "unknown";
  const time     = (line.match(/SystemTime='([^']+)'/) || [])[1] || "";
  const gd = name => { const m = line.match(new RegExp(`Name='${name}'[^>]*>([^<]*)<`)); return m ? m[1] : ""; };
  return { timestamp: time, source_type: line.includes("Sysmon") ? "sysmon" : "winauth",
    host: computer, event_id: eventId, command_line: gd("CommandLine"),
    process_image: gd("Image"), parent_image: gd("ParentImage"),
    dest_ip: gd("DestinationIp"), ticket_encryption: gd("TicketEncryptionType"),
    target_filename: gd("TargetFilename"), registry_key: gd("TargetObject"),
    user: gd("SubjectUserName") || gd("TargetUserName"), raw: line };
}

// ── Detection Engine ──────────────────────────────────────────────────────────
const _counts = {};   // generic stateful counter store
function resetDetState() { Object.keys(_counts).forEach(k => delete _counts[k]); }
function cnt(key, n=1) { _counts[key] = (_counts[key] || 0) + n; return _counts[key]; }
function get(key) { return _counts[key] || 0; }

function entropy(s) {
  if (!s) return 0;
  const c = {}; for (const ch of s.toLowerCase()) c[ch] = (c[ch]||0)+1;
  const n = s.length;
  return -Object.values(c).reduce((sum, v) => sum + (v/n)*Math.log2(v/n), 0);
}

function mkDet(ruleId, ruleName, severity, confidence, entry, description, tags, tactics, techniques, extra) {
  return { id: Math.random().toString(36).slice(2,10).toUpperCase(),
    rule_id: ruleId, rule_name: ruleName, severity, confidence,
    host: entry.host||"unknown", user: entry.user||null, source_type: entry.source_type,
    timestamp: entry.timestamp||new Date().toISOString(),
    description, tags, mitre_tactics: tactics, mitre_techniques: techniques,
    extra: extra||{}, raw_log: typeof entry.raw==="object" ? entry.raw : {line:entry.raw} };
}

function detectEntry(entry) {
  const hits = [];
  const sig  = (entry.alert_signature || "").toLowerCase();
  const msg  = (entry.message || "").toLowerCase();
  const cmd  = (entry.command_line || "").toLowerCase();
  const img  = (entry.process_image || "").toLowerCase();
  const par  = (entry.parent_image || "").toLowerCase();
  const eid  = entry.event_id || "";
  const src  = entry.src_ip || "";
  const dst  = entry.dest_ip || "";
  const dport= String(entry.dest_port || "");

  // ════════════════════════════════════════════════════════════════
  // ENDPOINT / WINDOWS RULES
  // ════════════════════════════════════════════════════════════════

  // RULE-001: Encoded/Obfuscated PowerShell
  if (entry.source_type === "sysmon" && eid === "1") {
    if (img.includes("powershell") || img.includes("pwsh")) {
      const flags = ["-encodedcommand","-enc ","-e ","iex(","invoke-expression","downloadstring",
        "webclient","-nop","-w hidden","bypass","frombase64string","-windowstyle hidden","reflection.assembly"];
      const matched = flags.filter(f => cmd.includes(f));
      if (matched.length > 0)
        hits.push(mkDet("RULE-001","Encoded/Obfuscated PowerShell","HIGH",
          Math.min(0.50+0.08*matched.length,0.95),entry,
          `PowerShell flags: ${matched.slice(0,3).join(", ")} | ${cmd.slice(0,120)}`,
          ["powershell","execution","obfuscation"],["Execution"],["T1059.001"],{command_line:entry.command_line}));
    }
  }

  // RULE-002: Brute Force Login — Windows (4625)
  if (entry.source_type === "winauth" && eid === "4625") {
    const k = `bf:${entry.host}:${entry.user}:${dst}`;
    const n = cnt(k);
    _counts[`bflast:${entry.host}:${entry.user}`] = dst;
    if (n===5||n===15||n===30)
      hits.push(mkDet("RULE-002","Brute Force Login",n>=15?"HIGH":"MEDIUM",
        Math.min(0.60+n*0.01,0.95),entry,
        `${n} failed logins for '${entry.user}' from ${dst}`,
        ["brute-force","credential-access"],["Credential Access"],["T1110"],{count:n,src_ip:dst}));
  }

  // RULE-002B: SSH Brute Force — Linux auth.log
  if (entry.source_type === "linux_auth") {
    if (msg.includes("failed") || msg.includes("invalid user") || msg.includes("authentication failure")) {
      const ip = (entry.message?.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/)||[])[1]||"unknown";
      const k = `sshbf:${entry.host}:${ip}`; const n = cnt(k);
      if (n===10||n===25||n===50)
        hits.push(mkDet("RULE-002","SSH Brute Force",n>=25?"HIGH":"MEDIUM",
          Math.min(0.60+n*0.005,0.90),entry,
          `${n} SSH failures from ${ip} on ${entry.host}`,
          ["brute-force","ssh"],["Credential Access"],["T1110.001"],{count:n,src_ip:ip}));
    }
  }

  // RULE-003: Logon Success After Brute Force
  if (entry.source_type === "winauth" && eid === "4624") {
    const priorIP = _counts[`bflast:${entry.host}:${entry.user}`];
    if (priorIP) {
      const k = `bf:${entry.host}:${entry.user}:${priorIP}`; const n = get(k);
      if (n >= 5) {
        hits.push(mkDet("RULE-003","Login After Brute Force","HIGH",0.87,entry,
          `Login succeeded for '${entry.user}' after ${n} failures — compromise likely`,
          ["initial-access","credential-compromise"],["Initial Access"],["T1078"],{prior_failures:n,src_ip:priorIP}));
        delete _counts[k]; delete _counts[`bflast:${entry.host}:${entry.user}`];
      }
    }
  }

  // RULE-004: Kerberoasting
  if (entry.source_type === "winauth" && eid === "4769") {
    const enc = String(entry.ticket_encryption||"");
    if (enc==="0x17"||enc==="23") {
      const k = `kerb:${entry.host}:${entry.user}`; const n = cnt(k);
      if (n===1||n%5===0)
        hits.push(mkDet("RULE-004","Kerberoasting (RC4 TGS)","HIGH",
          Math.min(0.75+n*0.03,0.95),entry,
          `RC4 TGS for '${entry.service_name}' — ${n} request(s)`,
          ["kerberoasting","active-directory"],["Credential Access"],["T1558.003"],{spn:entry.service_name,count:n}));
    }
  }

  // RULE-008: PsExec / Remote Execution Service
  if (entry.source_type === "sysmon") {
    const f = (entry.target_filename||"").toLowerCase();
    if (img.includes("psexesvc")||f.includes("psexesvc"))
      hits.push(mkDet("RULE-008","PsExec Lateral Movement","HIGH",0.88,entry,
        `PSEXESVC detected on ${entry.host}`,
        ["lateral-movement","psexec"],["Lateral Movement","Execution"],["T1021.002","T1569.002"],{}));
  }

  // RULE-009: Suspicious Office Macro → Shell Spawn
  if (entry.source_type === "sysmon" && eid === "1") {
    const pairs = [["cmd.exe","excel.exe"],["cmd.exe","winword.exe"],["cmd.exe","outlook.exe"],
      ["powershell.exe","winword.exe"],["powershell.exe","excel.exe"],["wscript.exe","winword.exe"],
      ["mshta.exe","winword.exe"],["mshta.exe","excel.exe"]];
    for (const [child,p] of pairs) {
      if (img.includes(child)&&par.includes(p)) {
        hits.push(mkDet("RULE-009","Office Macro Shell Spawn","HIGH",0.81,entry,
          `Anomalous: ${p} → ${child}`,
          ["macro","phishing"],["Execution","Initial Access"],["T1059.001","T1566.001"],{parent:par,child:img}));
        break;
      }
    }
  }

  // RULE-013: LOLBIN Abuse (Living off the Land)
  if (entry.source_type === "sysmon" && eid === "1") {
    const lolbins = ["certutil","mshta","regsvr32","rundll32","wmic","bitsadmin","cmstp",
      "installutil","regasm","regsvcs","msiexec","wscript","cscript","forfiles","pcalua"];
    const suspicious = ["http","ftp","\\\\","base64","download","urlcache","encode","decode",
      "scriptleturl","regserver","scrobj"];
    const isLol = lolbins.some(b => img.includes(b));
    const isSus = suspicious.some(s => cmd.includes(s));
    if (isLol && isSus)
      hits.push(mkDet("RULE-013","LOLBIN Abuse","HIGH",0.79,entry,
        `${img.split("\\").pop()} used suspiciously: ${cmd.slice(0,120)}`,
        ["lolbin","defense-evasion"],["Defense Evasion","Execution"],["T1218","T1105"],{binary:img,cmd:entry.command_line}));
  }

  // RULE-014: Suspicious Registry Modification
  if (entry.source_type === "sysmon" && eid === "13") {
    const reg = (entry.registry_key||"").toLowerCase();
    const runKeys = ["currentversion\\run","currentversion\\runonce","winlogon","userinit",
      "shell\\open\\command","appinit_dlls","image file execution options","lsa\\notification"];
    if (runKeys.some(k => reg.includes(k)))
      hits.push(mkDet("RULE-014","Suspicious Registry Persistence","HIGH",0.84,entry,
        `Registry write to persistence key: ${entry.registry_key}`,
        ["persistence","registry"],["Persistence"],["T1547.001","T1112"],{key:entry.registry_key}));
  }

  // RULE-015: Suspicious Named Pipe
  if (entry.source_type === "sysmon" && eid === "17") {
    const pipe = (entry.pipe_name||"").toLowerCase();
    const c2pipes = ["msagent_","postex_","mojo.","status_","demoagent_","spoolss","ntsvcs",
      "samr","lsarpc","netlogon","browser","atsvc"];
    if (c2pipes.some(p => pipe.includes(p)))
      hits.push(mkDet("RULE-015","C2 Named Pipe Detected","HIGH",0.82,entry,
        `Suspicious pipe: ${entry.pipe_name} — common C2 framework indicator`,
        ["c2","named-pipe"],["Command and Control"],["T1071","T1559.001"],{pipe:entry.pipe_name}));
  }

  // RULE-016: Credential Dumping (LSASS Access)
  if (entry.source_type === "sysmon" && (eid === "10" || eid === "1")) {
    const target = (entry.target_filename||entry.process_image||"").toLowerCase();
    const isLsass = target.includes("lsass");
    const dumpTools = ["mimikatz","procdump","tasklist","wce","fgdump","gsecdump","pwdump","ntdsutil"];
    const isDump = dumpTools.some(t => cmd.includes(t)||img.includes(t));
    if (isLsass||isDump)
      hits.push(mkDet("RULE-016","Credential Dumping Attempt","CRITICAL",0.90,entry,
        `LSASS access or known dumping tool: ${img.split("\\").pop()||target}`,
        ["credential-dumping","mimikatz"],["Credential Access"],["T1003.001"],{tool:img,target}));
  }

  // RULE-017: Suspicious Scheduled Task Creation
  if (entry.source_type === "sysmon" && eid === "1") {
    if ((img.includes("schtasks")||img.includes("at.exe")) &&
        (cmd.includes("/create")||cmd.includes("-create")))
      hits.push(mkDet("RULE-017","Scheduled Task Persistence","MEDIUM",0.76,entry,
        `Scheduled task created: ${cmd.slice(0,150)}`,
        ["persistence","scheduled-task"],["Persistence","Execution"],["T1053.005"],{cmd:entry.command_line}));
  }

  // RULE-018: WMI Lateral Movement / Persistence
  if (entry.source_type === "sysmon" && eid === "1") {
    if (img.includes("wmic")||(img.includes("wmiprvse"))) {
      const wmiSus = ["process call create","node:","/node","subscription","eventfilter","eventtrigger"];
      if (wmiSus.some(w => cmd.includes(w)))
        hits.push(mkDet("RULE-018","WMI Lateral Movement / Persistence","HIGH",0.80,entry,
          `WMI abuse: ${cmd.slice(0,150)}`,
          ["wmi","lateral-movement"],["Lateral Movement","Persistence"],["T1047","T1546.003"],{cmd:entry.command_line}));
    }
  }

  // RULE-019: Pass-the-Hash / Unusual Logon Type
  if (entry.source_type === "winauth" && eid === "4624") {
    const lt = String(entry.logon_type||"");
    if ((lt==="3"||lt==="9"||lt==="10") && dst && !["127.0.0.1","::1"].includes(dst)) {
      const k = `pth:${entry.host}:${entry.user}:${lt}`; const n = cnt(k);
      if (n===3||n===8||n===15)
        hits.push(mkDet("RULE-019","Suspicious Remote Logon (PtH/PtT)","HIGH",0.72,entry,
          `Logon type ${lt} for '${entry.user}' from ${dst} (${n} occurrences)`,
          ["pass-the-hash","lateral-movement"],["Lateral Movement","Credential Access"],["T1550.002"],
          {logon_type:lt,src_ip:dst,count:n}));
    }
  }

  // RULE-020: Account Creation / Privilege Escalation
  if (entry.source_type === "winauth") {
    if (eid==="4720")
      hits.push(mkDet("RULE-020","New User Account Created","MEDIUM",0.70,entry,
        `New account created: '${entry.user}' on ${entry.host}`,
        ["persistence","account-creation"],["Persistence"],["T1136.001"],{}));
    if (eid==="4732"||eid==="4728")
      hits.push(mkDet("RULE-020","User Added to Privileged Group","HIGH",0.82,entry,
        `User added to admin group on ${entry.host}`,
        ["privilege-escalation","account-manipulation"],["Privilege Escalation"],["T1098"],{}));
  }

  // RULE-021: Windows Defender / Security Tool Disabled
  if (entry.source_type === "sysmon" && eid === "1") {
    const avKill = ["set-mppreference","add-mppreference","disablerealtimemonitoring","disableioavprotection",
      "sc stop","net stop","taskkill","wdfilter","wcscentry","antivirusoverride"];
    if (avKill.some(k => cmd.includes(k)))
      hits.push(mkDet("RULE-021","Security Tool Tampering","HIGH",0.85,entry,
        `AV/EDR kill attempt: ${cmd.slice(0,150)}`,
        ["defense-evasion","antivirus-kill"],["Defense Evasion"],["T1562.001"],{cmd:entry.command_line}));
  }

  // RULE-022: Shadow Copy Deletion (Ransomware precursor)
  if (entry.source_type === "sysmon" && eid === "1") {
    const shadowKill = ["vssadmin delete","wmic shadowcopy delete","bcdedit /set recoveryenabled no",
      "bcdedit /set bootstatuspolicy","wbadmin delete","diskshadow /s","resize shadowstorage"];
    if (shadowKill.some(k => cmd.includes(k)))
      hits.push(mkDet("RULE-022","Shadow Copy / Backup Deletion","CRITICAL",0.93,entry,
        `Backup destruction: ${cmd.slice(0,150)}`,
        ["ransomware","impact","backup-deletion"],["Impact"],["T1490"],{cmd:entry.command_line}));
  }

  // RULE-023: Suspicious File Written (Sysmon Event 11)
  if (entry.source_type === "sysmon" && eid === "11") {
    const tf = (entry.target_filename||"").toLowerCase();
    const suspPaths = ["\\temp\\","\\appdata\\","\\programdata\\","\\public\\","\\windows\\temp\\"];
    const suspExts  = [".exe",".dll",".bat",".ps1",".vbs",".js",".hta",".scr",".cpl"];
    if (suspPaths.some(p=>tf.includes(p)) && suspExts.some(e=>tf.endsWith(e)))
      hits.push(mkDet("RULE-023","Suspicious File Drop in Temp/Public","MEDIUM",0.70,entry,
        `Executable dropped: ${entry.target_filename}`,
        ["dropper","file-write"],["Execution","Defense Evasion"],["T1105","T1036"],{path:entry.target_filename}));
  }

  // ════════════════════════════════════════════════════════════════
  // NETWORK / SURICATA RULES
  // ════════════════════════════════════════════════════════════════

  // RULE-005: C2 Framework (Suricata alert signatures)
  if (entry.source_type === "suricata" && entry.event_type === "alert") {
    const c2 = ["cobalt strike","cobaltstrike","metasploit","c2 beacon","et malware",
      "meterpreter","sliver","havoc","empire","brute ratel","poshc2","mythic","covenant"];
    if (c2.some(p => sig.includes(p)))
      hits.push(mkDet("RULE-005","C2 Framework Communication",
        entry.alert_severity<=1?"CRITICAL":"HIGH",entry.alert_severity<=1?0.92:0.80,entry,
        `IDS: '${entry.alert_signature}' → ${dst}:${dport}`,
        ["c2","malware"],["Command and Control"],["T1071.001"],
        {signature:entry.alert_signature,dest:`${dst}:${dport}`}));
  }

  // RULE-006: DNS Tunneling
  if (entry.source_type === "suricata" && entry.dns_query) {
    const label = (entry.dns_query.split(".")[0]||"");
    if (label.length > 40) {
      const domain = entry.dns_query.split(".").slice(-2).join(".");
      const k = `dnstun:${entry.host}:${domain}`; const n = cnt(k);
      if (n >= 3)
        hits.push(mkDet("RULE-006","DNS Tunneling Suspected","HIGH",0.78,entry,
          `Long label (${label.length} chars): ${entry.dns_query.slice(0,80)} (${n} queries)`,
          ["dns-tunnel","exfiltration"],["Exfiltration","Command and Control"],["T1048.003","T1071.004"],
          {query:entry.dns_query,label_len:label.length,count:n}));
    }
  }

  // RULE-007: DGA / High-Entropy Domain
  if (entry.source_type === "suricata" && entry.dns_query) {
    const label = (entry.dns_query.split(".")[0]||""); const ent = entropy(label);
    if (ent > 3.5) {
      const k = `dga:${entry.host}`; const n = cnt(k);
      if (n >= 5)
        hits.push(mkDet("RULE-007","DGA-Based C2 Activity","MEDIUM",
          Math.min(0.45+ent*0.06,0.82),entry,
          `High-entropy domain: '${entry.dns_query.slice(0,60)}' (entropy=${ent.toFixed(2)}, ${n} queries)`,
          ["dga","malware"],["Command and Control"],["T1568.002"],{query:entry.dns_query,entropy:ent,count:n}));
    }
  }

  // RULE-010: Network Reconnaissance / Port Scan
  if (entry.source_type === "suricata" && entry.event_type === "alert") {
    const scanPat = ["et scan","potential ssh scan","sipvicious","nmap","masscan",
      "potential vnc scan","suspicious inbound","portscan","port scan"];
    if (scanPat.some(p => sig.includes(p))) {
      const k = `scan:${src}`; const n = cnt(k);
      if (n===5||n===15||n===30||n===60)
        hits.push(mkDet("RULE-010","Network Reconnaissance / Port Scan",
          n>=30?"HIGH":"MEDIUM",Math.min(0.55+n*0.005,0.88),entry,
          `${n} scan alerts from ${src} → ${dst} | ${entry.alert_signature}`,
          ["reconnaissance","scanning"],["Reconnaissance"],["T1595.001","T1046"],
          {src_ip:src,count:n,last_sig:entry.alert_signature}));
    }
  }

  // RULE-011: Threat Intelligence — Known Malicious IP
  if (entry.source_type === "suricata" && entry.event_type === "alert") {
    const tiPat = ["et drop","et cins","et compromised","dshield","poor reputation","block listed","hostile host","feodo","abuse.ch"];
    if (tiPat.some(p => sig.includes(p))) {
      const k = `ti:${src}`; const n = cnt(k);
      if (n===1||n===5||n===15)
        hits.push(mkDet("RULE-011","Threat Intel — Known Malicious IP",
          n>=5?"HIGH":"MEDIUM",Math.min(0.65+n*0.02,0.90),entry,
          `Known bad IP ${src} → ${dst}:${dport} (${n} hit(s)) | ${entry.alert_signature}`,
          ["threat-intel","blacklist"],["Initial Access","Impact"],["T1190","T1071"],
          {src_ip:src,dest_port:dport,count:n}));
    }
  }

  // RULE-012: VoIP / SIP Scanning
  if (entry.source_type === "suricata" && entry.event_type === "alert") {
    if (sig.includes("sipvicious")||sig.includes("friendly-scanner")||
        (sig.includes("sip")&&dport==="5060")) {
      const k = `sip:${src}`; const n = cnt(k);
      if (n===3||n===10)
        hits.push(mkDet("RULE-012","VoIP Reconnaissance (SIPVicious)","MEDIUM",0.80,entry,
          `SIPVicious from ${src} targeting ${dst}:${dport} (${n} probes)`,
          ["voip","sipvicious","reconnaissance"],["Reconnaissance"],["T1595.001"],{src_ip:src,count:n}));
    }
  }

  // RULE-024: Exploit / Shellcode Attempt
  if (entry.source_type === "suricata" && entry.event_type === "alert") {
    const exploitPat = ["et exploit","shellcode","heap spray","rop chain","use after free",
      "buffer overflow","sql injection","sqli","xss","rce","remote code execution","log4j","log4shell",
      "spring4shell","proxylogon","eternalblue","wannacry","eternal"];
    if (exploitPat.some(p => sig.includes(p)))
      hits.push(mkDet("RULE-024","Exploit / Shellcode Attempt","CRITICAL",0.88,entry,
        `Exploit sig: '${entry.alert_signature}' from ${src}:${entry.src_port} → ${dst}:${dport}`,
        ["exploit","shellcode"],["Initial Access","Execution"],["T1190","T1203"],
        {signature:entry.alert_signature,src,dst,dport}));
  }

  // RULE-025: Malware / RAT / Trojan Signature
  if (entry.source_type === "suricata" && entry.event_type === "alert") {
    const malPat = ["et malware","trojan","rat ","ransomware","botnet","backdoor","et trojan",
      "et backdoor","njrat","darkcomet","quasar","asyncrat","remcos","nanocore","agent tesla",
      "formbook","redline","amadey","vidar","raccoon","lokibot"];
    if (malPat.some(p => sig.includes(p)))
      hits.push(mkDet("RULE-025","Malware / RAT Detected","CRITICAL",0.87,entry,
        `Malware sig: '${entry.alert_signature}' → ${dst}:${dport}`,
        ["malware","rat","trojan"],["Command and Control","Exfiltration"],["T1219","T1041"],
        {signature:entry.alert_signature,dest:`${dst}:${dport}`}));
  }

  // RULE-026: Suspicious HTTP — Webshell / Tool UA
  if (entry.source_type === "suricata" && entry.event_type === "alert") {
    const httpPat = ["webshell","web shell","php reverse","cmd.php","shell.php",
      "et web_client","et web_server","sqlmap","nikto","dirb","gobuster","wp-scan"];
    if (httpPat.some(p => sig.includes(p)))
      hits.push(mkDet("RULE-026","Webshell / Web Attack Tool","HIGH",0.83,entry,
        `Web attack: '${entry.alert_signature}' | URL: ${entry.http_url||"unknown"}`,
        ["webshell","web-attack"],["Persistence","Initial Access"],["T1505.003","T1190"],
        {signature:entry.alert_signature,url:entry.http_url,ua:entry.http_ua}));
  }

  // RULE-027: Suspicious TLS / Self-Signed Certificate
  if (entry.source_type === "suricata" && entry.event_type === "tls") {
    const issuer = (entry.tls_issuer||"").toLowerCase();
    const sni    = (entry.tls_sni||"").toLowerCase();
    const selfSigned = issuer.includes("self") || issuer === sni ||
      (issuer && !issuer.includes("let's encrypt") && !issuer.includes("digicert") &&
       !issuer.includes("comodo") && !issuer.includes("sectigo") && !issuer.includes("globalsign"));
    if (selfSigned && dst) {
      const k = `tls:${dst}`; const n = cnt(k);
      if (n===1||n===5)
        hits.push(mkDet("RULE-027","Suspicious TLS (Self-Signed Cert)","MEDIUM",0.65,entry,
          `Self-signed TLS to ${dst}:${dport} | SNI: ${entry.tls_sni} | Issuer: ${entry.tls_issuer}`,
          ["tls","c2","evasion"],["Command and Control"],["T1573.001"],
          {dest:dst,sni:entry.tls_sni,issuer:entry.tls_issuer,count:n}));
    }
  }

  // RULE-028: Nmap / Automated Scanner User-Agent
  if (entry.source_type === "suricata" && entry.http_ua) {
    const scanUAs = ["nmap","masscan","zgrab","shodan","censys","python-requests/",
      "go-http-client","curl/","wget/","libwww","nikto","sqlmap","dirbuster","nuclei"];
    const ua = entry.http_ua.toLowerCase();
    if (scanUAs.some(s => ua.includes(s)))
      hits.push(mkDet("RULE-028","Scanner / Recon User-Agent","MEDIUM",0.72,entry,
        `Suspicious UA '${entry.http_ua}' from ${src} | URL: ${entry.http_url}`,
        ["scanning","recon"],["Reconnaissance"],["T1595.002"],{ua:entry.http_ua,url:entry.http_url,src}));
  }

  // RULE-029: SSH Tool Fingerprint (Nmap, custom clients)
  if (entry.source_type === "suricata" && entry.event_type === "ssh") {
    const sshClient = (entry.ssh_client||"").toLowerCase();
    const suspClients = ["nmap","libssh","paramiko","impacket","putty","bitvise",
      "jsch","twisted","asyncssh","dropbear"];
    if (suspClients.some(s => sshClient.includes(s)) && !sshClient.includes("openssh")) {
      const k = `sshfp:${src}`; const n = cnt(k);
      if (n===1||n===5)
        hits.push(mkDet("RULE-029","Suspicious SSH Client Fingerprint","MEDIUM",0.68,entry,
          `Unusual SSH client '${entry.ssh_client}' from ${src}`,
          ["ssh","reconnaissance"],["Reconnaissance","Initial Access"],["T1021.004"],
          {client:entry.ssh_client,src,count:n}));
    }
  }

  // RULE-030: Data Exfiltration — Large Outbound Transfer
  if (entry.source_type === "suricata" && entry.event_type === "alert") {
    const exfilPat = ["et policy large","data exfil","exfiltration","large upload",
      "suspicious upload","dns exfil","http post large","ftp upload"];
    if (exfilPat.some(p => sig.includes(p)))
      hits.push(mkDet("RULE-030","Potential Data Exfiltration","HIGH",0.75,entry,
        `Exfil sig: '${entry.alert_signature}' from ${src} → ${dst}:${dport}`,
        ["exfiltration","data-theft"],["Exfiltration"],["T1041","T1048"],
        {signature:entry.alert_signature,src,dst}));
  }

  // RULE-031: Tor / Anonymization Network
  if (entry.source_type === "suricata" && entry.event_type === "alert") {
    const torPat = ["et tor","tor exit","tor known","onion","i2p ","freenet","vpn detection"];
    if (torPat.some(p => sig.includes(p)))
      hits.push(mkDet("RULE-031","Tor / Anonymization Network Usage","HIGH",0.82,entry,
        `Anonymization: '${entry.alert_signature}' | ${src} → ${dst}`,
        ["tor","anonymization","evasion"],["Defense Evasion","Command and Control"],["T1090.003"],
        {signature:entry.alert_signature,src,dst}));
  }

  // RULE-032: SNMP / Telnet / Legacy Protocol Abuse
  if (entry.source_type === "suricata" && entry.event_type === "alert") {
    const legacyPat = ["snmp public","telnet login","rlogin","rsh ","finger ","tftp "];
    if (legacyPat.some(p => sig.includes(p)))
      hits.push(mkDet("RULE-032","Legacy Protocol Abuse","LOW",0.60,entry,
        `Legacy protocol: '${entry.alert_signature}' from ${src}`,
        ["legacy-protocol","reconnaissance"],["Discovery"],["T1046"],
        {signature:entry.alert_signature,src,dport}));
  }

  // RULE-033: Cryptocurrency Mining
  if (entry.source_type === "suricata" && entry.event_type === "alert") {
    const minePat = ["crypto","miner","mining","stratum","monero","xmrig","bitcoin","et coinminer",
      "coinhive","cryptonight","pool.supportxmr","minexmr"];
    if (minePat.some(p => sig.includes(p)))
      hits.push(mkDet("RULE-033","Cryptocurrency Mining Activity","MEDIUM",0.80,entry,
        `Mining: '${entry.alert_signature}' | ${src} → ${dst}:${dport}`,
        ["cryptomining","impact"],["Impact"],["T1496"],{signature:entry.alert_signature,src,dst,dport}));
  }

  // RULE-034: RDP Brute Force / Suspicious RDP
  if (entry.source_type === "suricata" && entry.event_type === "alert") {
    if (dport==="3389"||(sig.includes("rdp")||sig.includes("remote desktop"))) {
      const k = `rdp:${src}`; const n = cnt(k);
      if (n===3||n===10||n===25)
        hits.push(mkDet("RULE-034","RDP Brute Force / Scanning","HIGH",
          Math.min(0.65+n*0.01,0.90),entry,
          `RDP activity from ${src} → ${dst}:${dport} (${n} attempts)`,
          ["rdp","brute-force"],["Lateral Movement","Credential Access"],["T1110","T1021.001"],
          {src,count:n}));
    }
  }

  // RULE-035: Suspicious DNS — Newly Seen / Rare TLD
  if (entry.source_type === "suricata" && entry.dns_query && entry.dns_type === "query") {
    const rareTLDs = [".xyz",".tk",".pw",".cc",".top",".club",".work",".download",
      ".loan",".win",".stream",".gq",".ml",".cf",".ga"];
    if (rareTLDs.some(t => entry.dns_query.endsWith(t))) {
      const k = `raretld:${entry.host}`; const n = cnt(k);
      if (n===3||n===10)
        hits.push(mkDet("RULE-035","Suspicious Rare TLD DNS Query","MEDIUM",0.62,entry,
          `Rare TLD query: ${entry.dns_query} (${n} rare-TLD queries from host)`,
          ["suspicious-dns","c2"],["Command and Control"],["T1568","T1071.004"],
          {query:entry.dns_query,count:n}));
    }
  }

  // ════════════════════════════════════════════════════════════════
  // GENERIC / CROSS-SOURCE RULES
  // ════════════════════════════════════════════════════════════════

  // RULE-036: Generic Linux Suspicious Commands
  if (entry.source_type === "linux_auth" || entry.source_type === "generic") {
    const suspCmds = ["chmod 777","wget http","curl http","bash -i","nc -e","/dev/tcp",
      "python -c","perl -e","nohup","base64 -d",">/dev/null 2>&1",
      "chmod +x","useradd","adduser","visudo","sudo su","su root"];
    if (suspCmds.some(c => msg.includes(c)))
      hits.push(mkDet("RULE-036","Suspicious Linux Command Executed","MEDIUM",0.68,entry,
        `Suspicious cmd in log: ${entry.message?.slice(0,150)}`,
        ["linux","suspicious-command"],["Execution","Persistence"],["T1059.004"],{message:entry.message}));
  }

  // RULE-037: Privilege Escalation — Sudo / Su
  if (entry.source_type === "linux_auth") {
    if (msg.includes("sudo") && (msg.includes("incorrect password")||msg.includes("not in sudoers"))) {
      const k = `sudofail:${entry.host}`; const n = cnt(k);
      if (n===3||n===10)
        hits.push(mkDet("RULE-037","Sudo Privilege Escalation Attempt","MEDIUM",0.72,entry,
          `${n} sudo failures on ${entry.host}: ${entry.message?.slice(0,120)}`,
          ["privilege-escalation","sudo"],["Privilege Escalation"],["T1548.003"],{count:n}));
    }
    if (msg.includes("session opened for user root"))
      hits.push(mkDet("RULE-037","Root Session Opened","HIGH",0.80,entry,
        `Root session opened on ${entry.host}: ${entry.message?.slice(0,120)}`,
        ["privilege-escalation","root"],["Privilege Escalation"],["T1548"],{}));
  }

  // RULE-038: Log Clearing / Audit Tampering
  if (entry.source_type === "winauth" && (eid==="1102"||eid==="104"))
    hits.push(mkDet("RULE-038","Security Log Cleared","HIGH",0.90,entry,
      `Audit log cleared on ${entry.host} by '${entry.user}'`,
      ["defense-evasion","log-clearing"],["Defense Evasion"],["T1070.001"],{}));
  if (entry.source_type === "sysmon" && eid==="1") {
    if (cmd.includes("clear-eventlog")||cmd.includes("wevtutil cl")||cmd.includes("auditpol"))
      hits.push(mkDet("RULE-038","Event Log Manipulation","HIGH",0.85,entry,
        `Log tampering: ${cmd.slice(0,150)}`,
        ["defense-evasion","log-clearing"],["Defense Evasion"],["T1070.001"],{cmd:entry.command_line}));
  }

  // RULE-039: Ransomware Behavioral Pattern
  if (entry.source_type === "sysmon" && eid === "11") {
    const tf = (entry.target_filename||"").toLowerCase();
    const ransomExts = [".locked",".encrypted",".enc",".crypt",".crypted",".cerber",
      ".locky",".wannacry",".wnncry",".petya",".ryuk",".conti",".ransom",".pay2decrypt"];
    if (ransomExts.some(e => tf.endsWith(e)))
      hits.push(mkDet("RULE-039","Ransomware File Extension Detected","CRITICAL",0.94,entry,
        `Ransomware extension on file: ${entry.target_filename}`,
        ["ransomware","impact"],["Impact"],["T1486"],{file:entry.target_filename}));
  }

  // RULE-040: Port Forwarding / Tunneling Tool
  if (entry.source_type === "sysmon" && eid === "1") {
    const tunnels = ["plink","chisel","ngrok","frpc","frps","ligolo","socat","netsh portproxy",
      "netsh interface portproxy","ssh -r","ssh -l","ssh -d","proxychains","stunnel"];
    if (tunnels.some(t => cmd.includes(t)||img.includes(t)))
      hits.push(mkDet("RULE-040","Port Forwarding / Tunnel Tool","HIGH",0.80,entry,
        `Tunneling tool detected: ${img.split("\\").pop()} | ${cmd.slice(0,120)}`,
        ["tunneling","lateral-movement","c2"],["Command and Control","Lateral Movement"],["T1572","T1021"],
        {tool:img,cmd:entry.command_line}));
  }

  return hits;
}

// ── Correlator ────────────────────────────────────────────────────────────────
function correlate(detections) {
  const byHost = {};
  for (const d of detections) {
    const k = d.host || "unknown";
    if (!byHost[k]) byHost[k] = [];
    byHost[k].push(d);
  }

  const incidents = [];

  for (const [host, dets] of Object.entries(byHost)) {
    const rids = new Set(dets.map(d => d.rule_id));
    const has  = (...rules) => rules.some(r => rids.has(r));

    // ── Boolean flags for every rule group ───────────────────────────────────
    const hasBrute    = has("RULE-002");
    const hasWin      = has("RULE-003");
    const hasPShell   = has("RULE-001");
    const hasKerb     = has("RULE-004");
    const hasC2Net    = has("RULE-005");
    const hasDNSTun   = has("RULE-006");
    const hasDGA      = has("RULE-007");
    const hasPsExec   = has("RULE-008");
    const hasMacro    = has("RULE-009");
    const hasScan     = has("RULE-010");
    const hasTI       = has("RULE-011");
    const hasSIP      = has("RULE-012");
    const hasLolbin   = has("RULE-013");
    const hasRegPers  = has("RULE-014");
    const hasNamedPipe= has("RULE-015");
    const hasCred     = has("RULE-016");
    const hasSched    = has("RULE-017");
    const hasWMI      = has("RULE-018");
    const hasPtH      = has("RULE-019");
    const hasAcctChg  = has("RULE-020");
    const hasAVKill   = has("RULE-021");
    const hasShadow   = has("RULE-022");
    const hasFileDrop = has("RULE-023");
    const hasExploit  = has("RULE-024");
    const hasMalware  = has("RULE-025");
    const hasWebshell = has("RULE-026");
    const hasBadTLS   = has("RULE-027");
    const hasScanUA   = has("RULE-028");
    const hasSuspSSH  = has("RULE-029");
    const hasExfil    = has("RULE-030");
    const hasTor      = has("RULE-031");
    const hasLegacy   = has("RULE-032");
    const hasMine     = has("RULE-033");
    const hasRDP      = has("RULE-034");
    const hasRareTLD  = has("RULE-035");
    const hasSuspCmd  = has("RULE-036");
    const hasSudo     = has("RULE-037");
    const hasLogClr   = has("RULE-038");
    const hasRansomExt= has("RULE-039");
    const hasTunnel   = has("RULE-040");

    // Composite groups
    const hasExec   = hasPShell || hasMacro || hasLolbin || hasFileDrop || hasSuspCmd;
    const hasC2     = hasC2Net  || hasDNSTun || hasDGA   || hasNamedPipe|| hasBadTLS;
    const hasLat    = hasPsExec || hasWMI    || hasPtH;
    const hasPers   = hasRegPers|| hasSched  || hasAcctChg;
    const hasRansom = hasShadow || hasRansomExt;
    const hasRecon  = hasScan   || hasScanUA || hasSuspSSH|| hasRDP;
    const hasEvasion= hasAVKill || hasLogClr;

    // confidence booster: +0.04 per extra corroborating signal
    const boost = (...flags) => flags.filter(Boolean).length * 0.04;

    let title = null, chain = [], conf = 0;

    // ── 1. RANSOMWARE (highest priority) ─────────────────────────────────────
    if (hasRansom) {
      title = "Ransomware Attack Chain";
      chain = [];
      if (hasExec)    chain.push("Malicious payload executed — initial infection vector");
      if (hasEvasion) chain.push("Security tools / event logs disabled to blind defenders");
      if (hasCred)    chain.push("Credentials harvested to spread across environment");
      if (hasLat)     chain.push("Lateral movement to maximise encryption blast radius");
      if (hasShadow)  chain.push("Shadow copies / backups deleted — recovery blocked");
      if (hasRansomExt) chain.push("Ransomware file extensions written to disk — encryption active");
      conf = 0.93 + boost(hasExec, hasEvasion, hasCred, hasLat);
    }

    // ── 2. FULL KILL CHAIN ────────────────────────────────────────────────────
    else if (hasBrute && hasWin && hasExec && hasC2) {
      title = "Full Compromise — Credential Access → Execution → C2";
      chain = [
        "Brute force credential attack",
        "Login succeeded — initial access confirmed",
        "Malicious code executed on host",
        "Active C2 channel established",
      ];
      if (hasLat)  chain.push("Lateral movement underway");
      if (hasPers) chain.push("Persistence mechanism installed for long-term access");
      if (hasExfil)chain.push("Data exfiltration activity detected");
      conf = 0.93 + boost(hasLat, hasPers, hasExfil);
    }

    // ── 3. EXPLOIT → POST-EXPLOITATION ───────────────────────────────────────
    else if (hasExploit && (hasMalware || hasC2 || hasExec)) {
      title = "Exploit → Post-Exploitation Chain";
      chain = ["Exploit attempt detected against exposed service"];
      if (hasMalware) chain.push("Malware deployed following exploitation");
      if (hasExec)    chain.push("Arbitrary code execution confirmed");
      if (hasC2)      chain.push("C2 channel established post-exploit");
      if (hasLat)     chain.push("Lateral movement initiated");
      if (hasCred)    chain.push("Credential harvesting observed");
      conf = 0.88 + boost(hasMalware, hasExec, hasC2, hasLat);
    }

    // ── 4. WEBSHELL → PERSISTENCE / LATERAL ──────────────────────────────────
    else if (hasWebshell && (hasPers || hasLat || hasExec)) {
      title = "Webshell Deployment → Post-Compromise Activity";
      chain = ["Web attack / webshell signature detected on server"];
      if (hasExec)    chain.push("Commands executed via webshell");
      if (hasPers)    chain.push("Persistence mechanism installed post-compromise");
      if (hasLat)     chain.push("Lateral movement from compromised web server");
      if (hasExfil)   chain.push("Data exfiltration observed");
      conf = 0.85 + boost(hasExec, hasPers, hasLat, hasExfil);
    }

    // ── 5. CREDENTIAL DUMP → LATERAL MOVEMENT ────────────────────────────────
    else if (hasCred && hasLat) {
      title = "Credential Dumping → Lateral Movement";
      chain = [
        "LSASS / credential dump tool detected",
        "Harvested credentials used for lateral movement",
      ];
      if (hasKerb)  chain.push("Kerberoasting compounds AD-wide credential risk");
      if (hasPtH)   chain.push("Pass-the-Hash / Pass-the-Ticket logon observed");
      if (hasPsExec)chain.push("PsExec remote execution following credential theft");
      if (hasC2)    chain.push("C2 channel maintained throughout operation");
      conf = 0.90 + boost(hasKerb, hasPtH, hasC2);
    }

    // ── 6. BRUTE FORCE → COMPROMISE ──────────────────────────────────────────
    else if (hasBrute && hasWin) {
      title = "Credential Compromise → Post-Exploitation";
      chain = [
        "Repeated failed logins — brute force in progress",
        "Login succeeded — credentials compromised",
      ];
      if (hasExec)  chain.push("Malicious payload executed on compromised host");
      if (hasC2)    chain.push("C2 channel established");
      if (hasLat)   chain.push("Lateral movement observed");
      if (hasPers)  chain.push("Persistence mechanism installed");
      if (hasEvasion) chain.push("Defense evasion techniques applied");
      conf = 0.78 + boost(hasExec, hasC2, hasLat, hasPers, hasEvasion);
    }

    // ── 7. ACTIVE MALWARE + C2 ────────────────────────────────────────────────
    else if (hasMalware && hasC2) {
      title = "Active Malware with C2 Communication";
      chain = [
        "Malware / RAT signature detected in traffic",
        "Command-and-control channel confirmed active",
      ];
      if (hasDNSTun)  chain.push("DNS tunneling used to covertly exfiltrate data");
      if (hasDGA)     chain.push("DGA domains queried — beacon rotation likely");
      if (hasTunnel)  chain.push("Network tunneling tool bypassing egress controls");
      if (hasExfil)   chain.push("Data exfiltration in progress");
      conf = 0.89 + boost(hasDNSTun, hasDGA, hasTunnel, hasExfil);
    }

    // ── 8. CREDENTIAL DUMPING (standalone) ────────────────────────────────────
    else if (hasCred) {
      title = "Credential Dumping / LSASS Attack";
      chain = [
        "LSASS memory access or credential dumping tool detected",
        "Plaintext or hashed credentials at risk of extraction",
      ];
      if (hasKerb) chain.push("Kerberoasting also detected — AD service account hashes at risk");
      if (hasPtH)  chain.push("Pass-the-Hash logon — stolen hashes already in use");
      conf = 0.88 + boost(hasKerb, hasPtH);
    }

    // ── 9. KERBEROASTING / AD ATTACK ─────────────────────────────────────────
    else if (hasKerb) {
      title = "Kerberoasting / Active Directory Credential Theft";
      chain = [
        "RC4-encrypted TGS tickets requested — offline hash cracking likely",
        "Service account credentials at risk of compromise",
      ];
      if (hasPtH)    chain.push("Pass-the-Hash/Ticket also detected — harvest in progress");
      if (hasAcctChg)chain.push("Account changes observed — attacker may be entrenching");
      conf = 0.76 + boost(hasPtH, hasAcctChg);
    }

    // ── 10. DEFENSE EVASION CHAIN ─────────────────────────────────────────────
    else if (hasEvasion && (hasExec || hasPers || hasC2)) {
      title = "Defense Evasion with Active Threat Activity";
      chain = [];
      if (hasAVKill) chain.push("Security tools / AV disabled to blind endpoint defenses");
      if (hasLogClr) chain.push("Event logs cleared to erase forensic trail");
      if (hasExec)   chain.push("Payload executed under cover of disabled defenses");
      if (hasPers)   chain.push("Persistence installed while defenses are down");
      if (hasC2)     chain.push("C2 communication established");
      conf = 0.84 + boost(hasExec, hasPers, hasC2);
    }

    // ── 11. LATERAL MOVEMENT ──────────────────────────────────────────────────
    else if (hasLat) {
      title = "Lateral Movement Detected";
      chain = [];
      if (hasBrute)   chain.push("Credential brute force preceded lateral movement");
      if (hasPsExec)  chain.push("PsExec remote execution service deployed");
      if (hasWMI)     chain.push("WMI used for remote command execution");
      if (hasPtH)     chain.push("Pass-the-Hash / Pass-the-Ticket authentication");
      if (hasPers)    chain.push("Persistence mechanism installed on remote host");
      conf = 0.72 + boost(hasBrute, hasPsExec, hasWMI, hasPtH, hasPers);
    }

    // ── 12. PERSISTENCE CLUSTER ───────────────────────────────────────────────
    else if ([hasRegPers, hasSched, hasAcctChg, hasNamedPipe].filter(Boolean).length >= 2) {
      title = "Multi-Vector Persistence Established";
      chain = [];
      if (hasRegPers)  chain.push("Registry Run key modified for auto-start persistence");
      if (hasSched)    chain.push("Scheduled task created for recurring execution");
      if (hasAcctChg)  chain.push("New account or privilege change — backdoor account likely");
      if (hasNamedPipe)chain.push("C2 named pipe created — in-memory implant maintaining access");
      conf = 0.80 + boost(hasExec, hasC2, hasEvasion);
    }

    // ── 13. TOR / ANONYMIZED EXFILTRATION ────────────────────────────────────
    else if (hasTor && (hasExfil || hasC2)) {
      title = "Tor-Anonymized C2 or Data Exfiltration";
      chain = [
        "Traffic routed through Tor — attacker masking origin",
      ];
      if (hasC2)   chain.push("C2 commands tunnelled through anonymization network");
      if (hasExfil)chain.push("Data exfiltration observed over Tor circuit");
      conf = 0.83 + boost(hasC2, hasExfil);
    }

    // ── 14. DNS-BASED C2 / EXFILTRATION ──────────────────────────────────────
    else if (hasDNSTun || (hasDGA && hasC2Net)) {
      title = "DNS-Based C2 / Data Exfiltration";
      chain = [];
      if (hasDNSTun) chain.push("DNS tunneling detected — data encoded in DNS queries");
      if (hasDGA)    chain.push("DGA domains queried — malware beacon rotating C2 addresses");
      if (hasRareTLD)chain.push("Rare TLD domains queried — suspicious DNS activity");
      if (hasC2Net)  chain.push("Confirmed C2 signature corroborates DNS covert channel");
      conf = 0.80 + boost(hasDGA, hasRareTLD, hasC2Net);
    }

    // ── 15. COORDINATED RECON FROM KNOWN-BAD IP ──────────────────────────────
    else if (hasScan && hasTI) {
      title = "Coordinated Reconnaissance from Threat-Intel IP";
      chain = [
        "Known malicious IP conducting active port scanning",
        "Multiple services probed — pre-attack enumeration underway",
      ];
      if (hasSIP)    chain.push("VoIP/SIP infrastructure targeted — toll fraud risk");
      if (hasRDP)    chain.push("RDP scanning included — likely credential brute force to follow");
      if (hasSuspSSH)chain.push("Suspicious SSH client fingerprint — automated attack tooling");
      if (hasScanUA) chain.push("Known scanner user-agent detected in HTTP traffic");
      conf = 0.80 + boost(hasSIP, hasRDP, hasSuspSSH, hasScanUA);
    }

    // ── 16. VoIP SCANNING / TOLL FRAUD ───────────────────────────────────────
    else if (hasSIP && hasTI) {
      title = "VoIP Scanning from Blacklisted IP — Toll Fraud Risk";
      chain = [
        "Blacklisted IP targeting SIP/VoIP on port 5060",
        "SIPVicious 'friendly-scanner' tool fingerprint detected",
        "Credential harvesting for toll fraud likely objective",
      ];
      conf = 0.82;
    }

    // ── 17. EXPLOIT (standalone) ──────────────────────────────────────────────
    else if (hasExploit) {
      title = "Exploit Attempt Against Exposed Service";
      chain = [
        "Exploit signature fired — attacker targeting a known vulnerability",
      ];
      if (hasScan)   chain.push("Port scanning preceded exploit — deliberate target selection");
      if (hasTI)     chain.push("Source IP on threat intelligence blocklist");
      conf = 0.80 + boost(hasScan, hasTI);
    }

    // ── 18. CRYPTOMINING ──────────────────────────────────────────────────────
    else if (hasMine) {
      title = "Cryptocurrency Mining Detected";
      chain = [
        "Mining pool / Stratum protocol communication observed",
        "Host compute resources being hijacked for cryptomining",
      ];
      if (hasExec) chain.push("Miner binary dropped and executed on host");
      if (hasEvasion) chain.push("Security tools tampered with to persist miner");
      conf = 0.78 + boost(hasExec, hasEvasion);
    }

    // ── 19. LOLBIN + EVASION ──────────────────────────────────────────────────
    else if (hasLolbin && hasEvasion) {
      title = "Living-off-the-Land with Defense Evasion";
      chain = [
        "Native system binary abused to execute attacker code",
        "Security tooling disabled to allow undetected operation",
      ];
      if (hasC2)    chain.push("C2 channel established via LOLBIN");
      if (hasPers)  chain.push("Persistence installed using trusted binary");
      conf = 0.78 + boost(hasC2, hasPers);
    }

    // ── 20. SUDO / PRIVILEGE ESCALATION ON LINUX ─────────────────────────────
    else if (hasSudo && hasSuspCmd) {
      title = "Linux Privilege Escalation Attempt";
      chain = [
        "Sudo privilege escalation attempts or root session observed",
        "Suspicious Linux commands executed on host",
      ];
      if (hasBrute) chain.push("SSH brute force preceded escalation attempt");
      conf = 0.74 + boost(hasBrute);
    }

    // ── 21. SUSPICIOUS SSH ACTIVITY ───────────────────────────────────────────
    else if (hasSuspSSH && hasBrute) {
      title = "Automated SSH Attack with Tool Fingerprint";
      chain = [
        "Non-standard SSH client fingerprint detected (Nmap, Paramiko, libssh2)",
        "SSH brute force running in parallel — automated attack toolchain",
      ];
      if (hasTI) chain.push("Source IP on threat intelligence blocklist — known attacker");
      conf = 0.76 + boost(hasTI);
    }

    // ── 22. DATA EXFILTRATION ─────────────────────────────────────────────────
    else if (hasExfil && (hasC2 || hasTunnel || hasDNSTun)) {
      title = "Data Exfiltration in Progress";
      chain = [
        "Exfiltration signature detected — data leaving the network",
      ];
      if (hasTunnel) chain.push("Tunnel tool used to bypass egress DLP controls");
      if (hasDNSTun) chain.push("DNS used as covert exfiltration channel");
      if (hasC2)     chain.push("C2 channel active — attacker directing exfil operation");
      if (hasTor)    chain.push("Tor anonymization masking exfiltration destination");
      conf = 0.82 + boost(hasTunnel, hasDNSTun, hasC2, hasTor);
    }

    // ── 23. SCANNING + LEGACY PROTOCOL ABUSE ─────────────────────────────────
    else if (hasRecon && hasLegacy) {
      title = "Reconnaissance with Legacy Protocol Exploitation";
      chain = [
        "Active network scanning detecting open services",
        "Legacy protocols (SNMP, Telnet, TFTP) being probed or abused",
      ];
      if (hasTI) chain.push("Source on threat intelligence blocklist");
      conf = 0.68 + boost(hasTI);
    }

    // ── 24. ACCOUNT MANIPULATION ──────────────────────────────────────────────
    else if (hasAcctChg && (hasExec || hasLat || hasPers)) {
      title = "Account Manipulation for Persistence or Escalation";
      chain = [];
      if (hasAcctChg) chain.push("New account created or user added to privileged group");
      if (hasExec)    chain.push("Command execution observed alongside account changes");
      if (hasLat)     chain.push("Lateral movement — new account used to pivot");
      if (hasPers)    chain.push("Additional persistence mechanisms installed");
      conf = 0.76 + boost(hasExec, hasLat, hasPers);
    }

    // ── DEFAULT: promote any detection above confidence threshold ─────────────
    else {
      // Group related low-count detections by tag similarity before promoting singles
      const promoted = new Set();
      for (const d of dets) {
        if (promoted.has(d.rule_id)) continue;
        // Find companion detections that share a tag
        const companions = dets.filter(o =>
          o.rule_id !== d.rule_id &&
          (o.tags||[]).some(t => (d.tags||[]).includes(t)) &&
          o.confidence >= 0.55
        );
        if (companions.length > 0 && d.confidence >= 0.55) {
          const group = [d, ...companions];
          group.forEach(g => promoted.add(g.rule_id));
          const groupChain = group.map(g => g.description);
          incidents.push(buildInc(
            `${d.rule_name} + ${companions.length} related detection(s)`,
            host, group,
            Math.min(d.confidence + companions.length * 0.03, 0.92),
            groupChain
          ));
        } else if (d.confidence >= 0.60 && !promoted.has(d.rule_id)) {
          promoted.add(d.rule_id);
          incidents.push(buildInc(d.rule_name, host, [d], d.confidence, [d.description]));
        }
      }
      continue;
    }

    if (title) incidents.push(buildInc(title, host, dets, Math.min(conf, 0.99), chain));
  }

  // Sort by composite severity then confidence
  const sevOrder = { CRITICAL:3, HIGH:2, MEDIUM:1, LOW:0 };
  incidents.sort((a,b) =>
    (sevOrder[b.composite_severity]||0) - (sevOrder[a.composite_severity]||0) ||
    b.confidence_score - a.confidence_score
  );

  return incidents;
}

function buildInc(title, host, dets, confidence, chain) {
  const sevOrder = {LOW:0,MEDIUM:1,HIGH:2,CRITICAL:3};
  const composite = dets.reduce((b,d) => sevOrder[d.severity]>sevOrder[b]?d.severity:b,"LOW");
  const users = [...new Set(dets.map(d=>d.user).filter(Boolean))];
  return { id: Math.random().toString(36).slice(2,10).toUpperCase(), title, host,
    user: users[0]||null, detections: dets, confidence_score: Math.min(confidence,0.99),
    composite_severity: composite, attack_chain: chain,
    mitre_techniques: [...new Set(dets.flatMap(d=>d.mitre_techniques||[]))],
    mitre_tactics:    [...new Set(dets.flatMap(d=>d.mitre_tactics||[]))],
    source_types:     [...new Set(dets.map(d=>d.source_type))],
    first_seen: dets.map(d=>d.timestamp).filter(Boolean).sort()[0]||new Date().toISOString(),
    last_seen:  dets.map(d=>d.timestamp).filter(Boolean).sort().pop()||new Date().toISOString(),
    severity: null, risk_score: null, status: "pending", triage: null };
}

// ── AI Triage ─────────────────────────────────────────────────────────────────
async function triageWithAI(incident) {
  // Cap detections sent to AI — top 10 by confidence
  const topDets = [...incident.detections]
    .sort((a,b) => b.confidence - a.confidence)
    .slice(0, 10);

  const detText = topDets.map(d =>
    `  [${d.severity}][${d.rule_id}] ${d.rule_name}: ${d.description.slice(0,120)} (conf=${Math.round(d.confidence*100)}%)`
  ).join("\n");

  const chainText = incident.attack_chain
    .slice(0, 6)
    .map((s,i) => `  ${i+1}. ${s.slice(0,120)}`)
    .join("\n");

  // Only send scalar extra fields, capped tightly
  const rawSamples = topDets.slice(0,2).map(d => {
    const safe = {};
    for (const [k,v] of Object.entries(d.extra||{}))
      if (typeof v !== "object") safe[k] = String(v).slice(0,80);
    return JSON.stringify(safe).slice(0,150);
  }).join(" | ");

  const response = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: "claude-sonnet-4-20250514",
      max_tokens: 800,
      system: "You are a senior SOC analyst. Return ONLY valid JSON, no markdown, no preamble.",
      messages: [{ role: "user", content:
`Triage this security incident. Return ONLY JSON.

INCIDENT: ${incident.title.slice(0,100)}
HOST: ${incident.host} | SEVERITY: ${incident.composite_severity}
SOURCES: ${incident.source_types.join(",")} | CONFIDENCE: ${Math.round(incident.confidence_score*100)}%
DETECTIONS (${incident.detections.length} total, showing top ${topDets.length}):
${detText}
CHAIN:
${chainText}
MITRE: ${incident.mitre_techniques.slice(0,8).join(", ")}
CONTEXT: ${rawSamples}

JSON format:
{"severity":"CRITICAL|HIGH|MEDIUM|LOW","risk_score":<0-100>,"false_positive_probability":<0.0-1.0>,"summary":"<2-3 sentences>","attack_narrative":"<kill chain>","recommended_actions":["<action>","<action>","<action>","<action>"],"mitre_tactics":["<tactic>"],"analyst_notes":"<notes>"}`
      }]
    })
  });

  let data;
  try { data = await response.json(); }
  catch { throw new Error(`Response not JSON (HTTP ${response.status})`); }

  // Surface Anthropic-level errors (auth, rate limit, etc.)
  if (data.error) throw new Error(`Anthropic: ${data.error.type} — ${data.error.message}`);

  // Validate content array exists
  if (!data.content || !Array.isArray(data.content) || data.content.length === 0)
    throw new Error(`Empty response content. Keys received: ${Object.keys(data).join(", ")}`);

  const block = data.content.find(b => b.type === "text");
  if (!block) throw new Error(`No text block in response. Types: ${data.content.map(b=>b.type).join(", ")}`);

  let raw = block.text.trim();
  // Strip markdown fences if present
  raw = raw.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "").trim();
  // Extract first JSON object in case of surrounding prose
  const match = raw.match(/\{[\s\S]*\}/);
  if (!match) throw new Error(`No JSON object in model output: ${raw.slice(0, 200)}`);

  let result;
  try { result = JSON.parse(match[0]); }
  catch (e) { throw new Error(`JSON parse failed: ${e.message}`); }

  if (!result.severity || result.risk_score === undefined)
    throw new Error(`Incomplete triage fields: ${JSON.stringify(result).slice(0, 200)}`);

  return result;
}

// ── UI Primitives ─────────────────────────────────────────────────────────────
function Tag({ label, color=C.muted }) {
  return <span style={{ padding:"2px 7px", borderRadius:3, fontSize:10, background:`${color}18`,
    color, border:`1px solid ${color}30`, fontFamily:"monospace", whiteSpace:"nowrap" }}>{label}</span>;
}
function Pill({ label, color=C.muted }) {
  return <span style={{ padding:"3px 10px", borderRadius:20, fontSize:11, fontWeight:700,
    background:`${color}18`, color, border:`1px solid ${color}40` }}>{label}</span>;
}
function ScoreRing({ score, size=60 }) {
  if (!score) return null;
  const color = score>=80?C.CRITICAL:score>=60?C.HIGH:score>=35?C.MEDIUM:C.LOW;
  const r=(size/2)-5, circ=2*Math.PI*r;
  return (
    <div style={{ position:"relative", width:size, height:size, flexShrink:0 }}>
      <svg width={size} height={size} style={{ transform:"rotate(-90deg)" }}>
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={C.border} strokeWidth={4}/>
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color} strokeWidth={4}
          strokeDasharray={`${(score/100)*circ} ${circ}`} strokeLinecap="round"
          style={{ transition:"stroke-dasharray 0.8s ease" }}/>
      </svg>
      <div style={{ position:"absolute", inset:0, display:"flex", alignItems:"center",
        justifyContent:"center", fontSize:size*0.23, fontWeight:800, color, fontFamily:"monospace" }}>
        {score}
      </div>
    </div>
  );
}
function SL({ children }) {
  return <div style={{ fontSize:9, letterSpacing:3, color:C.muted, fontFamily:"monospace",
    textTransform:"uppercase", marginBottom:10 }}>{children}</div>;
}
function Card({ children, style={}, accent }) {
  return <div style={{ background:C.surface, border:`1px solid ${accent?SEV_BD(accent):C.border}`,
    borderRadius:10, padding:16, marginBottom:12, ...style }}>{children}</div>;
}

// ── Upload Screen ─────────────────────────────────────────────────────────────
function UploadScreen({ onProcess }) {
  const [dragging, setDragging]     = useState(false);
  const [files, setFiles]           = useState([]);
  const [processing, setProcessing] = useState(false);
  const [progress, setProgress]     = useState("");
  const [error, setError]           = useState("");
  const fileRef = useRef();

  const addFiles = incoming => {
    const valid = [...(incoming||[])].filter(f =>
      f.name.match(/\.(json|log|txt|xml|csv)$/i)||f.type.includes("json")||f.type.includes("text"));
    if (!valid.length) { setError("Unsupported type. Upload .json, .log, .txt, .xml, or .csv"); return; }
    setError("");
    setFiles(prev => { const ex=new Set(prev.map(f=>f.name)); return [...prev,...valid.filter(f=>!ex.has(f.name))]; });
  };

  const handleProcess = async () => {
    if (!files.length||processing) return;
    setProcessing(true); setError(""); resetDetState();
    try {
      const allEntries = [];
      for (const file of files) {
        setProgress(`Parsing ${file.name}…`);
        allEntries.push(...parseLogFile(file.name, await file.text()));
      }
      setProgress(`Running ${allEntries.length.toLocaleString()} entries through ${40} detection rules…`);
      await new Promise(r=>setTimeout(r,30));
      const allDetections = allEntries.flatMap(detectEntry);
      setProgress(`Correlating ${allDetections.length} detections into incidents…`);
      await new Promise(r=>setTimeout(r,20));
      const incidents = correlate(allDetections);
      setProgress(`Found ${incidents.length} incident(s). Running AI triage…`);
      onProcess({ incidents, totalEntries:allEntries.length, totalDetections:allDetections.length, files:files.map(f=>f.name) });
    } catch(err) { setError(`Error: ${err.message}`); setProcessing(false); }
  };

  const fmtSize = n => n>1048576?`${(n/1048576).toFixed(1)} MB`:`${(n/1024).toFixed(0)} KB`;

  return (
    <div style={{ display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center",
      minHeight:"100vh", background:C.bg, padding:32 }}>
      <style>{`@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.35}} *{box-sizing:border-box}`}</style>
      <div style={{ display:"flex", alignItems:"center", gap:12, marginBottom:40 }}>
        <div style={{ width:44, height:44, borderRadius:10,
          background:`linear-gradient(135deg,${C.CRITICAL},${C.HIGH})`,
          display:"flex", alignItems:"center", justifyContent:"center", fontSize:22 }}>⚡</div>
        <div>
          <div style={{ fontSize:22, fontWeight:800, letterSpacing:2, color:"#e8f0ff" }}>THREATHUNTER AI</div>
          <div style={{ fontSize:10, letterSpacing:4, color:C.muted, fontFamily:"monospace" }}>REAL-TIME SOC TRIAGE PLATFORM · 40 RULES</div>
        </div>
      </div>

      <div onDragOver={e=>{e.preventDefault();setDragging(true);}} onDragLeave={()=>setDragging(false)}
        onDrop={e=>{e.preventDefault();setDragging(false);addFiles(e.dataTransfer.files);}}
        onClick={()=>!processing&&fileRef.current.click()}
        style={{ width:"100%", maxWidth:600, border:`2px dashed ${dragging?C.accent:C.bright}`,
          borderRadius:14, padding:"48px 32px", textAlign:"center", cursor:processing?"default":"pointer",
          background:dragging?`${C.accent}08`:C.surface, transition:"all 0.2s", marginBottom:20 }}>
        <input ref={fileRef} type="file" multiple accept=".json,.log,.txt,.xml,.csv"
          style={{ display:"none" }} onChange={e=>addFiles(e.target.files)}/>
        <div style={{ fontSize:40, marginBottom:16 }}>{processing?"⟳":dragging?"📂":"📁"}</div>
        {processing ? (
          <div style={{ fontSize:14, color:C.accent, fontFamily:"monospace", animation:"pulse 1.4s infinite" }}>{progress}</div>
        ) : (
          <>
            <div style={{ fontSize:16, fontWeight:600, color:C.text, marginBottom:8 }}>Drop log files here or click to browse</div>
            <div style={{ fontSize:12, color:C.muted, lineHeight:1.8 }}>
              Suricata EVE JSON · Sysmon XML/JSON · Winlogbeat JSON<br/>
              Windows Security Event Log · Linux auth.log · Generic JSON/CSV
            </div>
          </>
        )}
      </div>

      {files.length>0&&(
        <div style={{ width:"100%", maxWidth:600, marginBottom:16 }}>
          <div style={{ fontSize:10, letterSpacing:2, color:C.muted, fontFamily:"monospace", marginBottom:8 }}>
            {files.length} FILE{files.length>1?"S":""} QUEUED
          </div>
          {files.map((f,i)=>(
            <div key={i} style={{ display:"flex", justifyContent:"space-between", alignItems:"center",
              padding:"8px 12px", background:C.surface, border:`1px solid ${C.border}`,
              borderRadius:6, marginBottom:5 }}>
              <div style={{ display:"flex", gap:10, alignItems:"center" }}>
                <span style={{ fontSize:14 }}>{f.name.endsWith(".json")?"📄":f.name.endsWith(".xml")?"📋":"📝"}</span>
                <div>
                  <div style={{ fontSize:12, color:C.text }}>{f.name}</div>
                  <div style={{ fontSize:10, color:C.muted, fontFamily:"monospace" }}>{fmtSize(f.size)}</div>
                </div>
              </div>
              {!processing&&<button onClick={e=>{e.stopPropagation();setFiles(p=>p.filter((_,j)=>j!==i));}}
                style={{ background:"none", border:"none", color:C.muted, cursor:"pointer", fontSize:18, padding:"0 4px" }}>×</button>}
            </div>
          ))}
        </div>
      )}

      {error&&<div style={{ width:"100%", maxWidth:600, padding:"10px 16px", background:`${C.CRITICAL}12`,
        border:`1px solid ${C.CRITICAL}40`, borderRadius:7, color:C.CRITICAL, fontSize:12, marginBottom:16 }}>⚠ {error}</div>}

      <button onClick={handleProcess} disabled={!files.length||processing}
        style={{ padding:"12px 36px",
          background:files.length&&!processing?`linear-gradient(135deg,${C.CRITICAL},${C.HIGH})`:C.border,
          border:"none", borderRadius:8, color:"#fff", fontSize:13, fontWeight:700,
          cursor:files.length&&!processing?"pointer":"default", letterSpacing:1 }}>
        {processing?"⟳  PROCESSING…":"⚡  ANALYZE LOGS"}
      </button>

      <div style={{ marginTop:36, display:"flex", gap:10, flexWrap:"wrap", justifyContent:"center" }}>
        {[["🛡️","Suricata EVE","Alerts, DNS, TLS, SSH, HTTP"],["🪟","Sysmon / Winlogbeat","Process, Registry, Network"],
          ["🔐","Windows Auth","Event IDs 4624/25/69/20/32"],["🐧","Linux Auth","auth.log / syslog"],
          ["🌐","Generic JSON","Any structured log"]
        ].map(([icon,label,hint])=>(
          <div key={label} style={{ textAlign:"center", padding:"10px 14px", background:C.surface,
            border:`1px solid ${C.border}`, borderRadius:8, minWidth:130 }}>
            <div style={{ fontSize:20, marginBottom:4 }}>{icon}</div>
            <div style={{ fontSize:11, color:C.text, fontWeight:600 }}>{label}</div>
            <div style={{ fontSize:9, color:C.muted, fontFamily:"monospace", marginTop:2 }}>{hint}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
export default function ThreatHunterUI() {
  const [screen, setScreen]     = useState("upload");
  const [alerts, setAlerts]     = useState([]);
  const [meta, setMeta]         = useState(null);
  const [selected, setSelected] = useState(null);
  const [tab, setTab]           = useState("triage");
  const [filter, setFilter]     = useState("ALL");
  const [triaging, setTriaging] = useState(null);
  const [aiError, setAiError]   = useState(null);

  const heuristicTriage = inc => {
    const w={LOW:20,MEDIUM:44,HIGH:68,CRITICAL:88};
    const score=Math.min((w[inc.composite_severity]||30)+inc.detections.length*3+Math.round(inc.confidence_score*10),99);
    const sev=score>=80?"CRITICAL":score>=60?"HIGH":score>=35?"MEDIUM":"LOW";
    return { severity:sev, risk_score:score, false_positive_probability:0.28,
      summary:`${sev} severity incident on ${inc.host}: ${inc.attack_chain[0]||inc.title}`,
      attack_narrative:inc.attack_chain.join(" → "),
      recommended_actions:["Investigate host immediately","Review all detections","Preserve evidence chain","Escalate to IR team if confirmed"],
      mitre_tactics:inc.mitre_tactics, analyst_notes:"Heuristic triage (AI unavailable)" };
  };

  const handleProcess = useCallback(async ({ incidents, totalEntries, totalDetections, files }) => {
    setAlerts(incidents); setMeta({ totalEntries, totalDetections, files });
    setSelected(incidents[0]?.id||null); setScreen("dashboard");
    setAiError(null);
    for (const inc of incidents) {
      setTriaging(inc.id);
      try {
        const result = await triageWithAI(inc);
        setAlerts(prev=>prev.map(a=>a.id===inc.id
          ?{...a,severity:result.severity,risk_score:result.risk_score,status:"triaged",triage:result}:a));
      } catch(err) {
        setAiError(err.message);
        const result = heuristicTriage(inc);
        setAlerts(prev=>prev.map(a=>a.id===inc.id
          ?{...a,severity:result.severity,risk_score:result.risk_score,status:"triaged",triage:{...result,_fallback:true}}:a));
      }
      await new Promise(r=>setTimeout(r,250));
    }
    setTriaging(null);
  }, []);

  const retriage = async id => {
    if (triaging) return;
    const inc=alerts.find(a=>a.id===id); if (!inc) return;
    setTriaging(id); setAiError(null);
    try {
      const result = await triageWithAI(inc);
      setAlerts(prev=>prev.map(a=>a.id===id
        ?{...a,severity:result.severity,risk_score:result.risk_score,status:"triaged",triage:result}:a));
    } catch(err) {
      setAiError(err.message);
      const result = heuristicTriage(inc);
      setAlerts(prev=>prev.map(a=>a.id===id
        ?{...a,severity:result.severity,risk_score:result.risk_score,status:"triaged",triage:{...result,_fallback:true}}:a));
    }
    setTriaging(null);
  };

  if (screen==="upload") return <UploadScreen onProcess={handleProcess}/>;

  const filtered = filter==="ALL"?alerts:filter==="PENDING"?alerts.filter(a=>!a.severity):alerts.filter(a=>a.severity===filter);
  const sel = alerts.find(a=>a.id===selected);
  const counts = { total:alerts.length, critical:alerts.filter(a=>a.severity==="CRITICAL").length,
    high:alerts.filter(a=>a.severity==="HIGH").length, triaged:alerts.filter(a=>a.severity).length,
    pending:alerts.filter(a=>!a.severity).length };

  return (
    <div style={{ fontFamily:"system-ui,sans-serif", background:C.bg, minHeight:"100vh", color:C.text, display:"flex", flexDirection:"column" }}>
      <style>{`
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.35}}
        @keyframes fadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
        @keyframes spin{to{transform:rotate(360deg)}}
        *{box-sizing:border-box}
        ::-webkit-scrollbar{width:3px}
        ::-webkit-scrollbar-thumb{background:${C.border};border-radius:2px}
        .hrow:hover{background:${C.raised}!important}
        .tbtn:hover{color:#fff!important}
        .abtn:hover{filter:brightness(1.2)}
      `}</style>

      <header style={{ background:C.surface, borderBottom:`1px solid ${C.border}`,
        padding:"10px 20px", display:"flex", alignItems:"center", justifyContent:"space-between",
        position:"sticky", top:0, zIndex:200 }}>
        <div style={{ display:"flex", alignItems:"center", gap:12 }}>
          <div style={{ width:32, height:32, borderRadius:8,
            background:`linear-gradient(135deg,${C.CRITICAL},${C.HIGH})`,
            display:"flex", alignItems:"center", justifyContent:"center", fontSize:16 }}>⚡</div>
          <div>
            <div style={{ fontSize:14, fontWeight:800, letterSpacing:1.5, color:"#e8f0ff" }}>THREATHUNTER AI</div>
            {meta&&<div style={{ fontSize:9, letterSpacing:2, color:C.muted, fontFamily:"monospace" }}>
              {meta.totalEntries.toLocaleString()} entries · {meta.totalDetections} detections · {meta.files.join(", ").slice(0,55)}
            </div>}
          </div>
        </div>
        <div style={{ display:"flex", gap:12, alignItems:"center" }}>
          {triaging&&<span style={{ fontSize:10, color:C.accent, fontFamily:"monospace", display:"flex", alignItems:"center", gap:5 }}>
            <span style={{ display:"inline-block", animation:"spin 1s linear infinite" }}>⟳</span> AI TRIAGING…
          </span>}
          {[["CRITICAL",C.CRITICAL,counts.critical],["HIGH",C.HIGH,counts.high],["PENDING",C.muted,counts.pending]].map(([l,c,n])=>(
            <span key={l} style={{ padding:"3px 9px", borderRadius:4, fontSize:10,
              background:`${c}12`, color:c, border:`1px solid ${c}30`, fontFamily:"monospace" }}>{n} {l}</span>
          ))}
          <button className="abtn" onClick={()=>{setScreen("upload");setAlerts([]);setMeta(null);}}
            style={{ padding:"5px 12px", background:C.raised, border:`1px solid ${C.border}`,
              borderRadius:6, color:C.muted, fontSize:11, cursor:"pointer", fontFamily:"monospace" }}>↑ Upload New</button>
        </div>
      </header>

      {aiError && (
        <div style={{ background:`${C.CRITICAL}15`, borderBottom:`1px solid ${C.CRITICAL}40`,
          padding:"8px 20px", display:"flex", justifyContent:"space-between", alignItems:"center" }}>
          <span style={{ fontSize:11, color:C.CRITICAL, fontFamily:"monospace" }}>
            ⚠ AI TRIAGE ERROR — {aiError}
          </span>
          <button onClick={()=>setAiError(null)}
            style={{ background:"none", border:"none", color:C.CRITICAL, cursor:"pointer", fontSize:16 }}>×</button>
        </div>
      )}
      <div style={{ display:"flex", flex:1, height:`calc(100vh - ${aiError?87:53}px)`, overflow:"hidden" }}>
        {/* Left panel */}
        <div style={{ width:285, borderRight:`1px solid ${C.border}`, background:C.surface, display:"flex", flexDirection:"column" }}>
          <div style={{ padding:"7px 10px", borderBottom:`1px solid ${C.border}`, display:"flex", gap:4, flexWrap:"wrap" }}>
            {["ALL","CRITICAL","HIGH","MEDIUM","LOW","PENDING"].map(f=>(
              <button key={f} onClick={()=>setFilter(f)}
                style={{ padding:"3px 8px", borderRadius:4, fontSize:10, cursor:"pointer",
                  border:`1px solid ${filter===f?SEV(["PENDING","ALL"].includes(f)?null:f):C.border}`,
                  background:filter===f?`${SEV(["PENDING","ALL"].includes(f)?null:f)}18`:"transparent",
                  color:filter===f?SEV(["PENDING","ALL"].includes(f)?null:f):C.muted, fontFamily:"monospace" }}>{f}</button>
            ))}
          </div>
          <div style={{ overflowY:"auto", flex:1 }}>
            {filtered.length===0&&<div style={{ padding:24, textAlign:"center", color:C.muted, fontSize:12 }}>No incidents match this filter</div>}
            {filtered.map(a=>(
              <div key={a.id} className="hrow" onClick={()=>{setSelected(a.id);setTab("triage");}}
                style={{ padding:"10px 13px", borderBottom:`1px solid ${C.border}`, cursor:"pointer",
                  animation:"fadeIn 0.3s ease", borderLeft:`3px solid ${SEV(a.severity)||C.bright}`,
                  background:selected===a.id?C.raised:"transparent", transition:"background 0.1s" }}>
                <div style={{ display:"flex", justifyContent:"space-between", marginBottom:3 }}>
                  <span style={{ fontSize:10, color:C.muted, fontFamily:"monospace" }}>{a.id}</span>
                  {a.severity?<Pill label={a.severity} color={SEV(a.severity)}/>
                    :triaging===a.id
                      ?<span style={{ fontSize:10, color:C.accent, fontFamily:"monospace", display:"flex", alignItems:"center", gap:4 }}>
                        <span style={{ display:"inline-block", animation:"spin 1s linear infinite" }}>⟳</span> TRIAGING
                      </span>
                      :<Pill label="PENDING" color={C.muted}/>}
                </div>
                <div style={{ fontSize:12, color:a.severity?C.text:C.muted, lineHeight:1.35, marginBottom:3 }}>{a.title}</div>
                <div style={{ fontSize:10, color:C.muted, display:"flex", gap:5 }}>
                  <span>{a.host}</span>·<span>{(a.source_types||[]).join(", ")}</span>
                  {a.risk_score&&<span>· <b style={{ color:SEV(a.severity) }}>{a.risk_score}</b></span>}
                </div>
              </div>
            ))}
          </div>
          <div style={{ borderTop:`1px solid ${C.border}`, padding:12 }}>
            {[["Total incidents",counts.total,C.text],["Triaged",counts.triaged,C.green],["Pending",counts.pending,C.MEDIUM]].map(([l,v,c])=>(
              <div key={l} style={{ display:"flex", justifyContent:"space-between", fontSize:11, marginBottom:6 }}>
                <span style={{ color:C.muted }}>{l}</span>
                <span style={{ color:c, fontFamily:"monospace", fontWeight:600 }}>{v}</span>
              </div>
            ))}
            <div style={{ height:3, borderRadius:2, background:C.border, overflow:"hidden", marginTop:6 }}>
              <div style={{ height:"100%", borderRadius:2, background:C.green,
                width:`${counts.total?(counts.triaged/counts.total)*100:0}%`, transition:"width 0.5s" }}/>
            </div>
          </div>
        </div>

        {/* Center */}
        <div style={{ flex:1, overflowY:"auto", background:C.bg }}>
          {!sel?(
            <div style={{ display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center",
              height:"100%", gap:10, color:C.dim }}>
              <span style={{ fontSize:40 }}>⚡</span>
              <span style={{ fontSize:11, letterSpacing:3, fontFamily:"monospace" }}>SELECT AN INCIDENT</span>
            </div>
          ):(
            <div style={{ padding:20, animation:"fadeIn 0.3s ease" }}>
              <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:16 }}>
                <div style={{ flex:1, minWidth:0, marginRight:16 }}>
                  <div style={{ fontSize:9, letterSpacing:3, color:C.muted, fontFamily:"monospace", marginBottom:5 }}>
                    INCIDENT · {sel.id}{sel.status==="pending"&&<span style={{ color:C.MEDIUM }}> · PENDING AI TRIAGE</span>}
                  </div>
                  <div style={{ fontSize:20, fontWeight:800, color:"#e8f0ff", lineHeight:1.2, marginBottom:8 }}>{sel.title}</div>
                  <div style={{ display:"flex", gap:6, flexWrap:"wrap" }}>
                    <Tag label={sel.host} color={C.accent}/>
                    {sel.user&&<Tag label={sel.user} color={C.muted}/>}
                    {(sel.source_types||[]).map(s=><Tag key={s} label={s.toUpperCase()} color={C.dim}/>)}
                    <Tag label={`${Math.round((sel.confidence_score||0)*100)}% conf`} color={C.muted}/>
                    <Tag label={`${sel.detections?.length||0} detections`} color={C.muted}/>
                  </div>
                </div>
                <div style={{ display:"flex", alignItems:"center", gap:14, flexShrink:0 }}>
                  <ScoreRing score={sel.risk_score}/>
                  {sel.triage?(
                    <div style={{ textAlign:"center" }}>
                      <div style={{ fontSize:18, fontWeight:800, color:SEV(sel.severity) }}>{sel.severity}</div>
                      <div style={{ fontSize:9, color:C.muted, fontFamily:"monospace" }}>SEVERITY</div>
                      <button className="abtn" onClick={()=>retriage(sel.id)} disabled={!!triaging}
                        style={{ marginTop:6, padding:"4px 10px", background:C.raised, border:`1px solid ${C.border}`,
                          borderRadius:5, color:C.muted, fontSize:10, cursor:"pointer", fontFamily:"monospace" }}>re-triage</button>
                    </div>
                  ):(
                    triaging===sel.id
                      ?<div style={{ fontSize:12, color:C.accent, fontFamily:"monospace", animation:"pulse 1.2s infinite" }}>⟳ ANALYZING</div>
                      :<button className="abtn" onClick={()=>retriage(sel.id)} disabled={!!triaging}
                        style={{ padding:"8px 16px", background:C.purple, border:"none", borderRadius:7,
                          color:"#fff", fontSize:11, fontWeight:700, cursor:"pointer" }}>⚡ AI TRIAGE</button>
                  )}
                </div>
              </div>

              <div style={{ display:"flex", borderBottom:`1px solid ${C.border}`, marginBottom:16 }}>
                {[["triage","TRIAGE ANALYSIS"],["raw","RAW DETECTIONS"]].map(([t,label])=>(
                  <button key={t} className="tbtn" onClick={()=>setTab(t)}
                    style={{ padding:"7px 16px", background:"transparent", border:"none",
                      borderBottom:`2px solid ${tab===t?C.accent:"transparent"}`,
                      color:tab===t?"#fff":C.muted, fontSize:10, cursor:"pointer",
                      letterSpacing:1.5, fontFamily:"monospace" }}>{label}</button>
                ))}
              </div>

              {tab==="triage"&&(
                <div style={{ animation:"fadeIn 0.25s ease" }}>
                  <Card>
                    <SL>Attack Chain</SL>
                    {(sel.attack_chain||[]).map((step,i)=>(
                      <div key={i} style={{ display:"flex", gap:10, marginBottom:8, alignItems:"flex-start" }}>
                        <span style={{ fontFamily:"monospace", fontSize:10, color:C.accent, width:16, flexShrink:0, marginTop:1 }}>{i+1}.</span>
                        <span style={{ fontSize:12, color:C.text }}>{step}</span>
                      </div>
                    ))}
                  </Card>
                  {(sel.mitre_techniques?.length>0||sel.mitre_tactics?.length>0)&&(
                    <Card>
                      <SL>MITRE ATT&amp;CK</SL>
                      <div style={{ display:"flex", gap:6, flexWrap:"wrap", marginBottom:6 }}>
                        {(sel.mitre_techniques||[]).map(t=><Tag key={t} label={t} color={C.CRITICAL}/>)}
                      </div>
                      <div style={{ display:"flex", gap:6, flexWrap:"wrap" }}>
                        {(sel.mitre_tactics||[]).map(t=><Tag key={t} label={t} color={C.HIGH}/>)}
                      </div>
                    </Card>
                  )}
                  {sel.triage?(
                    <Card accent={sel.severity} style={{ background:SEV_BG(sel.severity) }}>
                      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:12 }}>
                        <SL>🤖 AI Triage Result</SL>
                        <div style={{ textAlign:"right" }}>
                          <div style={{ fontSize:9, color:C.muted, fontFamily:"monospace" }}>FP PROBABILITY</div>
                          <div style={{ fontSize:16, fontWeight:800, color:(sel.triage.false_positive_probability||0)<0.2?C.green:C.MEDIUM }}>
                            {Math.round((sel.triage.false_positive_probability||0)*100)}%
                          </div>
                        </div>
                      </div>
                      <p style={{ fontSize:13, lineHeight:1.8, color:C.text, marginBottom:14 }}>{sel.triage.summary}</p>
                      {sel.triage.attack_narrative&&sel.triage.attack_narrative!==sel.triage.summary&&(
                        <div style={{ marginBottom:14, padding:"10px 14px", background:C.raised, borderRadius:7, border:`1px solid ${C.border}` }}>
                          <SL>Attack Narrative</SL>
                          <p style={{ fontSize:12, color:C.muted, lineHeight:1.75, margin:0 }}>{sel.triage.attack_narrative}</p>
                        </div>
                      )}
                      <SL>Recommended Actions</SL>
                      {(sel.triage.recommended_actions||[]).map((a,i)=>(
                        <div key={i} style={{ display:"flex", gap:8, marginBottom:7, alignItems:"flex-start" }}>
                          <span style={{ color:SEV(sel.severity), fontSize:12, flexShrink:0 }}>→</span>
                          <span style={{ fontSize:12, color:C.text }}>{a}</span>
                        </div>
                      ))}
                      {sel.triage.analyst_notes&&(
                        <div style={{ marginTop:12, padding:"10px 12px", background:C.raised, borderRadius:6, border:`1px solid ${C.border}` }}>
                          <div style={{ fontSize:9, color:C.muted, fontFamily:"monospace", marginBottom:4 }}>ANALYST NOTES</div>
                          <p style={{ fontSize:11, color:C.muted, lineHeight:1.65, margin:0 }}>{sel.triage.analyst_notes}</p>
                        </div>
                      )}
                    </Card>
                  ):(
                    <Card>
                      <div style={{ textAlign:"center", padding:"24px 0", color:C.muted }}>
                        <div style={{ fontSize:28, marginBottom:8 }}>🤖</div>
                        <div style={{ fontSize:12 }}>
                          {triaging===sel.id?"AI triage in progress…":"Click ⚡ AI TRIAGE to analyze this incident"}
                        </div>
                      </div>
                    </Card>
                  )}
                </div>
              )}

              {tab==="raw"&&(
                <div style={{ animation:"fadeIn 0.25s ease" }}>
                  {(sel.detections||[]).map((d,i)=>(
                    <Card key={i} accent={d.severity}>
                      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:8 }}>
                        <div>
                          <span style={{ fontSize:10, fontFamily:"monospace", color:SEV(d.severity) }}>{d.rule_id}</span>
                          <span style={{ fontSize:12, fontWeight:600, color:C.text, marginLeft:8 }}>{d.rule_name}</span>
                        </div>
                        <div style={{ display:"flex", gap:6 }}>
                          <Tag label={d.source_type?.toUpperCase()} color={C.accent}/>
                          <Tag label={`${Math.round((d.confidence||0)*100)}%`} color={C.muted}/>
                          <Pill label={d.severity} color={SEV(d.severity)}/>
                        </div>
                      </div>
                      <p style={{ fontSize:12, color:C.text, marginBottom:10, lineHeight:1.6 }}>{d.description}</p>
                      <div style={{ display:"flex", gap:5, flexWrap:"wrap", marginBottom:d.extra&&Object.keys(d.extra).length>0?8:0 }}>
                        {(d.tags||[]).map(t=><Tag key={t} label={t} color={C.muted}/>)}
                        {(d.mitre_techniques||[]).map(t=><Tag key={t} label={t} color={C.CRITICAL}/>)}
                      </div>
                      {d.extra&&Object.keys(d.extra).length>0&&(
                        <pre style={{ fontSize:11, color:C.muted, background:C.raised, padding:"8px 10px",
                          borderRadius:5, margin:0, overflow:"auto", border:`1px solid ${C.border}`, whiteSpace:"pre-wrap" }}>
                          {JSON.stringify(d.extra,null,2)}
                        </pre>
                      )}
                    </Card>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right rail */}
        <div style={{ width:190, borderLeft:`1px solid ${C.border}`, background:C.surface,
          padding:14, display:"flex", flexDirection:"column", gap:18, overflowY:"auto" }}>
          <div>
            <SL>Severity breakdown</SL>
            {[["CRITICAL",C.CRITICAL],["HIGH",C.HIGH],["MEDIUM",C.MEDIUM],["LOW",C.LOW]].map(([s,c])=>{
              const n=alerts.filter(a=>a.severity===s).length;
              return (
                <div key={s} style={{ marginBottom:10 }}>
                  <div style={{ display:"flex", justifyContent:"space-between", fontSize:10, marginBottom:3 }}>
                    <span style={{ color:c, fontFamily:"monospace" }}>{s}</span><span style={{ color:C.text }}>{n}</span>
                  </div>
                  <div style={{ height:3, background:C.border, borderRadius:2 }}>
                    <div style={{ width:`${alerts.length?(n/alerts.length)*100:0}%`, height:"100%",
                      background:c, borderRadius:2, transition:"width 0.5s" }}/>
                  </div>
                </div>
              );
            })}
          </div>
          <div>
            <SL>Sources</SL>
            {["suricata","sysmon","winauth","linux_auth","generic"].map(src=>{
              const n=alerts.filter(a=>(a.source_types||[]).includes(src)).length;
              return n>0?(<div key={src} style={{ display:"flex", justifyContent:"space-between", fontSize:11, marginBottom:6 }}>
                <span style={{ color:C.muted }}>{src}</span><span style={{ color:C.text, fontFamily:"monospace" }}>{n}</span>
              </div>):null;
            })}
          </div>
          <div>
            <SL>Rule coverage</SL>
            {[["Endpoint",["RULE-001","RULE-002","RULE-003","RULE-004","RULE-008","RULE-009","RULE-013","RULE-014","RULE-015","RULE-016","RULE-017","RULE-018","RULE-019","RULE-020","RULE-021","RULE-022","RULE-023","RULE-038","RULE-039","RULE-040"],C.purple],
              ["Network",["RULE-005","RULE-006","RULE-007","RULE-010","RULE-011","RULE-012","RULE-024","RULE-025","RULE-026","RULE-027","RULE-028","RULE-029","RULE-030","RULE-031","RULE-032","RULE-033","RULE-034","RULE-035"],C.accent],
              ["Linux",["RULE-036","RULE-037"],C.green]
            ].map(([label,rules,color])=>{
              const fired=new Set(alerts.flatMap(a=>a.detections?.map(d=>d.rule_id)||[]));
              const hit=rules.filter(r=>fired.has(r)).length;
              return(<div key={label} style={{ marginBottom:8 }}>
                <div style={{ display:"flex", justifyContent:"space-between", fontSize:10, marginBottom:3 }}>
                  <span style={{ color:C.muted }}>{label}</span>
                  <span style={{ color, fontFamily:"monospace" }}>{hit}/{rules.length}</span>
                </div>
                <div style={{ height:3, background:C.border, borderRadius:2 }}>
                  <div style={{ width:`${(hit/rules.length)*100}%`, height:"100%", background:color, borderRadius:2 }}/>
                </div>
              </div>);
            })}
          </div>
          <div>
            <SL>Triage progress</SL>
            <div style={{ position:"relative", width:80, height:80, margin:"0 auto 8px" }}>
              <svg viewBox="0 0 80 80" width="100%" height="100%" style={{ transform:"rotate(-90deg)" }}>
                <circle cx={40} cy={40} r={32} fill="none" stroke={C.border} strokeWidth={6}/>
                <circle cx={40} cy={40} r={32} fill="none" stroke={C.green} strokeWidth={6} strokeLinecap="round"
                  strokeDasharray={`${counts.total?(counts.triaged/counts.total)*201:0} 201`}
                  style={{ transition:"stroke-dasharray 0.6s" }}/>
              </svg>
              <div style={{ position:"absolute", inset:0, display:"flex", alignItems:"center", justifyContent:"center" }}>
                <span style={{ fontSize:17, fontWeight:800, color:C.green, fontFamily:"monospace" }}>
                  {counts.total?Math.round((counts.triaged/counts.total)*100):0}%
                </span>
              </div>
            </div>
            <div style={{ textAlign:"center", fontSize:10, color:C.muted, fontFamily:"monospace" }}>{counts.triaged} / {counts.total}</div>
          </div>
          {meta&&(
            <div>
              <SL>File stats</SL>
              <div style={{ fontSize:11, color:C.muted, lineHeight:1.9 }}>
                <div>{meta.totalEntries.toLocaleString()} log entries</div>
                <div>{meta.totalDetections} raw detections</div>
                <div>{counts.total} incidents found</div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
