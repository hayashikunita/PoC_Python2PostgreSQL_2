import React, { useEffect, useState } from 'react';
import axios from 'axios';

function LanDevices() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [snmpData, setSnmpData] = useState(null);
  const [nmapData, setNmapData] = useState(null);

  const [maxHosts, setMaxHosts] = useState(256);
  const [timeoutMs, setTimeoutMs] = useState(250);
  const [maxConcurrency, setMaxConcurrency] = useState(64);
  const [copyStatus, setCopyStatus] = useState(null);

  const [resolveNames, setResolveNames] = useState(true);
  const [resolveVendors, setResolveVendors] = useState(true);
  const [pingCheck, setPingCheck] = useState(false);

  const [portScanCache, setPortScanCache] = useState({});
  const [portScanTopPorts, setPortScanTopPorts] = useState(50);

  const [snmpHost, setSnmpHost] = useState('');
  const [snmpCommunity, setSnmpCommunity] = useState('public');
  const [snmpLoading, setSnmpLoading] = useState(false);

  const [nmapCidr, setNmapCidr] = useState('');
  const [nmapArp, setNmapArp] = useState(true);
  const [nmapNoDns, setNmapNoDns] = useState(true);
  const [nmapMaxHosts, setNmapMaxHosts] = useState(4096);
  const [nmapTimeoutS, setNmapTimeoutS] = useState(120);
  const [nmapLoading, setNmapLoading] = useState(false);

  const fetchDevices = async (sweep) => {
    setLoading(true);
    setError(null);
    setCopyStatus(null);
    try {
      const res = await axios.get('/api/network/lan-devices', {
        params: {
          sweep: !!sweep,
          max_hosts: Number(maxHosts) || 256,
          timeout_ms: Number(timeoutMs) || 250,
          max_concurrency: Number(maxConcurrency) || 64,
          resolve_names: !!resolveNames,
          resolve_vendors: !!resolveVendors,
          // External vendor APIs are rate-limited; keep this low.
          vendor_timeout_ms: 2000,
          vendor_max_concurrency: 2,
          ping_check: !!pingCheck,
          ping_timeout_ms: 600,
          ping_max_concurrency: 64,
        },
      });
      setData(res.data);
    } catch (err) {
      setError('LAN機器一覧の取得に失敗しました: ' + (err?.response?.data?.detail || err.message));
    } finally {
      setLoading(false);
    }
  };

  const scanPortsForIp = async (ip) => {
    const target = String(ip || '').trim();
    if (!target) return;

    setPortScanCache((prev) => ({
      ...prev,
      [target]: { ...(prev?.[target] || {}), loading: true, error: null },
    }));

    try {
      const res = await axios.get('/api/network/nmap/ports', {
        params: {
          target,
          top_ports: Number(portScanTopPorts) || 50,
          service_version: false,
          os_detect: false,
          traceroute: false,
          no_dns: true,
          timeout_s: 120,
        },
      });

      setPortScanCache((prev) => ({
        ...prev,
        [target]: { loading: false, error: null, data: res.data },
      }));
    } catch (err) {
      setPortScanCache((prev) => ({
        ...prev,
        [target]: { loading: false, error: (err?.response?.data?.detail || err.message), data: null },
      }));
    }
  };

  const getOpenPortNumbers = (n) => {
    const ip = String(n?.ip || '');
    const cached = portScanCache?.[ip]?.data;
    const host = Array.isArray(cached?.hosts) ? cached.hosts.find((h) => String(h?.ip || '') === ip) : null;
    const ports = Array.isArray(host?.ports) ? host.ports : [];
    const open = ports.filter((p) => p && p.state === 'open' && p.port != null);
    const nums = open.map((p) => Number(p.port)).filter((x) => Number.isFinite(x));
    return Array.from(new Set(nums));
  };

  const formatOpenPorts = (n) => {
    const ip = String(n?.ip || '');
    const cached = portScanCache?.[ip]?.data;
    const host = Array.isArray(cached?.hosts) ? cached.hosts.find((h) => String(h?.ip || '') === ip) : null;
    const ports = Array.isArray(host?.ports) ? host.ports : [];
    const open = ports.filter((p) => p && p.state === 'open' && p.port != null);
    const entries = open
      .map((p) => ({ port: p.port, service: p.service }))
      .filter((x) => x.port != null);
    entries.sort((a, b) => a.port - b.port);
    return entries.length ? entries.map((e) => (e.service ? `${e.port}/${e.service}` : String(e.port))).join(', ') : '';
  };

  const inferRiskFlags = (n) => {
    const ports = getOpenPortNumbers(n);
    if (!ports || ports.length === 0) return '';
    const set = new Set(ports);

    // Operationally useful flags (TCP). Severity is heuristic.
    const critical = [];
    const high = [];
    const medium = [];

    // Remote admin / legacy cleartext
    if (set.has(23)) critical.push('TELNET');
    if (set.has(21)) high.push('FTP');
    if (set.has(3389)) critical.push('RDP');
    if (set.has(5900)) high.push('VNC');

    // Windows exposure
    if (set.has(445) || set.has(139) || set.has(135)) high.push('SMB/RPC');

    // Databases / caches (often not intended to be open broadly)
    if (set.has(1433) || set.has(1521) || set.has(3306) || set.has(5432) || set.has(27017) || set.has(9200) || set.has(6379) || set.has(11211)) high.push('DB/CACHE');

    // Web/admin panels
    if (set.has(80) || set.has(8080) || set.has(8000)) medium.push('HTTP');
    if (set.has(443) || set.has(8443)) medium.push('HTTPS');

    // SSH is common but still admin surface
    if (set.has(22)) medium.push('SSH');

    // Others
    if (set.has(25) || set.has(587)) medium.push('SMTP');

    const uniq = (arr) => Array.from(new Set(arr));
    const c = uniq(critical);
    const h = uniq(high);
    const m = uniq(medium);

    const parts = [];
    if (c.length) parts.push(`CRITICAL:${c.join('/')}`);
    if (h.length) parts.push(`HIGH:${h.join('/')}`);
    if (m.length) parts.push(`MED:${m.join('/')}`);
    return parts.join(' ');
  };

  const fetchSnmp = async () => {
    const host = (snmpHost || '').trim();
    const comm = (snmpCommunity || '').trim();
    if (!host || !comm) {
      setError('SNMPの host / community を入力してください');
      return;
    }

    setSnmpLoading(true);
    setError(null);
    try {
      const res = await axios.get('/api/network/lan-devices/snmp', {
        params: {
          host,
          community: comm,
        },
      });
      setSnmpData(res.data);
    } catch (err) {
      setError('SNMP取得に失敗しました: ' + (err?.response?.data?.detail || err.message));
    } finally {
      setSnmpLoading(false);
    }
  };

  const fetchNmap = async () => {
    const cidr = (nmapCidr || '').trim();
    if (!cidr) {
      setError('nmap の CIDR を入力してください');
      return;
    }

    setNmapLoading(true);
    setError(null);
    try {
      const res = await axios.get('/api/network/lan-devices/nmap', {
        params: {
          cidr,
          arp: !!nmapArp,
          no_dns: !!nmapNoDns,
          max_hosts: Number(nmapMaxHosts) || 4096,
          timeout_s: Number(nmapTimeoutS) || 120,
        },
      });
      if (res?.data && res.data.ok === false) {
        throw new Error(res.data.error || 'nmap failed');
      }
      setNmapData(res.data);
    } catch (err) {
      setError('nmap スキャンに失敗しました: ' + (err?.response?.data?.detail || err.message));
    } finally {
      setNmapLoading(false);
    }
  };

  useEffect(() => {
    fetchDevices(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    // 初回だけ推定CIDRをセット
    if (!nmapCidr && data && Array.isArray(data.interfaces)) {
      const firstPrivate = data.interfaces.find((i) => i && i.cidr && i.is_private);
      if (firstPrivate && firstPrivate.cidr) setNmapCidr(firstPrivate.cidr);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data]);

  const copyJson = async () => {
    if (!data) return;
    const text = JSON.stringify(data, null, 2);
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        ta.parentNode.removeChild(ta);
      }
      setCopyStatus('✅ コピーしました');
    } catch (e) {
      setCopyStatus('❌ コピーに失敗しました: ' + e.message);
    }
  };

  if (loading && !data) return <div className="loading">読み込み中...</div>;
  if (!data) return <div className="error">{error || 'データがありません'}</div>;

  const baseNeighbors = Array.isArray(data.neighbors) ? data.neighbors : [];
  const snmpNeighbors = Array.isArray(snmpData?.neighbors) ? snmpData.neighbors : [];
  const nmapHosts = Array.isArray(nmapData?.hosts) ? nmapData.hosts : [];
  const neighbors = (() => {
    // Merge by IP (nmapはMAC無しがあり得るため)
    const map = new Map();
    for (const n of baseNeighbors) {
      const k = String(n.ip || '');
      if (!k) continue;
      map.set(k, { ...n, sources: ['local'] });
    }
    for (const n of snmpNeighbors) {
      const k = String(n.ip || '');
      if (!k) continue;
      if (map.has(k)) {
        const cur = map.get(k);
        const sources = Array.isArray(cur.sources) ? cur.sources.slice() : [];
        if (!sources.includes('snmp')) sources.push('snmp');
        map.set(k, { ...cur, mac: cur.mac || n.mac, hostname: cur.hostname || n.hostname, vendor: cur.vendor || n.vendor, sources });
      } else {
        map.set(k, { ...n, sources: ['snmp'] });
      }
    }

    for (const h of nmapHosts) {
      const ip = String(h.ip || '');
      if (!ip) continue;
      const n = {
        interface: '',
        subnet: '',
        first_seen: '',
        last_seen: '',
        ping_ok: undefined,
        ping_rtt_ms: undefined,
        device_type: '',
        ip,
        is_private: h.is_private,
        mac: h.mac || '',
        hostname: h.hostname || '',
        vendor: h.vendor || '',
        state: h.is_up ? 'up' : '',
      };
      if (map.has(ip)) {
        const cur = map.get(ip);
        const sources = Array.isArray(cur.sources) ? cur.sources.slice() : [];
        if (!sources.includes('nmap')) sources.push('nmap');
        map.set(ip, { ...cur, mac: cur.mac || n.mac, hostname: cur.hostname || n.hostname, vendor: cur.vendor || n.vendor, sources });
      } else {
        map.set(ip, { ...n, sources: ['nmap'] });
      }
    }

    return Array.from(map.values()).sort((a, b) => String(a.ip || '').localeCompare(String(b.ip || '')));
  })();
  const interfaces = Array.isArray(data.interfaces) ? data.interfaces : [];

  return (
    <div className="card">
      <h2>🖧 LAN機器一覧（IP / MAC）</h2>

      {error ? (
        <div className="error" style={{ marginTop: '10px' }}>{error}</div>
      ) : null}

      <div className="packet-explanation">
        <div style={{ lineHeight: '1.8' }}>
          <div>ARP/Neighbor テーブルから、LAN内の近隣機器を best-effort で一覧化します。</div>
          <div>通信履歴がない機器は表示されない場合があります。</div>
        </div>
      </div>

      <div className="info-item" style={{ color: 'var(--muted)', lineHeight: '1.8' }}>
        <div>使い方:</div>
        <div>1) まず「再取得」で last_seen / subnet / type が埋まります</div>
        <div>2) 生存確認したいときだけ「Ping確認」をONにして再取得（台数が多いと時間がかかります）</div>
        <div>3) 気になる端末だけ「ポートスキャン」を押して Open ports / 危険フラグを埋める</div>
      </div>

      <div className="info-item">
        <div><strong>収集時刻:</strong> {data.collected_at || '-'}</div>
        <div><strong>ホスト名:</strong> {data.hostname || '-'}</div>
        <div><strong>Windows:</strong> {String(!!data.is_windows)}</div>
      </div>

      <h3>ローカルIF（推定サブネット）</h3>
      {interfaces.length === 0 ? (
        <div className="info-item">インターフェース情報がありません</div>
      ) : (
        interfaces.map((i, idx) => (
          <div key={idx} className="info-item">
            <div><strong>{i.name}</strong> {i.is_up ? '(UP)' : '(DOWN)'}</div>
            <div style={{ color: 'var(--muted)' }}>{i.ip} / {i.netmask} ({i.cidr})</div>
            <div style={{ color: 'var(--muted)' }}>プライベート: {String(!!i.is_private)}</div>
          </div>
        ))
      )}

      <div className="info-item">
        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginRight: '14px' }}>
          <strong>max_hosts:</strong>
          <input
            type="number"
            min={16}
            max={4096}
            value={maxHosts}
            onChange={(e) => setMaxHosts(e.target.value)}
            style={{ width: '120px', padding: '8px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface-2)' }}
          />
        </label>
        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center' }}>
          <strong>timeout_ms:</strong>
          <input
            type="number"
            min={100}
            max={2000}
            value={timeoutMs}
            onChange={(e) => setTimeoutMs(e.target.value)}
            style={{ width: '120px', padding: '8px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface-2)' }}
          />
        </label>

        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginLeft: '14px' }}>
          <strong>並列:</strong>
          <input
            type="number"
            min={1}
            max={256}
            value={maxConcurrency}
            onChange={(e) => setMaxConcurrency(e.target.value)}
            style={{ width: '100px', padding: '8px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface-2)' }}
          />
        </label>

        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginLeft: '14px', color: 'var(--muted)' }}>
          <input type="checkbox" checked={resolveNames} onChange={(e) => setResolveNames(e.target.checked)} />
          ホスト名解決（逆引き）
        </label>

        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginLeft: '14px', color: 'var(--muted)' }}>
          <input type="checkbox" checked={resolveVendors} onChange={(e) => setResolveVendors(e.target.checked)} />
          メーカー名推定（外部API）
        </label>

        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginLeft: '14px', color: 'var(--muted)' }}>
          <input type="checkbox" checked={pingCheck} onChange={(e) => setPingCheck(e.target.checked)} />
          Ping確認（到達性/RRT）
        </label>
      </div>

      <div className="info-item" style={{ color: 'var(--muted)' }}>
        ポート要約/危険フラグは、各行の「ポートスキャン」で取得します（top-ports を使用）。
        <span style={{ marginLeft: '12px' }}>
          top-ports:
          <input
            type="number"
            min={10}
            max={200}
            value={portScanTopPorts}
            onChange={(e) => setPortScanTopPorts(e.target.value)}
            style={{ width: '90px', marginLeft: '8px', padding: '8px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface-2)' }}
          />
        </span>
      </div>

      <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
        <button className="button" onClick={() => fetchDevices(false)}>🔄 再取得</button>
        <button className="button" onClick={() => fetchDevices(true)}>🔍 スキャン（Ping sweep）</button>
        <button className="button" onClick={fetchSnmp} disabled={snmpLoading}>
          {snmpLoading ? 'SNMP取得中...' : '📡 SNMP（ルータ/スイッチ）から取得'}
        </button>
        <button className="button" onClick={fetchNmap} disabled={nmapLoading}>
          {nmapLoading ? 'nmapスキャン中...' : '🗺️ nmap（-sn）でスキャン'}
        </button>
        <button className="button" onClick={copyJson} disabled={!data}>📋 結果をコピー（JSON）</button>
        {copyStatus && <span style={{ color: 'var(--muted)', alignSelf: 'center' }}>{copyStatus}</span>}
      </div>

      <div className="info-item">
        <div style={{ color: 'var(--muted)', marginBottom: '8px' }}>
          SNMPはルータ/スイッチ側で有効化が必要です（SNMP v2c / community）。
        </div>
        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginRight: '14px' }}>
          <strong>SNMP host:</strong>
          <input
            value={snmpHost}
            onChange={(e) => setSnmpHost(e.target.value)}
            placeholder="例: 192.168.1.1"
            style={{ width: '220px', padding: '8px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface-2)' }}
          />
        </label>
        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center' }}>
          <strong>community:</strong>
          <input
            value={snmpCommunity}
            onChange={(e) => setSnmpCommunity(e.target.value)}
            style={{ width: '180px', padding: '8px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface-2)' }}
          />
        </label>
        {snmpData?.sysName?.sysName ? (
          <div style={{ marginTop: '8px', color: 'var(--muted)' }}>
            SNMP sysName: {snmpData.sysName.sysName}
          </div>
        ) : null}
      </div>

      <div className="info-item">
        <div style={{ color: 'var(--muted)', marginBottom: '8px' }}>
          nmap は別途インストールが必要です（PATHに nmap.exe）。同一LANの場合はARP(-PR)が有効です。
        </div>
        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginRight: '14px' }}>
          <strong>CIDR:</strong>
          <input
            value={nmapCidr}
            onChange={(e) => setNmapCidr(e.target.value)}
            placeholder="例: 192.168.1.0/24"
            style={{ width: '220px', padding: '8px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface-2)' }}
          />
        </label>

        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginRight: '14px' }}>
          <strong>max_hosts:</strong>
          <input
            type="number"
            min={16}
            max={65535}
            value={nmapMaxHosts}
            onChange={(e) => setNmapMaxHosts(e.target.value)}
            style={{ width: '120px', padding: '8px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface-2)' }}
          />
        </label>

        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginRight: '14px' }}>
          <strong>timeout_s:</strong>
          <input
            type="number"
            min={5}
            max={600}
            value={nmapTimeoutS}
            onChange={(e) => setNmapTimeoutS(e.target.value)}
            style={{ width: '120px', padding: '8px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface-2)' }}
          />
        </label>

        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginRight: '14px', color: 'var(--muted)' }}>
          <input type="checkbox" checked={nmapArp} onChange={(e) => setNmapArp(e.target.checked)} />
          ARP(-PR)
        </label>
        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', color: 'var(--muted)' }}>
          <input type="checkbox" checked={nmapNoDns} onChange={(e) => setNmapNoDns(e.target.checked)} />
          no DNS(-n)
        </label>

        {nmapData?.summary?.count != null ? (
          <div style={{ marginTop: '8px', color: 'var(--muted)' }}>
            nmap: {nmapData.summary.count} hosts (elapsed {nmapData.summary.elapsed_ms}ms)
          </div>
        ) : null}
      </div>

      <h3>近隣機器</h3>
      {neighbors.length === 0 ? (
        <div className="info-item">近隣テーブルが空です（スキャンを試してください）</div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', border: '1px solid var(--border)' }}>
            <thead>
              <tr style={{ background: 'var(--surface-2)' }}>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>IF</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>サブネット</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>IP</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>ホスト名</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>メーカー</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>種別</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>Last seen</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>Ping</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>RTT</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>Open ports</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>危険フラグ</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>プライベート</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>MAC</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>状態</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>ソース</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>操作</th>
              </tr>
            </thead>
            <tbody>
              {neighbors.map((n, idx) => (
                <tr key={idx} style={{ background: 'var(--surface)' }}>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}>{n.interface || ''}</td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>{n.subnet || ''}</td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}>{n.ip}</td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}>{n.hostname || ''}</td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}>{n.vendor || ''}</td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}>{n.device_type || ''}</td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>{n.last_seen || ''}</td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}>
                    {n.ping_ok === true ? 'OK' : (n.ping_ok === false ? 'NG' : '')}
                  </td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>
                    {n.ping_rtt_ms != null ? `${n.ping_rtt_ms}ms` : ''}
                  </td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}>{formatOpenPorts(n)}</td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>{inferRiskFlags(n)}</td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>{String(!!n.is_private)}</td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}>{n.mac}</td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>{n.state || ''}</td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>
                    {Array.isArray(n.sources) ? n.sources.join(', ') : (n.source || '')}
                  </td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}>
                    <button
                      className="button"
                      onClick={() => scanPortsForIp(n.ip)}
                      disabled={!!portScanCache?.[String(n.ip || '')]?.loading}
                      style={{ padding: '6px 10px' }}
                    >
                      {portScanCache?.[String(n.ip || '')]?.loading ? 'スキャン中...' : 'ポートスキャン'}
                    </button>
                    {portScanCache?.[String(n.ip || '')]?.error ? (
                      <div style={{ marginTop: '6px', color: 'var(--danger)' }}>{String(portScanCache[String(n.ip || '')].error)}</div>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {Array.isArray(data.notes) && data.notes.length > 0 && (
        <div style={{ marginTop: '1rem' }}>
          <h3>注意</h3>
          {data.notes.map((t, idx) => (
            <div key={idx} className="info-item" style={{ color: 'var(--muted)' }}>{t}</div>
          ))}
        </div>
      )}
    </div>
  );
}

export default LanDevices;
