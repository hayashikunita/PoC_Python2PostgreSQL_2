import React, { useState } from 'react';
import axios from 'axios';

function NmapScan() {
  const [cidr, setCidr] = useState('');
  const [arp, setArp] = useState(true);
  const [noDns, setNoDns] = useState(true);
  const [maxHosts, setMaxHosts] = useState(4096);
  const [timeoutS, setTimeoutS] = useState(120);

  const [data, setData] = useState(null);
  const [portsData, setPortsData] = useState(null);
  const [cidrPortsData, setCidrPortsData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [portsLoading, setPortsLoading] = useState(false);
  const [cidrPortsLoading, setCidrPortsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [copyStatus, setCopyStatus] = useState(null);

  const [target, setTarget] = useState('');
  const [ports, setPorts] = useState('');
  const [topPorts, setTopPorts] = useState(100);
  const [useTopPorts, setUseTopPorts] = useState(true);
  const [serviceVersion, setServiceVersion] = useState(true);
  const [osDetect, setOsDetect] = useState(false);
  const [traceRoute, setTraceRoute] = useState(false);

  const [cidrPortsCidr, setCidrPortsCidr] = useState('');
  const [cidrPortsTopPorts, setCidrPortsTopPorts] = useState(50);
  const [cidrPortsUseTopPorts, setCidrPortsUseTopPorts] = useState(true);
  const [cidrPortsPorts, setCidrPortsPorts] = useState('');
  const [cidrPortsServiceVersion, setCidrPortsServiceVersion] = useState(false);
  const [cidrPortsOsDetect, setCidrPortsOsDetect] = useState(false);
  const [cidrPortsTraceRoute, setCidrPortsTraceRoute] = useState(false);
  const [cidrPortsMaxHosts, setCidrPortsMaxHosts] = useState(1024);
  const [cidrPortsTimeoutS, setCidrPortsTimeoutS] = useState(600);
  const [cidrPortsConfirm, setCidrPortsConfirm] = useState(false);

  const runScan = async () => {
    const c = (cidr || '').trim();
    if (!c) {
      setError('CIDRを入力してください（例: 192.168.1.0/24）');
      return;
    }

    setLoading(true);
    setError(null);
    setCopyStatus(null);
    setPortsData(null);
    setCidrPortsData(null);

    try {
      const res = await axios.get('/api/network/lan-devices/nmap', {
        params: {
          cidr: c,
          arp: !!arp,
          no_dns: !!noDns,
          max_hosts: Number(maxHosts) || 4096,
          timeout_s: Number(timeoutS) || 120,
        },
      });

      if (res?.data && res.data.ok === false) {
        throw new Error(res.data.error || 'nmap failed');
      }

      setData(res.data);
    } catch (err) {
      setError('nmapスキャンに失敗しました: ' + (err?.response?.data?.detail || err.message));
    } finally {
      setLoading(false);
    }
  };

  const runPortScan = async () => {
    const t = (target || '').trim();
    if (!t) {
      setError('target（private IPv4）を入力してください（例: 192.168.1.1）');
      return;
    }

    setPortsLoading(true);
    setError(null);
    setCopyStatus(null);
    setData(null);
    setCidrPortsData(null);

    try {
      const params = {
        target: t,
        no_dns: !!noDns,
        timeout_s: Number(timeoutS) || 180,
        service_version: !!serviceVersion,
        os_detect: !!osDetect,
        traceroute: !!traceRoute,
      };

      if (useTopPorts) {
        params.top_ports = Number(topPorts) || 100;
      } else {
        const p = (ports || '').trim();
        if (!p) {
          setError('ports か top-ports のどちらかを指定してください');
          setPortsLoading(false);
          return;
        }
        params.ports = p;
      }

      const res = await axios.get('/api/network/nmap/ports', { params });
      if (res?.data && res.data.ok === false) {
        throw new Error(res.data.error || 'nmap failed');
      }
      setPortsData(res.data);
    } catch (err) {
      setError('ポートスキャンに失敗しました: ' + (err?.response?.data?.detail || err.message));
    } finally {
      setPortsLoading(false);
    }
  };

  const runCidrPortScan = async () => {
    const c = (cidrPortsCidr || '').trim();
    if (!c) {
      setError('CIDRを入力してください（例: 192.168.1.0/24）');
      return;
    }
    if (!cidrPortsConfirm) {
      setError('CIDRポートスキャンは負荷が高いので、確認チェックをONにしてください');
      return;
    }

    setCidrPortsLoading(true);
    setError(null);
    setCopyStatus(null);
    setData(null);
    setPortsData(null);

    try {
      const params = {
        cidr: c,
        no_dns: true,
        timeout_s: Number(cidrPortsTimeoutS) || 600,
        max_hosts: Number(cidrPortsMaxHosts) || 1024,
        service_version: !!cidrPortsServiceVersion,
        os_detect: !!cidrPortsOsDetect,
        traceroute: !!cidrPortsTraceRoute,
      };

      if (cidrPortsUseTopPorts) {
        params.top_ports = Number(cidrPortsTopPorts) || 50;
      } else {
        const p = (cidrPortsPorts || '').trim();
        if (!p) {
          setError('ports か top-ports のどちらかを指定してください');
          setCidrPortsLoading(false);
          return;
        }
        params.ports = p;
        params.top_ports = null;
      }

      const res = await axios.get('/api/network/nmap/network-ports', { params });
      if (res?.data && res.data.ok === false) {
        throw new Error(res.data.error || 'nmap failed');
      }
      setCidrPortsData(res.data);
    } catch (err) {
      setError('CIDRポートスキャンに失敗しました: ' + (err?.response?.data?.detail || err.message));
    } finally {
      setCidrPortsLoading(false);
    }
  };

  const copyJson = async () => {
    const payload = cidrPortsData || portsData || data;
    if (!payload) return;
    const text = JSON.stringify(payload, null, 2);
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

  const hosts = Array.isArray(data?.hosts) ? data.hosts : [];
  const portHosts = Array.isArray(portsData?.hosts) ? portsData.hosts : [];
  const cidrHosts = Array.isArray(cidrPortsData?.hosts) ? cidrPortsData.hosts : [];
  const cidrUpHosts = cidrHosts.filter((h) => h && h.status === 'up');
  const cidrUpWithOpen = cidrUpHosts.filter((h) => (h.open_port_count || 0) > 0);

  return (
    <div className="card">
      <h2>🗺️ NMAPスキャン（-sn）</h2>

      <div className="packet-explanation">
        <div style={{ lineHeight: '1.8' }}>
          <div>nmapのPingスキャン（<strong>-sn</strong>）で、指定CIDR内の生存ホストを一覧化します。</div>
          <div>※ nmap（および必要に応じてNpcap）がインストール済みで、PATHに <strong>nmap.exe</strong> がある必要があります。</div>
          <div>※ Private CIDRのみ許可しています（RFC1918）。</div>
        </div>
      </div>

      {error ? <div className="error">{error}</div> : null}

      <div className="info-item">
        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginRight: '14px' }}>
          <strong>CIDR:</strong>
          <input
            value={cidr}
            onChange={(e) => setCidr(e.target.value)}
            placeholder="例: 192.168.1.0/24"
            style={{ width: '240px', padding: '8px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface-2)' }}
          />
        </label>

        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginRight: '14px' }}>
          <strong>max_hosts:</strong>
          <input
            type="number"
            min={16}
            max={65535}
            value={maxHosts}
            onChange={(e) => setMaxHosts(e.target.value)}
            style={{ width: '120px', padding: '8px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface-2)' }}
          />
        </label>

        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginRight: '14px' }}>
          <strong>timeout_s:</strong>
          <input
            type="number"
            min={5}
            max={600}
            value={timeoutS}
            onChange={(e) => setTimeoutS(e.target.value)}
            style={{ width: '120px', padding: '8px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface-2)' }}
          />
        </label>

        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginRight: '14px', color: 'var(--muted)' }}>
          <input type="checkbox" checked={arp} onChange={(e) => setArp(e.target.checked)} />
          ARP(-PR)
        </label>

        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', color: 'var(--muted)' }}>
          <input type="checkbox" checked={noDns} onChange={(e) => setNoDns(e.target.checked)} />
          no DNS(-n)
        </label>
      </div>

      <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
        <button className="button" onClick={runScan} disabled={loading}>
          {loading ? 'スキャン中...' : '▶ nmapスキャン実行'}
        </button>
        <button className="button" onClick={copyJson} disabled={!data}>
          📋 結果をコピー（JSON）
        </button>
        {copyStatus && <span style={{ color: 'var(--muted)', alignSelf: 'center' }}>{copyStatus}</span>}
      </div>

      {data ? (
        <div className="info-item" style={{ marginTop: '10px' }}>
          <div><strong>収集時刻:</strong> {data.collected_at || '-'}</div>
          <div><strong>CIDR:</strong> {data.cidr || '-'}</div>
          <div><strong>検出数:</strong> {data?.summary?.count ?? '-'} / <span style={{ color: 'var(--muted)' }}>elapsed {data?.summary?.elapsed_ms ?? '-'}ms</span></div>
          {data.stderr ? <div style={{ color: 'var(--muted)' }}><strong>stderr:</strong> {data.stderr}</div> : null}
        </div>
      ) : null}

      <h3>検出ホスト</h3>
      {hosts.length === 0 ? (
        <div className="info-item">まだ結果がありません（CIDRを入れて実行してください）</div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', border: '1px solid var(--border)' }}>
            <thead>
              <tr style={{ background: 'var(--surface-2)' }}>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>IP</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>ホスト名</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>MAC</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>Vendor</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>プライベート</th>
              </tr>
            </thead>
            <tbody>
              {hosts.map((h, idx) => (
                <tr key={idx} style={{ background: 'var(--surface)' }}>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}>{h.ip}</td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>{h.hostname || ''}</td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}>{h.mac || ''}</td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>{h.vendor || ''}</td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>{String(!!h.is_private)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h2 style={{ marginTop: '1.25rem' }}>🔎 NMAPポートスキャン（TCP）</h2>

      <div className="packet-explanation">
        <div style={{ lineHeight: '1.8' }}>
          <div>指定IPに対してTCPポートスキャンを実行します（既定はConnect scan: <strong>-sT</strong>）。</div>
          <div>サービス判定（<strong>-sV</strong>）/ OS推定（<strong>-O</strong>）/ traceroute（<strong>--traceroute</strong>）も任意で実行できます。</div>
        </div>
      </div>

      <div className="info-item">
        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginRight: '14px' }}>
          <strong>target:</strong>
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="例: 192.168.1.1"
            style={{ width: '240px', padding: '8px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface-2)' }}
          />
        </label>

        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginRight: '14px', color: 'var(--muted)' }}>
          <input type="checkbox" checked={useTopPorts} onChange={(e) => setUseTopPorts(e.target.checked)} />
          top-ports
        </label>

        {useTopPorts ? (
          <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginRight: '14px' }}>
            <strong>top_ports:</strong>
            <input
              type="number"
              min={1}
              max={1000}
              value={topPorts}
              onChange={(e) => setTopPorts(e.target.value)}
              style={{ width: '120px', padding: '8px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface-2)' }}
            />
          </label>
        ) : (
          <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginRight: '14px' }}>
            <strong>ports:</strong>
            <input
              value={ports}
              onChange={(e) => setPorts(e.target.value)}
              placeholder="例: 22,80,443 / 1-1024"
              style={{ width: '240px', padding: '8px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface-2)' }}
            />
          </label>
        )}

        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginRight: '14px', color: 'var(--muted)' }}>
          <input type="checkbox" checked={serviceVersion} onChange={(e) => setServiceVersion(e.target.checked)} />
          -sV
        </label>
        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginRight: '14px', color: 'var(--muted)' }}>
          <input type="checkbox" checked={osDetect} onChange={(e) => setOsDetect(e.target.checked)} />
          -O
        </label>
        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', color: 'var(--muted)' }}>
          <input type="checkbox" checked={traceRoute} onChange={(e) => setTraceRoute(e.target.checked)} />
          traceroute
        </label>
      </div>

      <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
        <button className="button" onClick={runPortScan} disabled={portsLoading}>
          {portsLoading ? 'スキャン中...' : '▶ ポートスキャン実行'}
        </button>
        <button className="button" onClick={copyJson} disabled={!portsData && !data}>
          📋 結果をコピー（JSON）
        </button>
        {copyStatus && <span style={{ color: 'var(--muted)', alignSelf: 'center' }}>{copyStatus}</span>}
      </div>

      {portsData ? (
        <div className="info-item" style={{ marginTop: '10px' }}>
          <div><strong>収集時刻:</strong> {portsData.collected_at || '-'}</div>
          <div><strong>target:</strong> {portsData.target || '-'}</div>
          <div><strong>elapsed:</strong> {portsData.elapsed_ms ?? '-'}ms</div>
          {portsData.stderr ? <div style={{ color: 'var(--muted)' }}><strong>stderr:</strong> {portsData.stderr}</div> : null}
          {portsData?.hosts?.[0]?.os?.name ? (
            <div style={{ color: 'var(--muted)' }}>
              <strong>OS(推定):</strong> {portsData.hosts[0].os.name} ({portsData.hosts[0].os.accuracy}%)
            </div>
          ) : null}
        </div>
      ) : null}

      <h3>ポート一覧</h3>
      {portHosts.length === 0 ? (
        <div className="info-item">まだ結果がありません（targetを入れて実行してください）</div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', border: '1px solid var(--border)' }}>
            <thead>
              <tr style={{ background: 'var(--surface-2)' }}>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>IP</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>ポート</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>状態</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>サービス</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>詳細</th>
              </tr>
            </thead>
            <tbody>
              {portHosts.flatMap((h, idxH) => {
                const portsList = Array.isArray(h.ports) ? h.ports : [];
                if (portsList.length === 0) {
                  return (
                    <tr key={`h-${idxH}`} style={{ background: 'var(--surface)' }}>
                      <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}>{h.ip}</td>
                      <td style={{ padding: '10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)' }} colSpan={4}>
                        ポート情報なし
                      </td>
                    </tr>
                  );
                }

                return portsList.map((p, idxP) => (
                  <tr key={`p-${idxH}-${idxP}`} style={{ background: 'var(--surface)' }}>
                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}>{h.ip}</td>
                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}>
                      {p.proto}/{p.port}
                    </td>
                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>
                      {p.state || ''}
                    </td>
                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}>
                      {p.service || ''}
                    </td>
                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>
                      {[p.product, p.version, p.extrainfo].filter(Boolean).join(' ')}
                    </td>
                  </tr>
                ));
              })}
            </tbody>
          </table>
        </div>
      )}

      <h2 style={{ marginTop: '1.25rem' }}>🧭 CIDRポートスキャン（TCP / 範囲）</h2>

      <div className="packet-explanation">
        <div style={{ lineHeight: '1.8' }}>
          <div><strong>注意:</strong> CIDR全体のポートスキャンは負荷が高いです。小さいレンジ（/24程度）＋ top-ports 50〜100 を推奨します。</div>
          <div>Private CIDRのみ許可し、ホスト数の上限（max_hosts）でガードしています。</div>
        </div>
      </div>

      <div className="info-item">
        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginRight: '14px' }}>
          <strong>CIDR:</strong>
          <input
            value={cidrPortsCidr}
            onChange={(e) => setCidrPortsCidr(e.target.value)}
            placeholder="例: 192.168.1.0/24"
            style={{ width: '240px', padding: '8px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface-2)' }}
          />
        </label>

        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginRight: '14px' }}>
          <strong>max_hosts:</strong>
          <input
            type="number"
            min={16}
            max={65535}
            value={cidrPortsMaxHosts}
            onChange={(e) => setCidrPortsMaxHosts(e.target.value)}
            style={{ width: '120px', padding: '8px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface-2)' }}
          />
        </label>

        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginRight: '14px' }}>
          <strong>timeout_s:</strong>
          <input
            type="number"
            min={10}
            max={3600}
            value={cidrPortsTimeoutS}
            onChange={(e) => setCidrPortsTimeoutS(e.target.value)}
            style={{ width: '120px', padding: '8px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface-2)' }}
          />
        </label>
      </div>

      <div className="info-item">
        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginRight: '14px', color: 'var(--muted)' }}>
          <input type="checkbox" checked={cidrPortsUseTopPorts} onChange={(e) => setCidrPortsUseTopPorts(e.target.checked)} />
          top-ports
        </label>

        {cidrPortsUseTopPorts ? (
          <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginRight: '14px' }}>
            <strong>top_ports:</strong>
            <input
              type="number"
              min={1}
              max={200}
              value={cidrPortsTopPorts}
              onChange={(e) => setCidrPortsTopPorts(e.target.value)}
              style={{ width: '120px', padding: '8px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface-2)' }}
            />
          </label>
        ) : (
          <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginRight: '14px' }}>
            <strong>ports:</strong>
            <input
              value={cidrPortsPorts}
              onChange={(e) => setCidrPortsPorts(e.target.value)}
              placeholder="例: 22,80,443 / 1-1024"
              style={{ width: '240px', padding: '8px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface-2)' }}
            />
          </label>
        )}

        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginRight: '14px', color: 'var(--muted)' }}>
          <input type="checkbox" checked={cidrPortsServiceVersion} onChange={(e) => setCidrPortsServiceVersion(e.target.checked)} />
          -sV
        </label>
        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginRight: '14px', color: 'var(--muted)' }}>
          <input type="checkbox" checked={cidrPortsOsDetect} onChange={(e) => setCidrPortsOsDetect(e.target.checked)} />
          -O
        </label>
        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', color: 'var(--muted)' }}>
          <input type="checkbox" checked={cidrPortsTraceRoute} onChange={(e) => setCidrPortsTraceRoute(e.target.checked)} />
          traceroute
        </label>
      </div>

      <div className="info-item">
        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', color: 'var(--muted)' }}>
          <input type="checkbox" checked={cidrPortsConfirm} onChange={(e) => setCidrPortsConfirm(e.target.checked)} />
          私はこのCIDRポートスキャンが高負荷であることを理解しました
        </label>
      </div>

      <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
        <button className="button" onClick={runCidrPortScan} disabled={cidrPortsLoading}>
          {cidrPortsLoading ? 'スキャン中...' : '▶ CIDRポートスキャン実行'}
        </button>
        <button className="button" onClick={copyJson} disabled={!cidrPortsData && !portsData && !data}>
          📋 結果をコピー（JSON）
        </button>
        {copyStatus && <span style={{ color: 'var(--muted)', alignSelf: 'center' }}>{copyStatus}</span>}
      </div>

      {cidrPortsData ? (
        <div className="info-item" style={{ marginTop: '10px' }}>
          <div><strong>収集時刻:</strong> {cidrPortsData.collected_at || '-'}</div>
          <div><strong>CIDR:</strong> {cidrPortsData.cidr || '-'}</div>
          <div><strong>UP:</strong> {cidrPortsData?.summary?.up_count ?? '-'} / <strong>openあり:</strong> {cidrPortsData?.summary?.up_with_open_ports ?? '-'}</div>
          <div><strong>elapsed:</strong> {cidrPortsData.elapsed_ms ?? '-'}ms</div>
          {cidrPortsData.stderr ? <div style={{ color: 'var(--muted)' }}><strong>stderr:</strong> {cidrPortsData.stderr}</div> : null}
        </div>
      ) : null}

      <h3>CIDR結果（openありのホスト）</h3>
      {cidrUpWithOpen.length === 0 ? (
        <div className="info-item">まだ結果がありません（CIDRを入れて実行してください）</div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', border: '1px solid var(--border)' }}>
            <thead>
              <tr style={{ background: 'var(--surface-2)' }}>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>IP</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>open数</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>openポート</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>MAC</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>Vendor</th>
              </tr>
            </thead>
            <tbody>
              {cidrUpWithOpen.map((h, idx) => {
                const openPorts = Array.isArray(h.open_ports) ? h.open_ports : [];
                const portStr = openPorts
                  .map((p) => `${p.proto}/${p.port}${p.service ? `(${p.service})` : ''}`)
                  .join(', ');
                return (
                  <tr key={idx} style={{ background: 'var(--surface)' }}>
                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}>{h.ip}</td>
                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>{h.open_port_count ?? 0}</td>
                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}>{portStr}</td>
                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}>{h.mac || ''}</td>
                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>{h.vendor || ''}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {Array.isArray((portsData || data)?.notes) && (portsData || data).notes.length > 0 ? (
        <div style={{ marginTop: '1rem' }}>
          <h3>注意</h3>
          {(portsData || data).notes.map((t, idx) => (
            <div key={idx} className="info-item" style={{ color: 'var(--muted)' }}>{t}</div>
          ))}
        </div>
      ) : null}

      {Array.isArray(cidrPortsData?.notes) && cidrPortsData.notes.length > 0 ? (
        <div style={{ marginTop: '1rem' }}>
          <h3>注意（CIDR）</h3>
          {cidrPortsData.notes.map((t, idx) => (
            <div key={idx} className="info-item" style={{ color: 'var(--muted)' }}>{t}</div>
          ))}
        </div>
      ) : null}
    </div>
  );
}

export default NmapScan;
