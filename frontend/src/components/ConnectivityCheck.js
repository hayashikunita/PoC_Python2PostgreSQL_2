import React, { useState } from 'react';
import axios from 'axios';

function ConnectivityCheck() {
  const [pingTargets, setPingTargets] = useState('8.8.8.8');
  const [dnsTargets, setDnsTargets] = useState('www.google.com');
  const [httpTargets, setHttpTargets] = useState('https://www.google.com/generate_204');
  const [useProxy, setUseProxy] = useState(true);
  const [deepChecks, setDeepChecks] = useState(true);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const [copyStatus, setCopyStatus] = useState(null);

  const splitLines = (text) => {
    return (text || '')
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
  };

  const runChecks = async () => {
    setLoading(true);
    setError(null);
    setCopyStatus(null);
    try {
      const payload = {
        ping_targets: splitLines(pingTargets),
        dns_targets: splitLines(dnsTargets),
        http_targets: splitLines(httpTargets),
        use_proxy: useProxy,
        deep_checks: deepChecks,
      };
      const res = await axios.post('/api/diagnostics/connectivity', payload);
      setResult(res.data);
    } catch (err) {
      setError('疎通チェックに失敗しました: ' + (err?.response?.data?.detail || err.message));
    } finally {
      setLoading(false);
    }
  };

  const copyJson = async () => {
    if (!result) return;
    const text = JSON.stringify(result, null, 2);
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

  const Badge = ({ ok }) => (
    <span
      style={{
        padding: '2px 8px',
        borderRadius: '999px',
        fontSize: '12px',
        fontWeight: 700,
        border: '1px solid var(--border)',
        background: 'var(--surface-2)',
        color: ok ? 'var(--accent-strong)' : 'var(--muted)',
      }}
    >
      {ok ? 'OK' : 'NG'}
    </span>
  );

  const renderRows = (title, items) => {
    const arr = Array.isArray(items) ? items : [];
    return (
      <div style={{ marginTop: '1rem' }}>
        <h3 style={{ color: 'var(--accent)', marginBottom: '0.5rem' }}>{title}</h3>
        {arr.length === 0 ? (
          <div className="info-item">結果がありません</div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', border: '1px solid var(--border)' }}>
              <thead>
                <tr style={{ background: 'var(--surface-2)' }}>
                  <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>対象</th>
                  <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>結果</th>
                  <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>詳細</th>
                </tr>
              </thead>
              <tbody>
                {arr.map((r, idx) => (
                  <tr key={idx} style={{ background: 'var(--surface)' }}>
                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}>{r.target}</td>
                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}>
                      <Badge ok={!!r.ok} />
                      {typeof r.elapsed_ms === 'number' ? (
                        <span style={{ marginLeft: '8px', color: 'var(--muted)' }}>{r.elapsed_ms}ms</span>
                      ) : null}
                    </td>
                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>
                      {r.error ? r.error : r.status_code ? `HTTP ${r.status_code}` : ''}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="card">
      <h2>🧪 疎通チェック（Ping / DNS / HTTP）</h2>

      <div className="packet-explanation">
        <div style={{ lineHeight: '1.8' }}>
          <div>Ping: ICMP疎通</div>
          <div>DNS: 名前解決</div>
          <div>HTTP: Web到達（プロキシ影響も確認可能）</div>
        </div>
      </div>

      {error && <div className="error">{error}</div>}

      <div className="info-item">
        <strong>Ping 対象（改行区切り）</strong>
        <textarea
          value={pingTargets}
          onChange={(e) => setPingTargets(e.target.value)}
          rows={2}
          style={{ width: '100%', marginTop: '8px', padding: '10px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface-2)' }}
        />
      </div>

      <div className="info-item">
        <strong>DNS 対象（改行区切り）</strong>
        <textarea
          value={dnsTargets}
          onChange={(e) => setDnsTargets(e.target.value)}
          rows={2}
          style={{ width: '100%', marginTop: '8px', padding: '10px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface-2)' }}
        />
      </div>

      <div className="info-item">
        <strong>HTTP 対象URL（改行区切り）</strong>
        <textarea
          value={httpTargets}
          onChange={(e) => setHttpTargets(e.target.value)}
          rows={2}
          style={{ width: '100%', marginTop: '8px', padding: '10px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface-2)' }}
        />
        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginTop: '10px', color: 'var(--muted)' }}>
          <input type="checkbox" checked={useProxy} onChange={(e) => setUseProxy(e.target.checked)} />
          プロキシ設定を使用（環境変数など）
        </label>

        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginTop: '10px', color: 'var(--muted)' }}>
          <input type="checkbox" checked={deepChecks} onChange={(e) => setDeepChecks(e.target.checked)} />
          詳細モード（GW/DNSサーバ/PAC/TLS/tracert）
        </label>
      </div>

      <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', marginTop: '0.5rem' }}>
        <button className="button" onClick={runChecks} disabled={loading}>
          {loading ? '実行中...' : '▶️ 疎通チェック実行'}
        </button>
        <button className="button" onClick={copyJson} disabled={!result}>
          📋 結果をコピー（JSON）
        </button>
        {copyStatus && <span style={{ color: 'var(--muted)', alignSelf: 'center' }}>{copyStatus}</span>}
      </div>

      {result && (
        <>
          {renderRows('Ping', result?.results?.ping)}
          {renderRows('DNS', result?.results?.dns)}
          {renderRows('HTTP', result?.results?.http)}

          {result?.results?.deep && (
            <div style={{ marginTop: '1.5rem' }}>
              <h3 style={{ color: 'var(--accent)', marginBottom: '0.5rem' }}>詳細（切り分け補助）</h3>

              <div className="info-item">
                <div><strong>Windows:</strong> {String(!!result?.results?.deep?.is_windows)}</div>
                <div><strong>Default GW:</strong> {result?.results?.deep?.default_gateway?.default_gateway || '-'}</div>
                <div style={{ color: 'var(--muted)' }}>
                  {result?.results?.deep?.default_gateway?.source ? `取得元: ${result.results.deep.default_gateway.source}` : ''}
                </div>
              </div>

              {result?.results?.deep?.gateway_ping && (
                <div className="info-item">
                  <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                    <strong>GW疎通:</strong>
                    <Badge ok={!!result.results.deep.gateway_ping.ok} />
                    {typeof result.results.deep.gateway_ping.elapsed_ms === 'number' ? (
                      <span style={{ color: 'var(--muted)' }}>{result.results.deep.gateway_ping.elapsed_ms}ms</span>
                    ) : null}
                  </div>
                </div>
              )}

              <div style={{ marginTop: '1rem' }}>
                <h3 style={{ color: 'var(--accent)', marginBottom: '0.5rem' }}>DNSサーバ（どこに聞いているか）</h3>
                <div className="info-item">
                  <strong>DNS Servers:</strong> {Array.isArray(result?.results?.deep?.dns_servers?.servers) ? result.results.deep.dns_servers.servers.join(', ') : '-'}
                </div>

                {Array.isArray(result?.results?.deep?.dns_by_server) && result.results.deep.dns_by_server.length > 0 && (
                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', border: '1px solid var(--border)' }}>
                      <thead>
                        <tr style={{ background: 'var(--surface-2)' }}>
                          <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>名前</th>
                          <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>DNSサーバ</th>
                          <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>結果</th>
                          <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>応答</th>
                        </tr>
                      </thead>
                      <tbody>
                        {result.results.deep.dns_by_server.map((r, idx) => (
                          <tr key={idx} style={{ background: 'var(--surface)' }}>
                            <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}>{r.target}</td>
                            <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}>{r.server}</td>
                            <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}><Badge ok={!!r.ok} /></td>
                            <td style={{ padding: '10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>
                              {Array.isArray(r.addresses) && r.addresses.length > 0 ? r.addresses.join(', ') : (r.error || '')}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              <div style={{ marginTop: '1rem' }}>
                <h3 style={{ color: 'var(--accent)', marginBottom: '0.5rem' }}>HTTPS ハンドシェイク（証明書/プロキシ影響）</h3>
                {Array.isArray(result?.results?.deep?.tls) && result.results.deep.tls.length > 0 ? (
                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', border: '1px solid var(--border)' }}>
                      <thead>
                        <tr style={{ background: 'var(--surface-2)' }}>
                          <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>URL</th>
                          <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>検証</th>
                          <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>有効期限</th>
                          <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>エラー</th>
                        </tr>
                      </thead>
                      <tbody>
                        {result.results.deep.tls.map((t, idx) => (
                          <tr key={idx} style={{ background: 'var(--surface)' }}>
                            <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}>{t.target}</td>
                            <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}><Badge ok={!!t.verify_ok} /></td>
                            <td style={{ padding: '10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>{t?.cert?.notAfter || ''}</td>
                            <td style={{ padding: '10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>{t.verify_error || ''}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="info-item">HTTPSの対象がありません（http_targets に https:// を入れてください）</div>
                )}
              </div>

              <div style={{ marginTop: '1rem' }}>
                <h3 style={{ color: 'var(--accent)', marginBottom: '0.5rem' }}>Proxy / PAC（自動検出）</h3>
                <div className="info-item">
                  <strong>WinINET(HKCU):</strong>
                  <pre style={{ marginTop: '8px', padding: '10px', borderRadius: '10px', border: '1px solid var(--border)', background: 'var(--surface-2)', overflowX: 'auto' }}>
                    {String(result?.results?.deep?.proxy?.inet_settings_raw || '')}
                  </pre>
                  <strong>WinHTTP(netsh):</strong>
                  <pre style={{ marginTop: '8px', padding: '10px', borderRadius: '10px', border: '1px solid var(--border)', background: 'var(--surface-2)', overflowX: 'auto' }}>
                    {String(result?.results?.deep?.proxy?.winhttp_raw || '')}
                  </pre>
                </div>
              </div>

              <div style={{ marginTop: '1rem' }}>
                <h3 style={{ color: 'var(--accent)', marginBottom: '0.5rem' }}>tracert（経路）</h3>
                {Array.isArray(result?.results?.deep?.traceroute) && result.results.deep.traceroute.length > 0 ? (
                  result.results.deep.traceroute.map((tr, idx) => (
                    <div key={idx} className="info-item">
                      <div><strong>対象:</strong> {tr.target}</div>
                      <pre style={{ marginTop: '8px', padding: '10px', borderRadius: '10px', border: '1px solid var(--border)', background: 'var(--surface-2)', overflowX: 'auto' }}>
                        {Array.isArray(tr.lines) ? tr.lines.join('\n') : ''}
                      </pre>
                    </div>
                  ))
                ) : (
                  <div className="info-item">経路情報がありません</div>
                )}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

export default ConnectivityCheck;
