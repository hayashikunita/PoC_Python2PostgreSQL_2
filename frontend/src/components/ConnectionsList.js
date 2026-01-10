import React, { useEffect, useMemo, useState } from 'react';
import axios from 'axios';

function ConnectionsList() {
  const [limit, setLimit] = useState(500);
  const [includeListen, setIncludeListen] = useState(true);
  const [includeSignature, setIncludeSignature] = useState(false);

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [copyStatus, setCopyStatus] = useState(null);

  const fetchConnections = async () => {
    setLoading(true);
    setError(null);
    setCopyStatus(null);
    try {
      const res = await axios.get('/api/network/connections', {
        params: {
          limit: Number(limit) || 500,
          include_listen: includeListen,
          include_flags: true,
          include_signature: includeSignature,
        },
      });
      setData(res.data);
    } catch (err) {
      setError('接続先一覧の取得に失敗しました: ' + (err?.response?.data?.detail || err.message));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchConnections();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

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

  const connections = useMemo(() => {
    const arr = data && Array.isArray(data.connections) ? data.connections : [];
    return arr;
  }, [data]);

  if (loading) return <div className="loading">読み込み中...</div>;
  if (error) return <div className="error">{error}</div>;
  if (!data) return <div className="error">データがありません</div>;

  const summary = data.summary || {};

  const fmtAddr = (a) => {
    if (!a) return '';
    const ip = a.ip ?? '';
    const port = a.port ?? '';
    return port ? `${ip}:${port}` : String(ip);
  };

  const flagBadge = (on, label) => (
    <span
      style={{
        display: 'inline-block',
        padding: '2px 8px',
        borderRadius: '999px',
        fontSize: '12px',
        fontWeight: 700,
        border: '1px solid var(--border)',
        background: on ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.12)',
        color: on ? 'rgba(254, 202, 202, 0.95)' : 'rgba(167, 243, 208, 0.95)',
      }}
      title={label}
    >
      {label}
    </span>
  );

  const signatureLabel = (sig) => {
    if (!sig) return '';
    const parsed = sig.parsed;
    if (parsed && typeof parsed === 'object') {
      return String(parsed.Status || '') || '';
    }
    return '';
  };

  return (
    <div className="card">
      <h2>🔌 接続先一覧（TCP/UDP）</h2>

      <div className="packet-explanation">
        <div style={{ lineHeight: '1.8' }}>
          <div>現在の接続/待受（LISTEN）を一覧表示します。</div>
          <div>取得件数が多い場合は limit を下げてください。</div>
        </div>
      </div>

      <div className="info-item">
        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginRight: '14px' }}>
          <strong>limit:</strong>
          <input
            type="number"
            min={50}
            max={5000}
            value={limit}
            onChange={(e) => setLimit(e.target.value)}
            style={{ width: '120px', padding: '8px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface-2)' }}
          />
        </label>

        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', color: 'var(--muted)' }}>
          <input type="checkbox" checked={includeListen} onChange={(e) => setIncludeListen(e.target.checked)} />
          LISTEN を含める
        </label>

        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', color: 'var(--muted)', marginLeft: '14px' }}>
          <input type="checkbox" checked={includeSignature} onChange={(e) => setIncludeSignature(e.target.checked)} />
          署名確認（重い/取れない場合あり）
        </label>
      </div>

      <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
        <button className="button" onClick={fetchConnections}>🔄 再取得</button>
        <button className="button" onClick={copyJson} disabled={!data}>📋 結果をコピー（JSON）</button>
        {copyStatus && <span style={{ color: 'var(--muted)', alignSelf: 'center' }}>{copyStatus}</span>}
      </div>

      <div className="info-item">
        <div><strong>収集時刻:</strong> {data.collected_at || '-'}</div>
        <div><strong>ホスト名:</strong> {data.hostname || '-'}</div>
        <div><strong>件数:</strong> {summary.count ?? connections.length} / limit {summary.limit ?? '-'}</div>
        <div><strong>計測:</strong> {summary.elapsed_ms ?? '-'}ms</div>
      </div>

      {connections.length === 0 ? (
        <div className="info-item">接続がありません</div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', border: '1px solid var(--border)' }}>
            <thead>
              <tr style={{ background: 'var(--surface-2)' }}>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>プロトコル</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>状態</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>ローカル</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>リモート</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>フラグ</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>PID</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>プロセス</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>署名</th>
              </tr>
            </thead>
            <tbody>
              {connections.map((c, idx) => (
                <tr key={idx} style={{ background: 'var(--surface)' }}>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>{c.proto}</td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>{c.status}</td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}>{fmtAddr(c.laddr)}</td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}>{fmtAddr(c.raddr)}</td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}>
                    {c?.flags?.is_external ? flagBadge(true, '外向き') : flagBadge(false, '内向き')}{' '}
                    {c?.flags?.is_new ? flagBadge(true, '新規') : null}{' '}
                    {c?.flags?.is_unusual_remote_port ? flagBadge(true, 'ポート異常') : null}{' '}
                    {c?.flags?.is_ephemeral_local_port ? (
                      <span style={{ marginLeft: '6px', color: 'var(--muted)' }} title="ローカル一時ポート">
                        ephem
                      </span>
                    ) : null}
                  </td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>{String(c.pid ?? '')}</td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}>{c.process || ''}</td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>
                    {signatureLabel(c.signature)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default ConnectionsList;
