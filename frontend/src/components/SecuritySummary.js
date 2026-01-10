import React, { useEffect, useState } from 'react';
import axios from 'axios';

function SecuritySummary() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [copyStatus, setCopyStatus] = useState(null);

  const fetchSummary = async () => {
    setLoading(true);
    setError(null);
    setCopyStatus(null);
    try {
      const res = await axios.get('/api/windows/registry/summary');
      setData(res.data);
    } catch (err) {
      setError('要約の取得に失敗しました: ' + (err?.response?.data?.detail || err.message));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSummary();
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

  if (loading) return <div className="loading">読み込み中...</div>;
  if (error) return <div className="error">{error}</div>;
  if (!data) return <div className="error">データがありません</div>;

  const counts = data.counts || { ok: 0, warn: 0, error: 0 };
  const nonOk = Array.isArray(data.non_ok) ? data.non_ok : [];

  return (
    <div className="card">
      <h2>🛡️ セキュリティ/ポリシー要約（レジストリ判定）</h2>

      <div className="packet-explanation">
        <div style={{ lineHeight: '1.8' }}>
          <div>レジストリ判定結果を OK / 注意 / NG で要約します。</div>
          <div>NG/注意の項目は下に一覧で表示されます。</div>
        </div>
      </div>

      <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
        <button className="button" onClick={fetchSummary}>🔄 再取得</button>
        <button className="button" onClick={copyJson} disabled={!data}>📋 結果をコピー（JSON）</button>
        {copyStatus && <span style={{ color: 'var(--muted)', alignSelf: 'center' }}>{copyStatus}</span>}
      </div>

      <div className="info-item">
        <div><strong>収集時刻:</strong> {data.collected_at || '-'}</div>
        <div><strong>ホスト名:</strong> {data.hostname || '-'}</div>
        <div><strong>Windows:</strong> {String(!!data.is_windows)}</div>
      </div>

      <h3>集計</h3>
      <div className="info-item"><strong>OK:</strong> {counts.ok}</div>
      <div className="info-item"><strong>注意:</strong> {counts.warn}</div>
      <div className="info-item"><strong>NG:</strong> {counts.error}</div>

      <h3>NG/注意 一覧</h3>
      {nonOk.length === 0 ? (
        <div className="info-item">NG/注意はありません</div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', border: '1px solid var(--border)' }}>
            <thead>
              <tr style={{ background: 'var(--surface-2)' }}>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>レベル</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>タイトル</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>メッセージ</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>現在値</th>
                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border)' }}>期待値</th>
              </tr>
            </thead>
            <tbody>
              {nonOk.map((r, idx) => (
                <tr key={idx} style={{ background: 'var(--surface)' }}>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>{r.level}</td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)' }}>{r.title}</td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>{r.message || ''}</td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>{String(r.actual ?? '')}</td>
                  <td style={{ padding: '10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>{String(r.expected ?? '')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default SecuritySummary;
