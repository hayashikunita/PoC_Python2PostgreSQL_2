import React, { useState } from 'react';
import axios from 'axios';

function ExportReport() {
  const [includePackets, setIncludePackets] = useState(false);
  const [packetsLimit, setPacketsLimit] = useState(500);
  const [maxEvents, setMaxEvents] = useState(200);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [report, setReport] = useState(null);
  const [copyStatus, setCopyStatus] = useState(null);

  const fetchReport = async () => {
    setLoading(true);
    setError(null);
    setCopyStatus(null);
    try {
      const res = await axios.get('/api/report/all', {
        params: {
          include_packets: includePackets,
          packets_limit: Number(packetsLimit) || 0,
          max_events: Number(maxEvents) || 0,
        },
      });
      setReport(res.data);
    } catch (err) {
      setError('レポート取得に失敗しました: ' + (err?.response?.data?.detail || err.message));
    } finally {
      setLoading(false);
    }
  };

  const copyJson = async () => {
    if (!report) return;
    const text = JSON.stringify(report, null, 2);
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

  const downloadJson = () => {
    if (!report) return;
    const text = JSON.stringify(report, null, 2);
    const blob = new Blob([text], { type: 'application/json' });
    const url = URL.createObjectURL(blob);

    const ts = new Date().toISOString().replace(/[:.]/g, '-');
    const a = document.createElement('a');
    a.href = url;
    a.download = `report-all-${ts}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const approxSize = report ? new Blob([JSON.stringify(report)]).size : 0;

  return (
    <div className="card">
      <h2>📄 全体レポート出力（JSON）</h2>

      <div className="packet-explanation">
        <div style={{ lineHeight: '1.8' }}>
          <div>主要タブの情報をまとめて JSON で出力します。</div>
          <div>パケットやイベントログはサイズが増えるため、必要な場合のみ有効にしてください。</div>
        </div>
      </div>

      {error && <div className="error">{error}</div>}

      <div className="info-item">
        <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center', marginRight: '14px', color: 'var(--muted)' }}>
          <input type="checkbox" checked={includePackets} onChange={(e) => setIncludePackets(e.target.checked)} />
          パケットを含める（include_packets）
        </label>

        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', marginTop: '10px' }}>
          <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center' }}>
            <strong>packets_limit:</strong>
            <input
              type="number"
              min={0}
              max={5000}
              value={packetsLimit}
              onChange={(e) => setPacketsLimit(e.target.value)}
              style={{ width: '120px', padding: '8px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface-2)' }}
            />
          </label>

          <label style={{ display: 'inline-flex', gap: '8px', alignItems: 'center' }}>
            <strong>max_events:</strong>
            <input
              type="number"
              min={0}
              max={1000}
              value={maxEvents}
              onChange={(e) => setMaxEvents(e.target.value)}
              style={{ width: '120px', padding: '8px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--surface-2)' }}
            />
          </label>
        </div>
      </div>

      <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
        <button className="button" onClick={fetchReport} disabled={loading}>
          {loading ? '生成中...' : '▶️ レポート生成'}
        </button>
        <button className="button" onClick={copyJson} disabled={!report}>📋 JSONコピー</button>
        <button className="button" onClick={downloadJson} disabled={!report}>⬇️ JSONダウンロード</button>
        {copyStatus && <span style={{ color: 'var(--muted)', alignSelf: 'center' }}>{copyStatus}</span>}
      </div>

      {report && (
        <div className="info-item">
          <div><strong>収集時刻:</strong> {report.collected_at || '-'}</div>
          <div><strong>ホスト名:</strong> {report.hostname || '-'}</div>
          <div><strong>概算サイズ:</strong> {approxSize.toLocaleString()} bytes</div>
        </div>
      )}

      {report && (
        <pre
          style={{
            marginTop: '1rem',
            padding: '1rem',
            borderRadius: '10px',
            border: '1px solid var(--border)',
            background: 'var(--surface-2)',
            overflowX: 'auto',
            maxHeight: '520px',
          }}
        >
          {JSON.stringify(report, null, 2)}
        </pre>
      )}
    </div>
  );
}

export default ExportReport;
