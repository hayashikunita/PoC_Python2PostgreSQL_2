import React, { useEffect, useState } from 'react';
import axios from 'axios';

function RegistryEditor() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const copyJson = async (label, obj) => {
    try {
      const text = JSON.stringify(obj, null, 2);
      if (navigator?.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'absolute';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      }
    } catch (e) {
      setError(`${label}のコピーに失敗しました: ` + (e?.message || String(e)));
    }
  };

  const fetchReport = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.get('/api/windows/registry/report');
      setReport(response.data);
    } catch (err) {
      setError('レジストリ情報の取得に失敗しました: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReport();
  }, []);

  if (loading) return <div className="loading">読み込み中...</div>;
  if (error) return <div className="error">{error}</div>;
  if (!report) return <div className="error">データがありません</div>;

  return (
    <div className="card">
      <h2>レジストリエディタ（ここ）</h2>

      {!report.is_windows && (
        <div className="error">
          この機能はWindows環境でのみ利用できます。
        </div>
      )}

      <div className="info-item">
        <strong>取得時刻:</strong> {report.collected_at}
      </div>
      <div className="info-item">
        <strong>ホスト名:</strong> {report.hostname}
      </div>

      <h3>取得・判定結果</h3>
      <div className="packet-explanation" style={{ marginBottom: '1rem' }}>
        💡 <strong>解説:</strong> 指定したレジストリ値を取得し、期待値（または存在/空でないこと）で判定します。
      </div>

      {Array.isArray(report.checks) && report.checks.length > 0 ? (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={{ textAlign: 'left', padding: '8px' }}>項目</th>
                <th style={{ textAlign: 'left', padding: '8px' }}>場所</th>
                <th style={{ textAlign: 'left', padding: '8px' }}>値</th>
                <th style={{ textAlign: 'left', padding: '8px' }}>判定</th>
              </tr>
            </thead>
            <tbody>
              {report.checks.map((c) => (
                <tr key={c.id}>
                  <td style={{ padding: '8px', verticalAlign: 'top' }}>{c.title}</td>
                  <td style={{ padding: '8px', verticalAlign: 'top' }}>
                    <div><strong>{c.hive}\\{c.key_path}</strong></div>
                    <div>{c.value_name}</div>
                  </td>
                  <td style={{ padding: '8px', verticalAlign: 'top' }}>
                    {c.actual && c.actual.exists ? (
                      <div>
                        <div><strong>{String(c.actual.value)}</strong></div>
                        <div style={{ fontSize: '0.9em' }}>{c.actual.value_type}</div>
                      </div>
                    ) : (
                      <div>（見つかりません）</div>
                    )}
                  </td>
                  <td style={{ padding: '8px', verticalAlign: 'top' }}>
                    <div><strong>{String(c.level).toUpperCase()}</strong></div>
                    <div style={{ fontSize: '0.9em' }}>{c.message}</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="error">チェック項目がありません</div>
      )}

      <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
        <button className="button" onClick={fetchReport}>
          🔄 更新
        </button>
        <button className="button" onClick={() => copyJson('レジストリ結果', report)}>
          📋 結果をコピー（JSON）
        </button>
      </div>
    </div>
  );
}

export default RegistryEditor;
