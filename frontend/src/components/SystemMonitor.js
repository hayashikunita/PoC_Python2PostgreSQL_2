import React, { useState } from 'react';
import axios from 'axios';

function formatBytes(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n <= 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(n) / Math.log(k));
  return `${Math.round((n / Math.pow(k, i)) * 100) / 100} ${sizes[i]}`;
}


function SystemMonitor({ initialTab = 'specs', showSubTabs = true, pageTitle } = {}) {
  const [dbHealth, setDbHealth] = useState(null);
  const [specs, setSpecs] = useState(null);
  const [proc, setProc] = useState(null);
  const [appHistSample, setAppHistSample] = useState(null);
  const [appHist, setAppHist] = useState(null);
  const [svc, setSvc] = useState(null);
  const [startup, setStartup] = useState(null);
  const [evt, setEvt] = useState(null);
  const [evtLogs, setEvtLogs] = useState(null);

  const [activeMonitorTab, setActiveMonitorTab] = useState(initialTab);

  const [loadingDb, setLoadingDb] = useState(false);
  const [loadingSpecs, setLoadingSpecs] = useState(false);
  const [loadingProc, setLoadingProc] = useState(false);
  const [loadingAppHistSample, setLoadingAppHistSample] = useState(false);
  const [loadingAppHist, setLoadingAppHist] = useState(false);
  const [loadingSvc, setLoadingSvc] = useState(false);
  const [loadingStartup, setLoadingStartup] = useState(false);
  const [loadingEvt, setLoadingEvt] = useState(false);
  const [loadingEvtLogs, setLoadingEvtLogs] = useState(false);

  const [error, setError] = useState(null);

  const [procSampleMs, setProcSampleMs] = useState(200);
  const [procLimit, setProcLimit] = useState(250);
  const [procSave, setProcSave] = useState(false);

  const [svcLimit, setSvcLimit] = useState(500);
  const [startupLimit, setStartupLimit] = useState(200);

  const [appHistSinceHours, setAppHistSinceHours] = useState(24);
  const [appHistLimit, setAppHistLimit] = useState(50);

  const [evtLogName, setEvtLogName] = useState('System');
  const [evtSinceHours, setEvtSinceHours] = useState(24);
  const [evtMaxEvents, setEvtMaxEvents] = useState(200);
  const [evtTimeoutS, setEvtTimeoutS] = useState(30);
  const [evtSave, setEvtSave] = useState(false);

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

  const fetchDbHealth = async () => {
    setLoadingDb(true);
    setError(null);
    try {
      const res = await axios.get('/api/db/health');
      setDbHealth(res.data);
    } catch (e) {
      setError('DBヘルスチェックに失敗しました: ' + (e?.message || String(e)));
    } finally {
      setLoadingDb(false);
    }
  };

  const fetchSpecs = async () => {
    setLoadingSpecs(true);
    setError(null);
    try {
      const res = await axios.get('/api/system/specs');
      setSpecs(res.data);
    } catch (e) {
      setError('PCスペックの取得に失敗しました: ' + (e?.message || String(e)));
    } finally {
      setLoadingSpecs(false);
    }
  };

  const fetchProcessSnapshot = async () => {
    setLoadingProc(true);
    setError(null);
    try {
      const res = await axios.get('/api/system/process-snapshot', {
        params: {
          sample_ms: procSampleMs,
          limit: procLimit,
          save: procSave,
        },
      });
      setProc(res.data);
    } catch (e) {
      setError('プロセス情報の取得に失敗しました: ' + (e?.message || String(e)));
    } finally {
      setLoadingProc(false);
    }
  };

  const fetchServices = async () => {
    setLoadingSvc(true);
    setError(null);
    try {
      const res = await axios.get('/api/windows/services', {
        params: {
          limit: svcLimit,
          timeout_s: 10,
        },
      });
      setSvc(res.data);
    } catch (e) {
      setError('サービス一覧の取得に失敗しました: ' + (e?.message || String(e)));
    } finally {
      setLoadingSvc(false);
    }
  };

  const fetchStartupApps = async () => {
    setLoadingStartup(true);
    setError(null);
    try {
      const res = await axios.get('/api/windows/startup-apps', {
        params: {
          limit: startupLimit,
          timeout_s: 15,
        },
      });
      setStartup(res.data);
    } catch (e) {
      setError('スタートアップアプリの取得に失敗しました: ' + (e?.message || String(e)));
    } finally {
      setLoadingStartup(false);
    }
  };

  const saveAppHistorySample = async () => {
    setLoadingAppHistSample(true);
    setError(null);
    try {
      const res = await axios.post('/api/system/app-history/sample', null, {
        params: {
          save: true,
          timeout_s: 10,
          limit: 2000,
        },
      });
      setAppHistSample(res.data);
    } catch (e) {
      setError('アプリ履歴サンプルの保存に失敗しました: ' + (e?.message || String(e)));
    } finally {
      setLoadingAppHistSample(false);
    }
  };

  const fetchAppHistory = async () => {
    setLoadingAppHist(true);
    setError(null);
    try {
      const res = await axios.get('/api/system/app-history', {
        params: {
          since_hours: appHistSinceHours,
          limit: appHistLimit,
        },
      });
      setAppHist(res.data);
    } catch (e) {
      setError('アプリ履歴の取得に失敗しました: ' + (e?.message || String(e)));
    } finally {
      setLoadingAppHist(false);
    }
  };

  const fetchEventLog = async () => {
    setLoadingEvt(true);
    setError(null);
    try {
      const res = await axios.get('/api/windows/eventlog', {
        params: {
          log_name: evtLogName,
          since_hours: evtSinceHours,
          max_events: evtMaxEvents,
          timeout_s: evtTimeoutS,
          save: evtSave,
        },
      });
      setEvt(res.data);
    } catch (e) {
      setError('イベントログの取得に失敗しました: ' + (e?.message || String(e)));
    } finally {
      setLoadingEvt(false);
    }
  };

  const fetchEventLogList = async () => {
    setLoadingEvtLogs(true);
    setError(null);
    try {
      const res = await axios.get('/api/windows/eventlog/logs', { params: { limit: 200, timeout_s: 30 } });
      setEvtLogs(res.data);
    } catch (e) {
      setError('イベントログ一覧の取得に失敗しました: ' + (e?.message || String(e)));
    } finally {
      setLoadingEvtLogs(false);
    }
  };


  const computedTitle =
    pageTitle ||
    (showSubTabs
      ? '🪟 システム監視（タスクマネージャー / イベントビューア）'
      : activeMonitorTab === 'specs'
        ? '💻 PCスペック'
        : activeMonitorTab === 'process'
          ? '📌 タスクマネージャー'
          : '📜 イベントビュアー');

  return (
    <div className="card">
      <h2>{computedTitle}</h2>

      <div className="packet-explanation" style={{ marginBottom: '1.5rem' }}>
        💡 <strong>解説:</strong> このページでは、プロセス（CPU/メモリ上位など）とWindowsイベントログを自動取得し、要約を表示します。
        DB保存を有効にするとPostgreSQLに保存します。
      </div>

      {error && <div className="error">{error}</div>}

      {showSubTabs && (
        <nav className="tab-navigation" style={{ marginBottom: '1rem' }}>
          <button className={activeMonitorTab === 'specs' ? 'active' : ''} onClick={() => setActiveMonitorTab('specs')}>
            💻 PCスペック
          </button>
          <button className={activeMonitorTab === 'process' ? 'active' : ''} onClick={() => setActiveMonitorTab('process')}>
            📌 プロセス
          </button>
          <button className={activeMonitorTab === 'eventlog' ? 'active' : ''} onClick={() => setActiveMonitorTab('eventlog')}>
            📜 イベントログ
          </button>
        </nav>
      )}

      {activeMonitorTab === 'specs' && (
      <div className="info-item">
        <h3 style={{ marginTop: 0 }}>💻 PCスペック</h3>
        <button className="button" onClick={fetchSpecs} disabled={loadingSpecs}>
          {loadingSpecs ? '取得中...' : 'PCスペックを取得'}
        </button>

        {specs && (
          <div style={{ marginTop: '0.75rem', lineHeight: '1.8' }}>
            <div><strong>collected_at:</strong> {specs.collected_at}</div>
            <div><strong>hostname:</strong> {specs.hostname}</div>

            {specs.os && (
              <div style={{ marginTop: '0.5rem' }}>
                <h4 style={{ color: 'var(--accent)', marginBottom: '0.25rem' }}>OS</h4>
                <div><strong>system:</strong> {specs.os.system}</div>
                <div><strong>release:</strong> {specs.os.release}</div>
                <div><strong>version:</strong> {String(specs.os.version)}</div>
                <div><strong>machine:</strong> {specs.os.machine}</div>
              </div>
            )}

            {specs.cpu && (
              <div style={{ marginTop: '0.75rem' }}>
                <h4 style={{ color: 'var(--accent)', marginBottom: '0.25rem' }}>CPU</h4>
                <div><strong>physical_cores:</strong> {String(specs.cpu.physical_cores)}</div>
                <div><strong>logical_cores:</strong> {String(specs.cpu.logical_cores)}</div>
                {specs.cpu.freq && (specs.cpu.freq.current_mhz || specs.cpu.freq.max_mhz) && (
                  <div>
                    <strong>freq:</strong>{' '}
                    {specs.cpu.freq.current_mhz ? `${Math.round(specs.cpu.freq.current_mhz)}MHz` : ''}
                    {specs.cpu.freq.max_mhz ? ` (max ${Math.round(specs.cpu.freq.max_mhz)}MHz)` : ''}
                  </div>
                )}
              </div>
            )}

            {specs.memory && (
              <div style={{ marginTop: '0.75rem' }}>
                <h4 style={{ color: 'var(--accent)', marginBottom: '0.25rem' }}>メモリ</h4>
                <div><strong>total:</strong> {formatBytes(specs.memory.total || 0)}</div>
                <div><strong>available:</strong> {formatBytes(specs.memory.available || 0)}</div>
              </div>
            )}

            {Array.isArray(specs.disks) && specs.disks.length > 0 && (
              <div style={{ marginTop: '0.75rem' }}>
                <h4 style={{ color: 'var(--accent)', marginBottom: '0.25rem' }}>ディスク</h4>
                {specs.disks.slice(0, 12).map((d, idx) => (
                  <div key={idx} className="packet-item" style={{ marginBottom: '0.5rem' }}>
                    <div><strong>{d.mountpoint || d.device || 'disk'}</strong> {d.fstype ? `(${d.fstype})` : ''}</div>
                    {d.total ? (
                      <div>used: {formatBytes(d.used || 0)} / total: {formatBytes(d.total || 0)} ({d.percent ?? 0}%)</div>
                    ) : (
                      <div>device: {d.device}</div>
                    )}
                  </div>
                ))}
                {specs.disks.length > 12 && (
                  <div style={{ color: '#666' }}>※ 表示は先頭12件のみ（コピーは全件JSON）</div>
                )}
              </div>
            )}

            <div style={{ marginTop: '0.75rem' }}>
              <h4 style={{ color: 'var(--accent)', marginBottom: '0.25rem' }}>GPU</h4>
              {Array.isArray(specs.gpu) && specs.gpu.length > 0 ? (
                <div>
                  {specs.gpu.slice(0, 6).map((g, idx) => (
                    <div key={idx} className="packet-item" style={{ marginBottom: '0.5rem' }}>
                      <div><strong>{g.Name || '(unknown)'}</strong></div>
                      {g.VideoProcessor && <div>processor: {g.VideoProcessor}</div>}
                      {g.DriverVersion && <div>driver: {g.DriverVersion}</div>}
                      {g.AdapterRAM && <div>vram: {formatBytes(g.AdapterRAM)}</div>}
                      {(g.CurrentHorizontalResolution || g.CurrentVerticalResolution) && (
                        <div>
                          resolution: {g.CurrentHorizontalResolution || '?'} x {g.CurrentVerticalResolution || '?'}
                          {g.CurrentRefreshRate ? ` @ ${g.CurrentRefreshRate}Hz` : ''}
                        </div>
                      )}
                    </div>
                  ))}
                  {specs.gpu.length > 6 && (
                    <div style={{ color: '#666' }}>※ 表示は先頭6件のみ（コピーは全件JSON）</div>
                  )}
                </div>
              ) : (
                <div style={{ color: '#666' }}>GPU情報がありません（Windows以外、または取得できない環境の可能性があります）</div>
              )}
            </div>
          </div>
        )}
      </div>
      )}

      {activeMonitorTab === 'process' && (
      <div className="info-item">
        <h3 style={{ marginTop: 0 }}>📌 プロセス（タスクマネージャー相当）</h3>

        <div className="packet-explanation" style={{ marginBottom: '0.75rem' }}>
          <div>💡 <strong>使い方</strong></div>
          <ul style={{ margin: '0.35rem 0 0 1.2rem' }}>
            <li><strong>プロセスを取得</strong> で、CPU/メモリ上位の要約を表示します</li>
            <li><strong>DBに保存</strong> をONにするとPostgreSQLへ保存します</li>
          </ul>
        </div>

        <div className="packet-item" style={{ marginBottom: '0.75rem' }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', alignItems: 'center' }}>
            <label>
              <strong>sample_ms:</strong>{' '}
              <input
                type="number"
                value={procSampleMs}
                min={50}
                max={2000}
                onChange={(e) => setProcSampleMs(Number(e.target.value))}
                style={{ width: '110px', marginLeft: '6px' }}
              />
            </label>
            <label>
              <strong>limit:</strong>{' '}
              <input
                type="number"
                value={procLimit}
                min={1}
                max={2000}
                onChange={(e) => setProcLimit(Number(e.target.value))}
                style={{ width: '110px', marginLeft: '6px' }}
              />
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <input type="checkbox" checked={procSave} onChange={(e) => setProcSave(e.target.checked)} />
              <strong>DBに保存</strong>
            </label>
          </div>

          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', marginTop: '0.75rem' }}>
            <button className="button" onClick={fetchProcessSnapshot} disabled={loadingProc}>
              {loadingProc ? '取得中...' : 'プロセスを取得'}
            </button>

            {proc && (
              <button className="button" onClick={() => copyJson('プロセス結果', proc)}>
                プロセス結果をコピー（JSON）
              </button>
            )}
          </div>
        </div>

        {proc && (
          <div style={{ marginTop: '1rem' }}>
            <div style={{ marginBottom: '0.75rem' }}>
              <div><strong>collected_at:</strong> {proc.collected_at}</div>
              <div><strong>hostname:</strong> {proc.hostname}</div>
              {proc.db_saved !== undefined && (
                <div><strong>db_saved:</strong> {String(proc.db_saved)} {proc.db_id ? `(id=${proc.db_id})` : ''}</div>
              )}
              {proc.db_error && <div><strong>db_error:</strong> {proc.db_error}</div>}
            </div>

            {proc.summary && (
              <div>
                <h4 style={{ color: 'var(--accent)', marginBottom: '0.5rem' }}>概要</h4>
                <div><strong>process_count:</strong> {proc.summary.process_count}</div>
                <div><strong>high_cpu_count:</strong> {proc.summary.high_cpu_count}</div>
                <div><strong>high_memory_count:</strong> {proc.summary.high_memory_count}</div>
              </div>
            )}

            {proc.summary?.top_cpu && proc.summary.top_cpu.length > 0 && (
              <div style={{ marginTop: '1rem' }}>
                <h4 style={{ color: 'var(--accent)', marginBottom: '0.5rem' }}>CPU上位</h4>
                {proc.summary.top_cpu.map((p, idx) => (
                  <div key={idx} className="packet-item" style={{ marginBottom: '0.5rem' }}>
                    <div><strong>{p.name || 'unknown'}</strong> (pid={p.pid})</div>
                    <div>cpu: {p.cpu_percent ?? 0}% / mem: {formatBytes(p.memory_rss || 0)}</div>
                    {p.username && <div>user: {p.username}</div>}
                  </div>
                ))}
              </div>
            )}

            {proc.summary?.top_memory_rss && proc.summary.top_memory_rss.length > 0 && (
              <div style={{ marginTop: '1rem' }}>
                <h4 style={{ color: 'var(--accent)', marginBottom: '0.5rem' }}>メモリ上位</h4>
                {proc.summary.top_memory_rss.map((p, idx) => (
                  <div key={idx} className="packet-item" style={{ marginBottom: '0.5rem' }}>
                    <div><strong>{p.name || 'unknown'}</strong> (pid={p.pid})</div>
                    <div>mem: {formatBytes(p.memory_rss || 0)} / cpu: {p.cpu_percent ?? 0}%</div>
                    {p.username && <div>user: {p.username}</div>}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        <div style={{ marginTop: '1.25rem' }}>
          <h4 style={{ color: 'var(--accent)', marginBottom: '0.5rem' }}>🧩 サービス（タスクマネージャー相当）</h4>
          <div className="packet-explanation" style={{ marginBottom: '0.75rem' }}>
            <div>💡 <strong>概要</strong></div>
            <ul style={{ margin: '0.35rem 0 0 1.2rem' }}>
              <li>Windowsサービスの一覧（状態・起動種類・PIDなど）を取得します</li>
              <li>環境によっては一部情報が取得できない場合があります</li>
            </ul>
          </div>

          <div className="packet-item" style={{ marginBottom: '0.75rem' }}>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', alignItems: 'center' }}>
              <label>
                <strong>limit:</strong>{' '}
                <input
                  type="number"
                  value={svcLimit}
                  min={1}
                  max={5000}
                  onChange={(e) => setSvcLimit(Number(e.target.value))}
                  style={{ width: '110px', marginLeft: '6px' }}
                />
              </label>
              <button className="button" onClick={fetchServices} disabled={loadingSvc}>
                {loadingSvc ? '取得中...' : 'サービス一覧を取得'}
              </button>
              {svc && (
                <button className="button" onClick={() => copyJson('サービス一覧', svc)}>
                  サービス一覧をコピー（JSON）
                </button>
              )}
            </div>
          </div>

          {svc && (
            <div style={{ marginTop: '0.5rem' }}>
              {svc.summary?.error ? (
                <div className="error">{String(svc.summary.error)}</div>
              ) : (
                <>
                  <div className="evt-muted" style={{ marginBottom: '0.5rem' }}>
                    <strong>count:</strong> {String(svc.summary?.count ?? (Array.isArray(svc.services) ? svc.services.length : 0))}
                    {svc.summary?.timed_out ? '（タイムアウトで途中まで）' : ''}
                  </div>
                  <div style={{ overflowX: 'auto' }}>
                    <table className="packet-table">
                      <thead>
                        <tr>
                          <th style={{ whiteSpace: 'nowrap' }}>name</th>
                          <th style={{ whiteSpace: 'nowrap' }}>display</th>
                          <th style={{ whiteSpace: 'nowrap' }}>status</th>
                          <th style={{ whiteSpace: 'nowrap' }}>start</th>
                          <th style={{ whiteSpace: 'nowrap' }}>pid</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(Array.isArray(svc.services) ? svc.services : []).slice(0, 2000).map((s, idx) => (
                          <tr key={`${s?.name || 'svc'}-${idx}`}>
                            <td style={{ whiteSpace: 'nowrap' }}>{s?.name || ''}</td>
                            <td style={{ whiteSpace: 'nowrap' }}>{s?.display_name || ''}</td>
                            <td style={{ whiteSpace: 'nowrap' }}>{s?.status || ''}</td>
                            <td style={{ whiteSpace: 'nowrap' }}>{s?.start_type || ''}</td>
                            <td style={{ whiteSpace: 'nowrap', textAlign: 'right' }}>{s?.pid ?? ''}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
            </div>
          )}
        </div>

        <div style={{ marginTop: '1.25rem' }}>
          <h4 style={{ color: 'var(--accent)', marginBottom: '0.5rem' }}>🚀 スタートアップアプリ（タスクマネージャー相当）</h4>
          <div className="packet-explanation" style={{ marginBottom: '0.75rem' }}>
            <div>💡 <strong>概要</strong></div>
            <ul style={{ margin: '0.35rem 0 0 1.2rem' }}>
              <li>起動時に実行される項目を、複数ソース（レジストリ/フォルダ/CIM）から統合して一覧表示します</li>
              <li>「有効/無効」は StartupApproved を参照して推定します（環境によって unknown になる場合があります）</li>
            </ul>
          </div>

          <div className="packet-item" style={{ marginBottom: '0.75rem' }}>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', alignItems: 'center' }}>
              <label>
                <strong>limit:</strong>{' '}
                <input
                  type="number"
                  value={startupLimit}
                  min={1}
                  max={2000}
                  onChange={(e) => setStartupLimit(Number(e.target.value))}
                  style={{ width: '110px', marginLeft: '6px' }}
                />
              </label>
              <button className="button" onClick={fetchStartupApps} disabled={loadingStartup}>
                {loadingStartup ? '取得中...' : 'スタートアップを取得'}
              </button>
              {startup && (
                <button className="button" onClick={() => copyJson('スタートアップアプリ', startup)}>
                  スタートアップをコピー（JSON）
                </button>
              )}
            </div>
          </div>

          {startup && (
            <div style={{ marginTop: '0.5rem' }}>
              {startup.summary?.error ? (
                <div className="error">{String(startup.summary.error)}</div>
              ) : (
                <>
                  <div className="evt-muted" style={{ marginBottom: '0.5rem' }}>
                    <strong>count:</strong> {String(startup.summary?.count ?? (Array.isArray(startup.startup_apps) ? startup.startup_apps.length : 0))}
                  </div>
                  <div style={{ overflowX: 'auto' }}>
                    <table className="packet-table">
                      <thead>
                        <tr>
                          <th style={{ whiteSpace: 'nowrap' }}>enabled</th>
                          <th style={{ whiteSpace: 'nowrap' }}>name</th>
                          <th style={{ whiteSpace: 'nowrap' }}>source</th>
                          <th style={{ whiteSpace: 'nowrap' }}>user</th>
                          <th style={{ whiteSpace: 'nowrap' }}>location</th>
                          <th>command</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(Array.isArray(startup.startup_apps) ? startup.startup_apps : []).slice(0, 2000).map((a, idx) => (
                          <tr key={`${a?.name || 'startup'}-${idx}`}>
                            <td style={{ whiteSpace: 'nowrap' }}>
                              {a?.enabled === 'enabled' ? (
                                <span className="evt-level info">有効</span>
                              ) : a?.enabled === 'disabled' ? (
                                <span className="evt-level warning">無効</span>
                              ) : (
                                <span className="evt-level">unknown</span>
                              )}
                            </td>
                            <td style={{ whiteSpace: 'nowrap' }}>{a?.name || ''}</td>
                            <td style={{ whiteSpace: 'nowrap' }}>{a?.source || ''}</td>
                            <td style={{ whiteSpace: 'nowrap' }}>{a?.user || ''}</td>
                            <td style={{ whiteSpace: 'nowrap' }}>{a?.location || ''}</td>
                            <td className="evt-msg">
                              {typeof a?.command === 'string' && a.command.length > 140 ? (
                                <details>
                                  <summary>{a.command.slice(0, 140) + '…'}</summary>
                                  <div style={{ marginTop: '0.35rem' }}>{a.command}</div>
                                </details>
                              ) : (
                                <div>{a?.command || ''}</div>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
            </div>
          )}
        </div>

        <div style={{ marginTop: '1.25rem' }}>
          <h4 style={{ color: 'var(--accent)', marginBottom: '0.5rem' }}>🕒 アプリの履歴（簡易版）</h4>
          <div className="packet-explanation" style={{ marginBottom: '0.75rem' }}>
            <div>💡 <strong>手順</strong></div>
            <ol style={{ margin: '0.35rem 0 0 1.2rem' }}>
              <li><strong>履歴サンプルを保存</strong>（1回目）</li>
              <li>数分待つ（差分を作る）</li>
              <li><strong>履歴サンプルを保存</strong>（2回目）</li>
              <li><strong>履歴を計算</strong>（差分集計を表示）</li>
            </ol>
            <div style={{ marginTop: '0.5rem' }}>
              ※ CPU時間/IOは累積値なので、履歴には2点以上のサンプルが必要です。
            </div>
          </div>

          <div className="packet-item" style={{ marginBottom: '0.75rem' }}>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', alignItems: 'center' }}>
            <label>
              <strong>since_hours:</strong>{' '}
              <input
                type="number"
                value={appHistSinceHours}
                min={1}
                max={8760}
                onChange={(e) => setAppHistSinceHours(Number(e.target.value))}
                style={{ width: '110px', marginLeft: '6px' }}
              />
            </label>
            <label>
              <strong>limit:</strong>{' '}
              <input
                type="number"
                value={appHistLimit}
                min={1}
                max={500}
                onChange={(e) => setAppHistLimit(Number(e.target.value))}
                style={{ width: '110px', marginLeft: '6px' }}
              />
            </label>
            </div>

            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', marginTop: '0.75rem' }}>
              <button className="button" onClick={saveAppHistorySample} disabled={loadingAppHistSample}>
                {loadingAppHistSample ? '保存中...' : '履歴サンプルを保存'}
              </button>
              <button className="button" onClick={fetchAppHistory} disabled={loadingAppHist}>
                {loadingAppHist ? '取得中...' : '履歴を計算'}
              </button>

              {appHist && (
                <button className="button" onClick={() => copyJson('アプリ履歴結果', appHist)}>
                  履歴結果をコピー（JSON）
                </button>
              )}
            </div>
          </div>

          {appHistSample && (
            <div className="packet-item" style={{ marginTop: '0.75rem', color: '#333' }}>
              <div><strong>last_sample:</strong> {appHistSample.collected_at} / hostname: {appHistSample.hostname}</div>
              {appHistSample.db_saved !== undefined && (
                <div><strong>db_saved:</strong> {String(appHistSample.db_saved)} {appHistSample.db_id ? `(id=${appHistSample.db_id})` : ''}</div>
              )}
              {appHistSample.db_error && <div><strong>db_error:</strong> {appHistSample.db_error}</div>}
            </div>
          )}

          {appHist && (
            <div style={{ marginTop: '0.75rem' }}>
              {appHist.ok ? (
                <>
                  <div style={{ marginBottom: '0.5rem' }}>
                    <div><strong>samples:</strong> {appHist.samples}</div>
                    <div><strong>from:</strong> {appHist.from?.collected_at} / <strong>to:</strong> {appHist.to?.collected_at}</div>
                    {appHist.note && <div style={{ color: '#666' }}>{appHist.note}</div>}
                  </div>

                  {Array.isArray(appHist.apps) && appHist.apps.length > 0 ? (
                    <div style={{ overflowX: 'auto' }}>
                      <table className="packet-table">
                        <thead>
                          <tr>
                            <th>name</th>
                            <th>cpu_total(s)</th>
                            <th>cpu_user(s)</th>
                            <th>cpu_system(s)</th>
                            <th>read</th>
                            <th>write</th>
                            <th>proc_count</th>
                          </tr>
                        </thead>
                        <tbody>
                          {appHist.apps.map((a, idx) => {
                            const cpuUser = Number(a.cpu_user_s || 0);
                            const cpuSys = Number(a.cpu_system_s || 0);
                            const cpuTotal = cpuUser + cpuSys;
                            return (
                              <tr key={`${a.name}-${idx}`}>
                                <td>{a.name}</td>
                                <td style={{ textAlign: 'right' }}>{cpuTotal.toFixed(2)}</td>
                                <td style={{ textAlign: 'right' }}>{cpuUser.toFixed(2)}</td>
                                <td style={{ textAlign: 'right' }}>{cpuSys.toFixed(2)}</td>
                                <td style={{ textAlign: 'right' }}>{formatBytes(a.io_read_bytes || 0)}</td>
                                <td style={{ textAlign: 'right' }}>{formatBytes(a.io_write_bytes || 0)}</td>
                                <td style={{ textAlign: 'right' }}>{a.process_count ?? 0}</td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div style={{ color: '#666' }}>集計結果がありません（プロセスが入れ替わった可能性があります）</div>
                  )}
                </>
              ) : (
                <div style={{ color: '#666' }}>{appHist.message || '履歴を計算できませんでした'}</div>
              )}
            </div>
          )}
        </div>
      </div>
      )}

      {activeMonitorTab === 'eventlog' && (
      <div className="info-item">
        <h3 style={{ marginTop: 0 }}>📜 イベントログ（イベントビューア相当）</h3>

        <div className="packet-explanation" style={{ marginBottom: '0.75rem' }}>
          <div>💡 <strong>手順（おすすめ）</strong></div>
          <ul style={{ margin: '0.35rem 0 0 1.2rem' }}>
            <li><strong>ログ一覧を取得</strong> → ログ名（LogName）を確認</li>
            <li><strong>log</strong> に貼り付け → <strong>イベントログを取得</strong></li>
          </ul>
          <div style={{ marginTop: '0.5rem' }}><strong>入力の意味</strong></div>
          <ul style={{ margin: '0.35rem 0 0 1.2rem' }}>
            <li>
              <strong>log</strong>: 取得するログ名（<strong>LogName</strong>）
              <div style={{ color: '#555', marginTop: '0.15rem' }}>
                LogName は、Windowsイベントログの「どのログ（チャネル）」から取得するかを指定する名前です。
                この画面の <strong>ログ一覧を取得</strong> で確認できます。
                イベントビューア上では、左ツリーの「どの場所のログか」に対応します。
                <div style={{ marginTop: '0.25rem' }}>
                  <strong>Windowsログ</strong>（基本の3種類）:
                  <ul style={{ margin: '0.25rem 0 0 1.2rem' }}>
                    <li>Windowsログ → <strong>System</strong>（OS/ドライバ/サービス起因のイベントが多い）</li>
                    <li>Windowsログ → <strong>Application</strong>（アプリ/サービスのエラーや情報が多い）</li>
                    <li>Windowsログ → <strong>Security</strong>（監査ログ。環境により管理者権限が必要）</li>
                  </ul>
                </div>
                <div style={{ marginTop: '0.25rem' }}>
                  <strong>アプリケーションとサービス ログ</strong>（製品/機能ごとの詳細ログ）:
                  <ul style={{ margin: '0.25rem 0 0 1.2rem' }}>
                    <li>アプリケーションとサービス ログ → Microsoft → Windows → （機能名） → <strong>Operational</strong></li>
                    <li>
                      例: Microsoft → Windows → Windows Defender → Operational
                      <div style={{ color: '#666', marginTop: '0.15rem' }}>
                        LogName: <strong>Microsoft-Windows-Windows Defender/Operational</strong>
                      </div>
                    </li>
                    <li>
                      例: Microsoft → Windows → PowerShell → Operational
                      <div style={{ color: '#666', marginTop: '0.15rem' }}>
                        LogName: <strong>Microsoft-Windows-PowerShell/Operational</strong>
                      </div>
                    </li>
                  </ul>
                  <div style={{ color: '#666', marginTop: '0.15rem' }}>
                    ※「Operational」は“運用ログ”の意味で、機能ごとに別チャネルとして存在します。
                    ログによっては無効（IsEnabled=false）な場合があり、その場合はイベントビューアで有効化が必要です。
                  </div>
                </div>
              </div>
              <div style={{ color: '#555', marginTop: '0.15rem' }}>
                例: <strong>System</strong> / <strong>Application</strong> / <strong>Security</strong> / <strong>Microsoft-Windows-Windows Defender/Operational</strong>
              </div>
            </li>
            <li><strong>since_hours</strong>: 何時間前まで遡るか（例: 24 = 過去24時間）</li>
            <li><strong>max_events</strong>: 最大取得件数（多いほど重くなります）</li>
            <li><strong>timeout_s</strong>: 取得のタイムアウト秒数（重い場合は増やします）</li>
          </ul>
          <div style={{ marginTop: '0.5rem' }}>⚠️ <strong>注意</strong>: <strong>Security</strong> は管理者権限が必要な場合があります。失敗する場合は <strong>System</strong> / <strong>Application</strong> で試してください。</div>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', marginBottom: '0.75rem' }}>
          <label>
            <strong>log:</strong>{' '}
            <input
              list="eventlog-presets"
              value={evtLogName}
              onChange={(e) => setEvtLogName(e.target.value)}
              placeholder="例: Microsoft-Windows-Windows Defender/Operational"
              style={{ width: '340px', marginLeft: '6px' }}
            />
            <datalist id="eventlog-presets">
              <option value="System" />
              <option value="Application" />
              <option value="Security" />
              {Array.isArray(evtLogs?.logs) &&
                evtLogs.logs
                  .map((x) => x?.LogName)
                  .filter((name) => typeof name === 'string' && name)
                  .slice(0, 200)
                  .map((name) => <option key={name} value={name} />)}
            </datalist>
          </label>
          <label>
            <strong>since_hours:</strong>{' '}
            <input
              type="number"
              value={evtSinceHours}
              min={1}
              max={8760}
              onChange={(e) => setEvtSinceHours(Number(e.target.value))}
              style={{ width: '110px', marginLeft: '6px' }}
            />
          </label>
          <label>
            <strong>max_events:</strong>{' '}
            <input
              type="number"
              value={evtMaxEvents}
              min={1}
              max={5000}
              onChange={(e) => setEvtMaxEvents(Number(e.target.value))}
              style={{ width: '110px', marginLeft: '6px' }}
            />
          </label>
          <label>
            <strong>timeout_s:</strong>{' '}
            <input
              type="number"
              value={evtTimeoutS}
              min={5}
              max={120}
              onChange={(e) => setEvtTimeoutS(Number(e.target.value))}
              style={{ width: '110px', marginLeft: '6px' }}
            />
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <input type="checkbox" checked={evtSave} onChange={(e) => setEvtSave(e.target.checked)} />
            <strong>DBに保存</strong>
          </label>
        </div>

        <button className="button" onClick={fetchEventLog} disabled={loadingEvt}>
          {loadingEvt ? '取得中...' : 'イベントログを取得'}
        </button>

        <button className="button" onClick={fetchEventLogList} disabled={loadingEvtLogs} style={{ marginLeft: '8px' }}>
          {loadingEvtLogs ? '取得中...' : 'ログ一覧を取得'}
        </button>

        {evt && (
          <button className="button" onClick={() => copyJson('イベントログ結果', evt)}>
            イベントログ結果をコピー（JSON）
          </button>
        )}

        {evtLogs && (
          <button className="button" onClick={() => copyJson('ログ一覧', evtLogs)}>
            ログ一覧をコピー（JSON）
          </button>
        )}

        {evtLogs && (
          <div style={{ marginTop: '0.75rem' }}>
            <div style={{ marginBottom: '0.25rem', color: '#333' }}>
              <strong>ログ一覧:</strong> {String(evtLogs?.summary?.count ?? (Array.isArray(evtLogs?.logs) ? evtLogs.logs.length : 0))}
              {evtLogs?.summary?.limit ? ` (limit ${evtLogs.summary.limit})` : ''}
            </div>
            {evtLogs?.summary?.error ? (
              <div className="error">{String(evtLogs.summary.error)}</div>
            ) : (
              <div className="packet-item" style={{ maxHeight: '180px', overflowY: 'auto' }}>
                {Array.isArray(evtLogs.logs) && evtLogs.logs.length > 0 ? (
                  evtLogs.logs.map((l, idx) => (
                    <div key={idx} style={{ padding: '2px 0' }}>
                      {l?.LogName || '(unknown)'}
                    </div>
                  ))
                ) : (
                  <div style={{ color: '#666' }}>(empty)</div>
                )}
              </div>
            )}
          </div>
        )}

        {evt && (
          <div style={{ marginTop: '1rem' }}>
            <div style={{ marginBottom: '0.75rem' }}>
              <div><strong>collected_at:</strong> {evt.collected_at}</div>
              <div><strong>hostname:</strong> {evt.hostname}</div>
              <div><strong>log_name:</strong> {evt.log_name}</div>
              <div><strong>since_hours:</strong> {evt.since_hours}</div>
              <div><strong>max_events:</strong> {evt.max_events}</div>
              {evt.db_saved !== undefined && (
                <div><strong>db_saved:</strong> {String(evt.db_saved)} {evt.db_id ? `(id=${evt.db_id})` : ''}</div>
              )}
              {evt.db_error && <div><strong>db_error:</strong> {evt.db_error}</div>}
            </div>

            {evt.summary?.error && (
              <div className="error">{evt.summary.error}</div>
            )}

            {evt.summary && !evt.summary?.error && (
              <div>
                <h4 style={{ color: 'var(--accent)', marginBottom: '0.5rem' }}>概要</h4>
                <div><strong>event_count:</strong> {evt.summary.event_count}</div>

                {evt.summary.level_counts && (
                  <div style={{ marginTop: '0.5rem' }}>
                    <strong>level_counts:</strong>{' '}
                    {Object.entries(evt.summary.level_counts).map(([k, v]) => (
                      <span key={k} style={{ marginRight: '10px' }}>{k}:{v}</span>
                    ))}
                  </div>
                )}

                {evt.summary.top_providers && evt.summary.top_providers.length > 0 && (
                  <div style={{ marginTop: '0.75rem' }}>
                    <strong>top_providers:</strong>
                    <div style={{ marginTop: '0.25rem' }}>
                      {evt.summary.top_providers.map(([name, count], idx) => (
                        <div key={idx}>{name}: {count}</div>
                      ))}
                    </div>
                  </div>
                )}

                {evt.summary.top_event_ids && evt.summary.top_event_ids.length > 0 && (
                  <div style={{ marginTop: '0.75rem' }}>
                    <strong>top_event_ids:</strong>
                    <div style={{ marginTop: '0.25rem' }}>
                      {evt.summary.top_event_ids.map(([id, count], idx) => (
                        <div key={idx}>Id {id}: {count}</div>
                      ))}
                    </div>
                  </div>
                )}

                {(() => {
                  const events = Array.isArray(evt.events) ? evt.events : [];

                  const getLevel = (x) => (typeof x?.LevelDisplayName === 'string' ? x.LevelDisplayName : '');
                  const isErrorLike = (lvl) =>
                    typeof lvl === 'string' &&
                    (lvl.includes('エラー') || lvl.toLowerCase() === 'error' || lvl.toLowerCase() === 'critical');
                  const isWarningLike = (lvl) => typeof lvl === 'string' && (lvl.includes('警告') || lvl.toLowerCase() === 'warning');

                  const errorEvents = events.filter((e) => isErrorLike(getLevel(e))).slice(0, 50);
                  const warnEvents = events.filter((e) => isWarningLike(getLevel(e))).slice(0, 50);

                  const fallback = Array.isArray(evt.summary?.error_samples) ? evt.summary.error_samples : [];
                  const hasAny = errorEvents.length > 0 || warnEvents.length > 0 || fallback.length > 0;
                  if (!hasAny) return null;

                  const renderTable = (title, rows) => (
                    <div style={{ marginTop: '0.75rem' }}>
                      <h4 style={{ color: 'var(--accent)', marginBottom: '0.25rem' }}>{title}（{rows.length}件）</h4>
                      <div className="evt-muted" style={{ marginBottom: '0.5rem' }}>※ 表示は先頭50件まで</div>

                      {(() => {
                        const parseMsDate = (s) => {
                          if (typeof s !== 'string') return null;
                          const m = s.match(/\/Date\((\d+)\)\//);
                          if (!m) return null;
                          const ms = Number(m[1]);
                          return Number.isFinite(ms) ? new Date(ms) : null;
                        };

                        const formatTime = (tc) => {
                          if (!tc) return '';
                          const d1 = parseMsDate(tc);
                          if (d1) return d1.toLocaleString();
                          if (typeof tc === 'string') {
                            const d2 = new Date(tc);
                            if (!Number.isNaN(d2.getTime())) return d2.toLocaleString();
                            return tc;
                          }
                          return String(tc);
                        };

                        const levelClass = (lvl) => {
                          const s = typeof lvl === 'string' ? lvl : '';
                          const lower = s.toLowerCase();
                          if (s.includes('エラー') || lower === 'error' || lower === 'critical') return 'evt-level error';
                          if (s.includes('警告') || lower === 'warning') return 'evt-level warning';
                          return 'evt-level info';
                        };

                        const shortMessage = (msg) => {
                          const s = typeof msg === 'string' ? msg : '';
                          const oneLine = s.replace(/\s+/g, ' ').trim();
                          if (oneLine.length <= 140) return oneLine;
                          return oneLine.slice(0, 140) + '…';
                        };

                        return (
                          <div style={{ overflowX: 'auto' }}>
                            <table className="packet-table">
                              <thead>
                                <tr>
                                  <th style={{ whiteSpace: 'nowrap' }}>時刻</th>
                                  <th style={{ whiteSpace: 'nowrap' }}>レベル</th>
                                  <th style={{ whiteSpace: 'nowrap' }}>Provider</th>
                                  <th style={{ whiteSpace: 'nowrap' }}>Id</th>
                                  <th>メッセージ</th>
                                </tr>
                              </thead>
                              <tbody>
                                {rows.map((e, idx) => {
                                  const full = typeof e?.Message === 'string' ? e.Message : '';
                                  const summary = shortMessage(full);
                                  const showDetails = full && summary !== full;
                                  return (
                                    <tr key={idx}>
                                      <td style={{ whiteSpace: 'nowrap' }}>{formatTime(e?.TimeCreated)}</td>
                                      <td style={{ whiteSpace: 'nowrap' }}>
                                        <span className={levelClass(e?.LevelDisplayName)}>
                                          {e?.LevelDisplayName || ''}
                                        </span>
                                      </td>
                                      <td style={{ whiteSpace: 'nowrap' }}>{e?.ProviderName || ''}</td>
                                      <td style={{ whiteSpace: 'nowrap' }}>{e?.Id ?? ''}</td>
                                      <td className="evt-msg">
                                        {showDetails ? (
                                          <details>
                                            <summary>{summary}</summary>
                                            <div style={{ marginTop: '0.35rem' }}>{full}</div>
                                          </details>
                                        ) : (
                                          <div>{summary}</div>
                                        )}
                                      </td>
                                    </tr>
                                  );
                                })}
                              </tbody>
                            </table>
                          </div>
                        );
                      })()}
                    </div>
                  );

                  return (
                    <div style={{ marginTop: '1rem' }}>
                      {errorEvents.length > 0 && renderTable('エラー（具体一覧）', errorEvents)}
                      {warnEvents.length > 0 && renderTable('警告（具体一覧）', warnEvents)}
                      {errorEvents.length === 0 && warnEvents.length === 0 && fallback.length > 0 && (
                        <div style={{ marginTop: '0.75rem' }}>
                          <h4 style={{ color: 'var(--accent)', marginBottom: '0.5rem' }}>エラー/警告（サンプル）</h4>
                          {fallback.map((s, idx) => (
                            <div key={idx} className="packet-item" style={{ marginBottom: '0.5rem' }}>
                              <div><strong>{s.LevelDisplayName}</strong> {s.TimeCreated}</div>
                              <div>Provider: {s.ProviderName} / Id: {s.Id}</div>
                              {s.Message && <div style={{ marginTop: '0.25rem', color: '#333' }}>{s.Message}</div>}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })()}
              </div>
            )}
          </div>
        )}
      </div>
      )}

      <div className="info-item" style={{ marginTop: '1rem' }}>
        <h3 style={{ marginTop: 0 }}>🗄️ PostgreSQL 接続</h3>
        <button className="button" onClick={fetchDbHealth} disabled={loadingDb}>
          {loadingDb ? '確認中...' : 'DBヘルスチェック'}
        </button>
        {dbHealth && (
          <div style={{ marginTop: '0.5rem', lineHeight: '1.8' }}>
            <div><strong>configured:</strong> {String(dbHealth.configured)}</div>
            <div><strong>ok:</strong> {String(dbHealth.ok)}</div>
            {dbHealth.message && <div><strong>message:</strong> {dbHealth.message}</div>}
            {dbHealth.error && <div><strong>error:</strong> {dbHealth.error}</div>}
          </div>
        )}
      </div>
    </div>
  );
}

export default SystemMonitor;
