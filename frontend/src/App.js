import React, { useState } from 'react';
import NetworkInfo from './components/NetworkInfo';
import WiFiInfo from './components/WiFiInfo';
import NetworkStats from './components/NetworkStats';
import PacketCapture from './components/PacketCapture';
import PacketAnalysis from './components/PacketAnalysis';
import PacketChatbot from './components/PacketChatbot';
import SystemMonitor from './components/SystemMonitor';
import RegistryEditor from './components/RegistryEditor';
import ConnectivityCheck from './components/ConnectivityCheck';
import SecuritySummary from './components/SecuritySummary';
import ConnectionsList from './components/ConnectionsList';
import ExportReport from './components/ExportReport';
import LanDevices from './components/LanDevices';
import NmapScan from './components/NmapScan';
import './App.css';

function App() {
  const [activeTab, setActiveTab] = useState('network');

  return (
    <div className="App">
      <header className="App-header">
        <h1>🌐 ネットワーク監視ダッシュボード</h1>
        <p className="subtitle">ネットワーク状態・パケット・システム情報をまとめて確認</p>
      </header>

      <nav className="tab-navigation">
        <button
          className={activeTab === 'network' ? 'active' : ''}
          onClick={() => setActiveTab('network')}
        >
          📡 ネットワーク情報
        </button>
        <button
          className={activeTab === 'wifi' ? 'active' : ''}
          onClick={() => setActiveTab('wifi')}
        >
          📶 WiFi情報
        </button>
        <button
          className={activeTab === 'stats' ? 'active' : ''}
          onClick={() => setActiveTab('stats')}
        >
          📊 トラフィック統計
        </button>
        <button
          className={activeTab === 'lanDevices' ? 'active' : ''}
          onClick={() => setActiveTab('lanDevices')}
        >
          🖧 LAN機器一覧
        </button>
        <button
          className={activeTab === 'nmap' ? 'active' : ''}
          onClick={() => setActiveTab('nmap')}
        >
          🗺️ NMAPスキャン
        </button>
        <button
          className={activeTab === 'capture' ? 'active' : ''}
          onClick={() => setActiveTab('capture')}
        >
          🔍 パケットキャプチャ
        </button>
        <button
          className={activeTab === 'analysis' ? 'active' : ''}
          onClick={() => setActiveTab('analysis')}
        >
          📈 パケットキャプチャ統計解析
        </button>
        <button
          className={activeTab === 'sysSpecs' ? 'active' : ''}
          onClick={() => setActiveTab('sysSpecs')}
        >
          💻 PCスペック
        </button>
        <button
          className={activeTab === 'sysProcess' ? 'active' : ''}
          onClick={() => setActiveTab('sysProcess')}
        >
          📌 タスクマネージャー
        </button>
        <button
          className={activeTab === 'sysEventlog' ? 'active' : ''}
          onClick={() => setActiveTab('sysEventlog')}
        >
          📜 イベントビュアー
        </button>
        <button
          className={activeTab === 'registry' ? 'active' : ''}
          onClick={() => setActiveTab('registry')}
        >
          レジストリエディタ
        </button>
        <button
          className={activeTab === 'connectivity' ? 'active' : ''}
          onClick={() => setActiveTab('connectivity')}
        >
          🧪 疎通チェック
        </button>
        <button
          className={activeTab === 'securitySummary' ? 'active' : ''}
          onClick={() => setActiveTab('securitySummary')}
        >
          🛡️ セキュリティ要約
        </button>
        <button
          className={activeTab === 'connections' ? 'active' : ''}
          onClick={() => setActiveTab('connections')}
        >
          🔌 接続先一覧
        </button>
        <button
          className={activeTab === 'exportReport' ? 'active' : ''}
          onClick={() => setActiveTab('exportReport')}
        >
          📄 全体レポート
        </button>
        <button
          className={activeTab === 'chatbot' ? 'active' : ''}
          onClick={() => setActiveTab('chatbot')}
        >
          💬 相談チャット
        </button>
      </nav>

      <main className="main-content">
        {activeTab === 'network' && <NetworkInfo />}
        {activeTab === 'wifi' && <WiFiInfo />}
        {activeTab === 'stats' && <NetworkStats />}
        {activeTab === 'lanDevices' && <LanDevices />}
        {activeTab === 'nmap' && <NmapScan />}
        {activeTab === 'capture' && <PacketCapture />}
        {activeTab === 'analysis' && <PacketAnalysis />}
        {activeTab === 'sysSpecs' && <SystemMonitor initialTab="specs" showSubTabs={false} />}
        {activeTab === 'sysProcess' && <SystemMonitor initialTab="process" showSubTabs={false} />}
        {activeTab === 'sysEventlog' && <SystemMonitor initialTab="eventlog" showSubTabs={false} />}
        {activeTab === 'registry' && <RegistryEditor />}
        {activeTab === 'connectivity' && <ConnectivityCheck />}
        {activeTab === 'securitySummary' && <SecuritySummary />}
        {activeTab === 'connections' && <ConnectionsList />}
        {activeTab === 'exportReport' && <ExportReport />}
        {activeTab === 'chatbot' && <PacketChatbot />}
      </main>

      <footer className="App-footer">
        <p>© 2025 ネットワーク診断ツール - 初心者にもわかりやすいネットワーク監視</p>
      </footer>
    </div>
  );
}

export default App;
