import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';

function PacketChatbot() {
  const initialAssistantMessage = {
    role: 'assistant',
    content: 'こんにちは！パケットキャプチャ相談チャットボットです。🤖\n\nネットワークやパケットキャプチャに関する質問にお答えします。例えば:\n\n• パケットキャプチャの使い方\n• 特定のプロトコルについて\n• セキュリティの懸念事項\n• エラーのトラブルシューティング\n• ネットワーク用語の解説\n\n何でもお気軽にお尋ねください！'
  };

  const [conversationId, setConversationId] = useState('default');
  const [conversations, setConversations] = useState([]);
  const [messages, setMessages] = useState([initialAssistantMessage]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [, setStatistics] = useState(null);
  const messagesEndRef = useRef(null);

  // よくある質問のサンプル
  const quickQuestions = [
    'パケットキャプチャとは何ですか？',
    'TCPとUDPの違いは？',
    'HTTPSは安全ですか？',
    '不審なポートとは？',
    'ポートスキャンとは何ですか？',
    'パケット解析の方法は？'
  ];

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  useEffect(() => {
    // 統計データを取得
    fetchStatistics();
    // 会話一覧 + 初期会話の履歴を復元
    refreshConversations();
  }, []);

  useEffect(() => {
    // 会話切替時は履歴を再読み込み
    loadHistory(conversationId);
  }, [conversationId]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const fetchStatistics = async () => {
    try {
      const response = await axios.get('http://localhost:5000/api/capture/statistics');
      if (response.data.total_packets > 0) {
        setStatistics(response.data);
      }
    } catch (err) {
      console.error('Statistics fetch error:', err);
    }
  };

  const refreshConversations = async () => {
    try {
      const response = await axios.get('http://localhost:5000/api/chatbot/conversations', {
        params: { limit: 200 }
      });
      const data = response.data;
      const list = Array.isArray(data?.conversations) ? data.conversations : [];
      setConversations(list);
    } catch (err) {
      console.debug('Chat conversations load skipped:', err?.message || err);
    }
  };

  const loadHistory = async (cid) => {
    try {
      const response = await axios.get('http://localhost:5000/api/chatbot/history', {
        params: { conversation_id: cid, limit: 400 }
      });
      const data = response.data;
      const history = Array.isArray(data?.messages) ? data.messages : [];
      if (history.length > 0) {
        setMessages(history.map(m => ({ role: m.role, content: m.content })));
      } else {
        setMessages([initialAssistantMessage]);
      }
    } catch (err) {
      // DB未設定でもチャット自体は動かす
      console.debug('Chat history load skipped:', err?.message || err);
    }
  };

  const clearHistory = async (cid) => {
    try {
      await axios.delete('http://localhost:5000/api/chatbot/history', {
        params: { conversation_id: cid }
      });
      if (cid === conversationId) {
        setMessages([{ role: 'assistant', content: '履歴をクリアしました。続けてご質問ください。' }]);
      }
      await refreshConversations();
    } catch (err) {
      console.error('Chat history clear error:', err);
    }
  };

  const startNewConversation = () => {
    const pad = (n) => String(n).padStart(2, '0');
    const d = new Date();
    const id = `conv-${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
    setConversationId(id);
    setMessages([initialAssistantMessage]);
    setInput('');
  };

  const handleSend = async () => {
    if (!input.trim()) return;

    const userMessage = input.trim();
    setInput('');
    
    // ユーザーメッセージを追加
    setMessages(prev => [...prev, { role: 'user', content: userMessage }]);
    setLoading(true);

    try {
      // ボットの応答を生成
      const response = await generateResponse(userMessage);
      
      setTimeout(() => {
        setMessages(prev => [...prev, { role: 'assistant', content: response }]);
        setLoading(false);
        refreshConversations();
      }, 500);
    } catch (err) {
      setMessages(prev => [...prev, { 
        role: 'assistant', 
        content: '申し訳ございません。エラーが発生しました。もう一度お試しください。' 
      }]);
      setLoading(false);
    }
  };

  const generateResponse = async (question) => {
    try {
      const response = await axios.post('http://localhost:5000/api/chatbot', { question, conversation_id: conversationId });
      return response.data.answer || '回答が取得できませんでした。';
    } catch (err) {
      return 'サーバーとの通信に失敗しました。バックエンドが起動しているか確認してください。';
    }
  };

  const handleQuickQuestion = (question) => {
    setInput(question);
  };

  return (
    <div className="card" style={{ height: '95vh', display: 'flex', flexDirection: 'column' }}>
      <h2>💬 パケットキャプチャ相談チャットボット</h2>

      <div style={{ flex: '1 1 auto', display: 'flex', gap: '12px', minHeight: 0 }}>
        {/* 左: 履歴ナビ */}
        <div style={{
          width: '320px',
          flex: '0 0 320px',
          border: '1px solid var(--border)',
          borderRadius: '10px',
          backgroundColor: 'var(--surface-2)',
          padding: '10px',
          display: 'flex',
          flexDirection: 'column',
          gap: '8px',
          minHeight: 0
        }}>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button className="button" onClick={startNewConversation} disabled={loading} style={{ padding: '10px 12px', fontSize: '13px', marginRight: 0, marginBottom: 0, flex: 1 }}>
              ➕ 新規
            </button>
            <button className="button" onClick={refreshConversations} disabled={loading} style={{ padding: '10px 12px', fontSize: '13px', marginRight: 0, marginBottom: 0 }} title="会話一覧を再読込">
              🔄
            </button>
          </div>

          <div style={{ fontSize: '12px', color: 'var(--muted)' }}>
            選択中: <strong style={{ color: 'var(--accent-strong)' }}>{conversationId}</strong>
          </div>

          <div style={{ flex: '1 1 auto', overflowY: 'auto', minHeight: 0 }}>
            {(() => {
              const hasCurrent = conversations.some(c => c.conversation_id === conversationId);
              const list = hasCurrent
                ? conversations
                : [{ conversation_id: conversationId, last_message_at: null, message_count: 0, _unsaved: true }, ...conversations];

              if (list.length === 0) {
                return (
                  <div style={{ fontSize: '13px', color: 'var(--muted)', padding: '8px' }}>
                    まだ保存された履歴がありません。
                  </div>
                );
              }

              return (
                <>
                  {list.map((c) => {
                    const id = c.conversation_id;
                    const isActive = id === conversationId;
                    const count = c.message_count ?? 0;
                    const last = c.last_message_at ? new Date(c.last_message_at).toLocaleString() : '';
                    const unsaved = c._unsaved === true;
                    return (
                      <div
                        key={id}
                        onClick={() => setConversationId(id)}
                        style={{
                          border: '1px solid var(--border)',
                          borderRadius: '10px',
                          padding: '10px',
                          marginBottom: '8px',
                          cursor: 'pointer',
                          backgroundColor: isActive ? 'var(--surface)' : 'transparent'
                        }}
                        title={id}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', gap: '8px' }}>
                          <div style={{ fontWeight: 700, fontSize: '13px', color: isActive ? 'var(--accent-strong)' : 'var(--text)' }}>
                            {id}{unsaved ? ' (未保存)' : ''}
                          </div>
                          <button
                            className="button"
                            onClick={(e) => { e.stopPropagation(); clearHistory(id); }}
                            disabled={loading}
                            style={{ padding: '6px 10px', fontSize: '12px', marginRight: 0, marginBottom: 0 }}
                            title="この会話の履歴を削除"
                          >
                            🗑️
                          </button>
                        </div>
                        <div style={{ fontSize: '12px', color: 'var(--muted)', marginTop: '6px' }}>
                          {count} 件 / 最終: {last}
                        </div>
                        {isActive && (
                          <div style={{ display: 'flex', gap: '8px', marginTop: '8px' }}>
                            <button
                              className="button"
                              onClick={(e) => { e.stopPropagation(); loadHistory(id); }}
                              disabled={loading}
                              style={{ padding: '8px 10px', fontSize: '12px', marginRight: 0, marginBottom: 0, flex: 1 }}
                            >
                              🔄 再読込
                            </button>
                            <button
                              className="button"
                              onClick={(e) => { e.stopPropagation(); clearHistory(id); }}
                              disabled={loading}
                              style={{ padding: '8px 10px', fontSize: '12px', marginRight: 0, marginBottom: 0, flex: 1 }}
                            >
                              🗑️ クリア
                            </button>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </>
              );
            })()}
          </div>
        </div>

        {/* 右: チャット本体 */}
        <div style={{ flex: '1 1 auto', display: 'flex', flexDirection: 'column', minWidth: 0 }}>
      
      <div style={{ 
        marginBottom: '10px', 
        padding: '8px', 
        backgroundColor: 'var(--surface-2)', 
        borderRadius: '8px',
        fontSize: '14px'
      }}>
        <strong>💡 ヒント:</strong> ネットワークやパケットキャプチャに関する質問にお答えします。
        下のクイックボタンまたは自由に質問を入力してください。
      </div>

      {/* クイックボタン */}
      <div style={{ 
        display: 'flex', 
        flexWrap: 'wrap', 
        gap: '8px', 
        marginBottom: '6px',
        padding: '8px',
        backgroundColor: 'var(--surface-2)',
        borderRadius: '8px'
      }}>
        <div style={{ width: '100%', marginBottom: '5px', fontSize: '13px', fontWeight: 'bold' }}>
          よくある質問:
        </div>
        {quickQuestions.map((q, idx) => (
          <button
            key={idx}
            onClick={() => handleQuickQuestion(q)}
            style={{
              padding: '6px 12px',
              fontSize: '12px',
              backgroundColor: 'var(--surface-2)',
              border: '1px solid var(--border)',
              borderRadius: '15px',
              cursor: 'pointer',
              transition: 'all 0.2s'
            }}
            onMouseEnter={(e) => {
              e.target.style.backgroundColor = 'var(--surface)';
              e.target.style.color = 'var(--accent-strong)';
            }}
            onMouseLeave={(e) => {
              e.target.style.backgroundColor = 'var(--surface-2)';
              e.target.style.color = 'var(--text)';
            }}
          >
            {q}
          </button>
        ))}
      </div>

      {/* メッセージエリア */}
      <div style={{
        flex: '1 1 auto',
        overflowY: 'auto',
        padding: '6px',
        backgroundColor: 'var(--surface-2)',
        borderRadius: '8px',
        marginBottom: '6px',
        border: '1px solid var(--border)'
      }}>
        {messages.map((msg, idx) => (
          <div
            key={idx}
            style={{
              display: 'flex',
              justifyContent: 'flex-start',
              marginBottom: '15px',
              width: '100%'
            }}
          >
            <div
              style={{
                maxWidth: 'calc(100% - 40px)',
                width: 'auto',
                padding: '14px 18px',
                borderRadius: '14px',
                backgroundColor: msg.role === 'user' ? 'var(--surface)' : 'var(--surface-2)',
                color: msg.role === 'user' ? 'var(--accent-strong)' : 'var(--text)',
                boxShadow: '0 2px 8px rgba(0,0,0,0.08)',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                fontSize: '15px',
                lineHeight: '1.6',
                marginLeft: msg.role === 'user' ? 'auto' : '8px',
                marginRight: msg.role === 'user' ? '8px' : '0'
              }}
            >
              {msg.role === 'assistant' && (
                <div style={{ marginBottom: '8px', fontSize: '20px' }}>🤖</div>
              )}
              {msg.content}
            </div>
          </div>
        ))}
        
        {loading && (
          <div style={{ display: 'flex', justifyContent: 'flex-start', marginBottom: '15px' }}>
            <div style={{
              padding: '12px 16px',
              borderRadius: '12px',
              backgroundColor: 'var(--surface-2)',
              boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
            }}>
              <div style={{ fontSize: '20px', marginBottom: '8px' }}>🤖</div>
              <div style={{ display: 'flex', gap: '5px', alignItems: 'center' }}>
                <span>考え中</span>
                <span className="loading-dots">...</span>
              </div>
            </div>
          </div>
        )}
        
        <div ref={messagesEndRef} />
      </div>

      {/* 入力エリア */}
      <div style={{ display: 'flex', gap: '10px', alignItems: 'flex-end' }}>
        <textarea
          rows={3}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSend(); } }}
          placeholder="質問を入力してください..."
          disabled={loading}
          style={{
            flex: 1,
            padding: '14px 16px',
            fontSize: '15px',
            border: '1px solid var(--border)',
            borderRadius: '8px',
            outline: 'none',
            minHeight: '80px',
            resize: 'vertical',
            backgroundColor: 'var(--surface-2)',
            color: 'var(--text)'
          }}
        />
        <button
          onClick={handleSend}
          disabled={loading || !input.trim()}
          className="button"
          style={{
            padding: '12px 24px',
            fontSize: '14px',
            alignSelf: 'flex-end'
          }}
        >
          {loading ? '送信中...' : '📤 送信'}
        </button>
      </div>

      <style>{`
        @keyframes blink {
          0%, 20% { opacity: 0; }
          40% { opacity: 1; }
          100% { opacity: 0; }
        }
        .loading-dots span:nth-child(1) {
          animation: blink 1.4s infinite;
        }
        .loading-dots span:nth-child(2) {
          animation: blink 1.4s infinite 0.2s;
        }
        .loading-dots span:nth-child(3) {
          animation: blink 1.4s infinite 0.4s;
        }
      `}</style>
        </div>
      </div>
    </div>
  );
}

export default PacketChatbot;
