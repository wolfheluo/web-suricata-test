import { useEffect, useRef, useState } from 'react';

interface Props {
  taskId: string;
  onDone: () => void;
  onError: () => void;
}

export default function ProgressModal({ taskId, onDone, onError }: Props) {
  const [step, setStep] = useState('connecting');
  const [progress, setProgress] = useState(0);
  const [message, setMessage] = useState('正在連線...');
  const wsRef = useRef<WebSocket | null>(null);
  const stepRef = useRef(step);
  stepRef.current = step;

  useEffect(() => {
    let cancelled = false;
    const token = localStorage.getItem('access_token');
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${proto}://${window.location.host}/ws/task/${taskId}?token=${token}`);
    wsRef.current = ws;

    ws.onmessage = (e) => {
      if (cancelled) return;
      const data = JSON.parse(e.data);
      if (data.step === 'ping') return; // heartbeat, ignore
      setStep(data.step);
      setProgress(data.progress);
      setMessage(data.message || data.step);
      if (data.step === 'done') setTimeout(onDone, 500);
      if (data.step === 'error') setTimeout(onError, 2000);
    };

    ws.onerror = () => {
      if (cancelled) return;
      if (stepRef.current !== 'done') {
        setStep('ws_error');
        setMessage('WebSocket 連線失敗，任務仍在背景執行中');
      }
    };
    ws.onclose = () => {
      if (cancelled) return;
      if (stepRef.current !== 'done' && stepRef.current !== 'error' && stepRef.current !== 'ws_error') {
        setStep('ws_error');
        setMessage('WebSocket 連線中斷，任務仍在背景執行中');
      }
    };

    return () => { cancelled = true; ws.close(); };
  }, [taskId]);

  const stepLabels: Record<string, string> = {
    connecting: '連線中',
    suricata: 'Suricata 分析',
    tshark: 'tshark 分析',
    deep: '深度封包分析',
    dns: 'DNS 分析',
    http: 'HTTP 分析',
    tls: 'TLS 分析',
    report: '報告產生',
    done: '完成',
    error: '錯誤',
    ws_error: '連線中斷',
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl p-8 w-full max-w-md">
        <h2 className="text-lg font-bold text-gray-800 mb-4">分析進度</h2>
        <div className="mb-2 text-sm text-gray-600">
          {stepLabels[step] || step}
        </div>
        <div className="w-full bg-gray-200 rounded-full h-4 mb-3">
          <div
            className={`h-4 rounded-full transition-all duration-300 ${
              step === 'error' || step === 'ws_error' ? 'bg-red-500' : step === 'done' ? 'bg-green-500' : 'bg-blue-500'
            }`}
            style={{ width: `${Math.max(progress, 2)}%` }}
          />
        </div>
        <div className="text-xs text-gray-400">{message}</div>
        {step === 'done' && <div className="mt-4 text-green-600 font-medium">分析完成！即將跳轉...</div>}
        {step === 'error' && <div className="mt-4 text-red-600 font-medium">分析失敗：{message}</div>}
        {step === 'ws_error' && (
          <div className="mt-4">
            <div className="text-amber-600 text-sm mb-3">連線已中斷，但任務仍在背景執行。</div>
            <div className="flex gap-2">
              <button
                onClick={onDone}
                className="flex-1 bg-blue-600 text-white py-2 rounded-md hover:bg-blue-700 text-sm"
              >
                查看任務狀態
              </button>
              <button
                onClick={onError}
                className="flex-1 bg-gray-200 text-gray-700 py-2 rounded-md hover:bg-gray-300 text-sm"
              >
                返回
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
