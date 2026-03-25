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

  useEffect(() => {
    const token = localStorage.getItem('access_token');
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${proto}://${window.location.host}/ws/task/${taskId}?token=${token}`);
    wsRef.current = ws;

    ws.onmessage = (e) => {
      const data = JSON.parse(e.data);
      setStep(data.step);
      setProgress(data.progress);
      setMessage(data.message || data.step);
      if (data.step === 'done') setTimeout(onDone, 500);
      if (data.step === 'error') setTimeout(onError, 2000);
    };

    ws.onerror = () => { setStep('error'); setMessage('WebSocket 連線錯誤'); };
    ws.onclose = () => { if (step !== 'done' && step !== 'error') { /* reconnect logic could go here */ } };

    return () => { ws.close(); };
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
              step === 'error' ? 'bg-red-500' : step === 'done' ? 'bg-green-500' : 'bg-blue-500'
            }`}
            style={{ width: `${Math.max(progress, 2)}%` }}
          />
        </div>
        <div className="text-xs text-gray-400">{message}</div>
        {step === 'done' && <div className="mt-4 text-green-600 font-medium">分析完成！即將跳轉...</div>}
        {step === 'error' && <div className="mt-4 text-red-600 font-medium">分析失敗：{message}</div>}
      </div>
    </div>
  );
}
