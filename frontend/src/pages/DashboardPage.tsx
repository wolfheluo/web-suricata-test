import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import client from '../api/client';
import FlowChart from '../components/FlowChart';
import TopIpTable from '../components/TopIpTable';
import GeoMap from '../components/GeoMap';
import EventChart from '../components/EventChart';
import AnomalyList from '../components/AnomalyList';
import DnsPanel from '../components/DnsPanel';
import HttpPanel from '../components/HttpPanel';
import TlsPanel from '../components/TlsPanel';

const TABS = [
  { key: 'overview', label: '總覽' },
  { key: 'flow', label: '流量趨勢' },
  { key: 'top_ip', label: 'Top IP' },
  { key: 'geo', label: '地理分布' },
  { key: 'events', label: '事件分析' },
  { key: 'anomaly', label: '異常偵測' },
  { key: 'dns', label: 'DNS 分析' },
  { key: 'http', label: 'HTTP 分析' },
  { key: 'tls', label: 'TLS 分析' },
];

export default function DashboardPage() {
  const { id } = useParams<{ id: string }>();
  const [tab, setTab] = useState('overview');
  const [task, setTask] = useState<any>(null);
  const [flow, setFlow] = useState<any>(null);
  const [topIp, setTopIp] = useState<any[]>([]);
  const [geo, setGeo] = useState<Record<string, number>>({});
  const [events, setEvents] = useState<Record<string, any>>({});
  const [anomalies, setAnomalies] = useState<any[]>([]);
  const [dns, setDns] = useState<any>(null);
  const [http, setHttp] = useState<any>(null);
  const [tls, setTls] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  const loadResults = () => {
    if (!id) return;
    Promise.all([
      client.get(`/api/v1/tasks/${id}/flow`),
      client.get(`/api/v1/tasks/${id}/top_ip`),
      client.get(`/api/v1/tasks/${id}/geo`),
      client.get(`/api/v1/tasks/${id}/events`),
      client.get(`/api/v1/tasks/${id}/anomaly`),
      client.get(`/api/v1/tasks/${id}/deep/dns`),
      client.get(`/api/v1/tasks/${id}/deep/http`),
      client.get(`/api/v1/tasks/${id}/deep/tls`),
    ]).then(([f, t, g, e, a, d, h, tl]) => {
      setFlow(f.data.data);
      setTopIp(t.data.data);
      setGeo(g.data.data);
      setEvents(e.data.data);
      setAnomalies(a.data.data);
      setDns(d.data.data);
      setHttp(h.data.data);
      setTls(tl.data.data);
    }).catch(() => {});
  };

  useEffect(() => {
    if (!id) return;
    setLoading(true);
    client.get(`/api/v1/tasks/${id}`).then(({ data }) => {
      setTask(data.data);
      if (data.data.status === 'done') {
        loadResults();
      }
    }).finally(() => setLoading(false));
  }, [id]);

  // Auto-refresh when task is running
  useEffect(() => {
    if (!task || (task.status !== 'running' && task.status !== 'pending')) return;
    const timer = setInterval(() => {
      client.get(`/api/v1/tasks/${id}`).then(({ data }) => {
        setTask(data.data);
        if (data.data.status === 'done') {
          loadResults();
        }
      });
    }, 3000);
    return () => clearInterval(timer);
  }, [task?.status, id]);

  const fmtBytes = (b: number) => {
    if (b >= 1 << 30) return `${(b / (1 << 30)).toFixed(2)} GB`;
    if (b >= 1 << 20) return `${(b / (1 << 20)).toFixed(2)} MB`;
    if (b >= 1 << 10) return `${(b / (1 << 10)).toFixed(1)} KB`;
    return `${b} B`;
  };

  if (loading) return <div className="min-h-screen flex items-center justify-center text-gray-500">載入中...</div>;

  const statusLabels: Record<string, string> = {
    pending: '等待中',
    running: '分析中...',
    done: '完成',
    failed: '失敗',
  };

  const isReady = task?.status === 'done';

  return (
    <div className="min-h-screen bg-gray-100">
      <nav className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 py-3 flex justify-between items-center">
          <h1 className="text-xl font-bold text-gray-800">分析儀表板</h1>
          <div className="flex gap-3">
            {isReady && (
              <>
                <a href={`/api/v1/tasks/${id}/report`} target="_blank" className="text-blue-600 hover:underline text-sm">
                  下載報告
                </a>
                <a href={`/api/v1/tasks/${id}/export?format=csv`} target="_blank" className="text-blue-600 hover:underline text-sm">
                  匯出 CSV
                </a>
              </>
            )}
            <Link to="/tasks" className="text-gray-500 hover:text-gray-700 text-sm">返回列表</Link>
          </div>
        </div>
      </nav>

      {/* Task status banner */}
      {task && !isReady && (
        <div className="max-w-7xl mx-auto px-4 mt-6">
          <div className={`rounded-lg shadow p-8 text-center ${
            task.status === 'failed' ? 'bg-red-50' : 'bg-blue-50'
          }`}>
            <div className={`text-lg font-semibold mb-2 ${
              task.status === 'failed' ? 'text-red-700' : 'text-blue-700'
            }`}>
              {statusLabels[task.status] || task.status}
            </div>
            <div className="text-sm text-gray-600 mb-1">任務：{task.name}</div>
            <div className="text-sm text-gray-500">NAS 路徑：{task.nas_project}</div>
            {task.status === 'running' && (
              <div className="mt-4 flex justify-center">
                <div className="w-8 h-8 border-4 border-blue-600 border-t-transparent rounded-full animate-spin" />
              </div>
            )}
            {task.status === 'running' && (
              <div className="mt-2 text-xs text-gray-400">每 3 秒自動重新整理狀態</div>
            )}
            {task.error_msg && (
              <div className="mt-3 text-sm text-red-600">錯誤：{task.error_msg}</div>
            )}
          </div>
        </div>
      )}

      {isReady && (
        <>
      {/* Tabs */}
      <div className="max-w-7xl mx-auto px-4 mt-4">
        <div className="flex gap-1 bg-white rounded-lg shadow p-1 overflow-x-auto">
          {TABS.map((t) => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={`px-4 py-2 text-sm rounded-md whitespace-nowrap transition ${
                tab === t.key
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-600 hover:bg-gray-100'
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      <div className="max-w-7xl mx-auto px-4 py-6">
        {tab === 'overview' && flow && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <StatCard label="總流量" value={fmtBytes(flow.total_bytes || 0)} color="blue" />
            <StatCard label="開始時間" value={flow.start_time?.replace('T', ' ').slice(0, 19) || 'N/A'} color="green" />
            <StatCard label="結束時間" value={flow.end_time?.replace('T', ' ').slice(0, 19) || 'N/A'} color="purple" />
            <StatCard label="協定數" value={String(Object.keys(events).length)} color="orange" />
            <StatCard label="異常數" value={String(anomalies.length)} color={anomalies.length > 0 ? 'red' : 'green'} />
            <StatCard label="Top IP 連線" value={String(topIp.length)} color="indigo" />
          </div>
        )}
        {tab === 'flow' && <FlowChart data={flow} />}
        {tab === 'top_ip' && <TopIpTable data={topIp} />}
        {tab === 'geo' && <GeoMap data={geo} />}
        {tab === 'events' && <EventChart data={events} />}
        {tab === 'anomaly' && <AnomalyList data={anomalies} />}
        {tab === 'dns' && <DnsPanel data={dns} />}
        {tab === 'http' && <HttpPanel data={http} />}
        {tab === 'tls' && <TlsPanel data={tls} />}
      </div>
      </>
      )}
    </div>
  );
}

function StatCard({ label, value, color }: { label: string; value: string; color: string }) {
  const colorMap: Record<string, string> = {
    blue: 'border-blue-500 text-blue-700',
    green: 'border-green-500 text-green-700',
    purple: 'border-purple-500 text-purple-700',
    orange: 'border-orange-500 text-orange-700',
    red: 'border-red-500 text-red-700',
    indigo: 'border-indigo-500 text-indigo-700',
  };
  return (
    <div className={`bg-white rounded-lg shadow p-5 border-l-4 ${colorMap[color] || ''}`}>
      <div className="text-xs text-gray-500 uppercase tracking-wide">{label}</div>
      <div className="text-xl font-bold mt-1">{value}</div>
    </div>
  );
}
