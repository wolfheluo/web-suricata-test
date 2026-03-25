import { useState } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer, Cell } from 'recharts';

interface DetailedStat {
  src_ip: string;
  dst_ip: string;
  packet_count: number;
  packet_size: number;
}

interface ProtocolData {
  count: number;
  top_ip: string;
  detailed_stats: DetailedStat[];
}

interface Props {
  data: Record<string, ProtocolData> | Record<string, number> | { protocol: string; count: number }[] | null;
}

const COLORS = ['#3b82f6', '#ef4444', '#10b981', '#f59e0b', '#8b5cf6', '#ec4899', '#06b6d4', '#f97316'];

const PROTO_ICONS: Record<string, string> = {
  TCP: '🔗', TLS: '🔒', DNS: '🌐', HTTP: '📄', HTTPS: '🔐',
  SMTP: '📧', FTP: '📁', ICMP: '📡', DHCP: '🏠', SMB: '💾',
  SMB2: '💾', SMB3: '💾', SNMP: '📊', OTHER: '❓',
};

function fmtBytes(b: number) {
  if (b >= 1 << 30) return `${(b / (1 << 30)).toFixed(2)} GB`;
  if (b >= 1 << 20) return `${(b / (1 << 20)).toFixed(2)} MB`;
  if (b >= 1 << 10) return `${(b / (1 << 10)).toFixed(1)} KB`;
  return `${b} B`;
}

export default function EventChart({ data }: Props) {
  const [selected, setSelected] = useState<string | null>(null);

  if (!data) return <div className="text-gray-500">無事件資料</div>;

  // Normalize: could be {proto: {count, top_ip, ...}} or {proto: number} or array
  const isRich = !Array.isArray(data) && typeof Object.values(data)[0] === 'object';
  const richData = isRich ? (data as Record<string, ProtocolData>) : null;

  const items = Array.isArray(data)
    ? data.map(d => ({ protocol: d.protocol, count: d.count }))
    : Object.entries(data).map(([protocol, v]) => ({
        protocol,
        count: typeof v === 'number' ? v : (v as ProtocolData).count,
      }));

  if (items.length === 0) return <div className="text-gray-500">無事件資料</div>;

  const sorted = [...items].sort((a, b) => b.count - a.count);
  const totalEvents = sorted.reduce((s, i) => s + i.count, 0);
  const selectedData = selected && richData ? richData[selected] : null;

  return (
    <div className="space-y-6">
      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-white rounded-lg shadow p-5 border-l-4 border-blue-500">
          <div className="text-xs text-gray-500 uppercase tracking-wide">總事件數</div>
          <div className="text-2xl font-bold text-blue-700 mt-1">{totalEvents.toLocaleString()}</div>
        </div>
        <div className="bg-white rounded-lg shadow p-5 border-l-4 border-green-500">
          <div className="text-xs text-gray-500 uppercase tracking-wide">協定種類</div>
          <div className="text-2xl font-bold text-green-700 mt-1">{sorted.length}</div>
        </div>
        <div className="bg-white rounded-lg shadow p-5 border-l-4 border-purple-500">
          <div className="text-xs text-gray-500 uppercase tracking-wide">最大協定</div>
          <div className="text-2xl font-bold text-purple-700 mt-1">{sorted[0]?.protocol || '-'}</div>
        </div>
      </div>

      {/* Protocol Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-3">
        {sorted.map((item, idx) => (
          <button
            key={item.protocol}
            onClick={() => richData && setSelected(selected === item.protocol ? null : item.protocol)}
            className={`bg-white rounded-lg shadow p-4 text-left transition hover:shadow-md ${
              selected === item.protocol ? 'ring-2 ring-blue-500' : ''
            } ${richData ? 'cursor-pointer' : 'cursor-default'}`}
          >
            <div className="text-2xl mb-1">{PROTO_ICONS[item.protocol] || '📦'}</div>
            <div className="font-bold text-gray-800 text-sm">{item.protocol}</div>
            <div className="text-lg font-semibold mt-1" style={{ color: COLORS[idx % COLORS.length] }}>
              {item.count.toLocaleString()}
            </div>
            <div className="text-xs text-gray-400">
              {totalEvents > 0 ? ((item.count / totalEvents) * 100).toFixed(1) : 0}%
            </div>
            {richData && richData[item.protocol]?.top_ip && (
              <div className="text-xs text-gray-500 mt-1 truncate" title={richData[item.protocol].top_ip}>
                Top: {richData[item.protocol].top_ip}
              </div>
            )}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Bar Chart */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-bold text-gray-800 mb-4">協議事件統計</h3>
          <ResponsiveContainer width="100%" height={350}>
            <BarChart data={sorted} margin={{ top: 10, right: 30, left: 10, bottom: 40 }}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="protocol" angle={-35} textAnchor="end" fontSize={12} />
              <YAxis allowDecimals={false} />
              <Tooltip formatter={(v) => [Number(v).toLocaleString(), '事件數量']} />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {sorted.map((_, idx) => (
                  <Cell key={idx} fill={COLORS[idx % COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Detail Panel */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-bold text-gray-800 mb-4">
            {selected ? `${selected} 詳細連線` : '點擊協定卡片查看詳情'}
          </h3>
          {selectedData ? (
            <div>
              <div className="mb-3 text-sm text-gray-600">
                事件數: <span className="font-bold">{selectedData.count.toLocaleString()}</span>
                {selectedData.top_ip && <> | Top IP: <span className="font-mono text-xs">{selectedData.top_ip}</span></>}
              </div>
              {selectedData.detailed_stats && selectedData.detailed_stats.length > 0 ? (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b">
                      <th className="text-left py-2 px-2 font-medium text-gray-600">來源</th>
                      <th className="text-left py-2 px-2 font-medium text-gray-600">目的</th>
                      <th className="text-right py-2 px-2 font-medium text-gray-600">封包數</th>
                      <th className="text-right py-2 px-2 font-medium text-gray-600">流量</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selectedData.detailed_stats.map((d, i) => (
                      <tr key={i} className="border-b border-gray-50 hover:bg-gray-50">
                        <td className="py-1.5 px-2 font-mono text-xs">{d.src_ip}</td>
                        <td className="py-1.5 px-2 font-mono text-xs">{d.dst_ip}</td>
                        <td className="py-1.5 px-2 text-right">{d.packet_count.toLocaleString()}</td>
                        <td className="py-1.5 px-2 text-right">{fmtBytes(d.packet_size)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <p className="text-gray-500 text-sm">無詳細連線資料</p>
              )}
            </div>
          ) : (
            <div className="flex items-center justify-center h-48 text-gray-400">
              <div className="text-center">
                <div className="text-4xl mb-2">👆</div>
                <p>點擊左方協定卡片以查看連線詳情</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
