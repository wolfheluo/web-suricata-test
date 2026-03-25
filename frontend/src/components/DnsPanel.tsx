import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';

interface DnsData {
  top_queries: { qname: string; count: number }[];
  nxdomain_list: { qname: string; count: number }[];
  tunnel_suspects: { qname: string; reason: string }[];
  total_queries?: number;
  unique_qnames?: number;
}

interface Props {
  data: DnsData | null;
}

const COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#06b6d4', '#f97316'];

export default function DnsPanel({ data }: Props) {
  if (!data) return <div className="text-gray-500">無 DNS 深度資料</div>;

  const topQueryData = (data.top_queries ?? []).slice(0, 10).map((q) => ({
    name: q.qname.length > 25 ? q.qname.slice(0, 22) + '...' : q.qname,
    count: q.count,
  }));

  return (
    <div className="space-y-6">
      {/* Stats Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-white rounded-lg shadow p-5 border-l-4 border-blue-500">
          <div className="text-xs text-gray-500 uppercase tracking-wide">總查詢數</div>
          <div className="text-2xl font-bold text-blue-700 mt-1">{(data.total_queries ?? 0).toLocaleString()}</div>
        </div>
        <div className="bg-white rounded-lg shadow p-5 border-l-4 border-green-500">
          <div className="text-xs text-gray-500 uppercase tracking-wide">唯一域名數</div>
          <div className="text-2xl font-bold text-green-700 mt-1">{(data.unique_qnames ?? 0).toLocaleString()}</div>
        </div>
        <div className="bg-white rounded-lg shadow p-5 border-l-4 border-red-500">
          <div className="text-xs text-gray-500 uppercase tracking-wide">NXDOMAIN 數</div>
          <div className="text-2xl font-bold text-red-700 mt-1">{(data.nxdomain_list ?? []).length}</div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Queries Bar Chart */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-bold text-gray-800 mb-3">Top DNS 查詢</h3>
          {topQueryData.length === 0 ? (
            <p className="text-gray-500 text-sm">無查詢記錄</p>
          ) : (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={topQueryData} layout="vertical" margin={{ left: 100, right: 20 }}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis type="number" />
                <YAxis type="category" dataKey="name" fontSize={11} width={95} />
                <Tooltip formatter={(v) => [Number(v).toLocaleString(), '查詢次數']} />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {topQueryData.map((_, idx) => (
                    <Cell key={idx} fill={COLORS[idx % COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Top Queries Table */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-bold text-gray-800 mb-3">查詢排行</h3>
          {(data.top_queries ?? []).length === 0 ? (
            <p className="text-gray-500 text-sm">無查詢記錄</p>
          ) : (
            <div className="max-h-[300px] overflow-y-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-white">
                  <tr className="border-b">
                    <th className="text-left py-2 px-2 font-medium text-gray-600">#</th>
                    <th className="text-left py-2 px-2 font-medium text-gray-600">Domain</th>
                    <th className="text-right py-2 px-2 font-medium text-gray-600">次數</th>
                  </tr>
                </thead>
                <tbody>
                  {(data.top_queries ?? []).map((q, i) => (
                    <tr key={q.qname} className="border-b border-gray-50 hover:bg-gray-50">
                      <td className="py-1.5 px-2 text-gray-400">{i + 1}</td>
                      <td className="py-1.5 px-2 font-mono text-xs break-all">{q.qname}</td>
                      <td className="py-1.5 px-2 text-right">{q.count.toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* NXDOMAIN */}
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-bold text-gray-800 mb-3">NXDOMAIN 紀錄</h3>
        {(data.nxdomain_list ?? []).length === 0 ? (
          <div className="bg-green-50 border border-green-200 rounded p-3 text-green-700 text-sm">
            ✓ 無 NXDOMAIN 紀錄
          </div>
        ) : (
          <div className="max-h-64 overflow-y-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-white">
                <tr className="border-b">
                  <th className="text-left py-2 px-2 font-medium text-gray-600">Domain</th>
                  <th className="text-right py-2 px-2 font-medium text-gray-600">次數</th>
                </tr>
              </thead>
              <tbody>
                {(data.nxdomain_list ?? []).map((n) => (
                  <tr key={n.qname} className="border-b border-gray-50 hover:bg-gray-50">
                    <td className="py-1.5 px-2 font-mono text-xs break-all">{n.qname}</td>
                    <td className="py-1.5 px-2 text-right">{n.count.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Tunnel Suspects */}
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-bold text-red-700 mb-3">DNS 隧道嫌疑</h3>
        {(data.tunnel_suspects ?? []).length === 0 ? (
          <div className="bg-green-50 border border-green-200 rounded p-3 text-green-700 text-sm">
            ✓ 未偵測到 DNS 隧道嫌疑
          </div>
        ) : (
          <div className="space-y-3">
            {(data.tunnel_suspects ?? []).map((t, i) => (
              <div key={i} className="bg-red-50 border border-red-200 rounded-lg p-4">
                <div className="font-mono text-sm font-bold text-red-800">{t.qname}</div>
                <div className="text-sm text-red-700 mt-1">{t.reason}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
