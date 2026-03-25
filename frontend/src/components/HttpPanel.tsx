import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts';

interface HttpData {
  top_hosts: { host: string; count: number }[];
  top_uris: { uri: string; count: number }[];
  method_dist: Record<string, number>;
  user_agent_dist: { user_agent: string; count: number }[];
  status_code_dist: Record<string, number>;
  total_requests?: number;
}

interface Props {
  data: HttpData | null;
}

const COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#06b6d4', '#f97316'];

const statusColor = (code: string) => {
  if (code.startsWith('2')) return '#10b981';
  if (code.startsWith('3')) return '#3b82f6';
  if (code.startsWith('4')) return '#f59e0b';
  if (code.startsWith('5')) return '#ef4444';
  return '#6b7280';
};

export default function HttpPanel({ data }: Props) {
  if (!data) return <div className="text-gray-500">無 HTTP 深度資料</div>;

  const methodData = Object.entries(data.method_dist ?? {}).map(([name, value]) => ({ name, value }));
  const statusData = Object.entries(data.status_code_dist ?? {})
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value);

  return (
    <div className="space-y-6">
      {/* Stats Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-white rounded-lg shadow p-5 border-l-4 border-blue-500">
          <div className="text-xs text-gray-500 uppercase tracking-wide">總請求數</div>
          <div className="text-2xl font-bold text-blue-700 mt-1">{(data.total_requests ?? 0).toLocaleString()}</div>
        </div>
        <div className="bg-white rounded-lg shadow p-5 border-l-4 border-green-500">
          <div className="text-xs text-gray-500 uppercase tracking-wide">不同 Host 數</div>
          <div className="text-2xl font-bold text-green-700 mt-1">{(data.top_hosts ?? []).length}</div>
        </div>
        <div className="bg-white rounded-lg shadow p-5 border-l-4 border-purple-500">
          <div className="text-xs text-gray-500 uppercase tracking-wide">User-Agent 數</div>
          <div className="text-2xl font-bold text-purple-700 mt-1">{(data.user_agent_dist ?? []).length}</div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Hosts */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-bold text-gray-800 mb-3">Top Hosts</h3>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b">
                <th className="text-left py-2 px-2 font-medium text-gray-600">#</th>
                <th className="text-left py-2 px-2 font-medium text-gray-600">Host</th>
                <th className="text-right py-2 px-2 font-medium text-gray-600">次數</th>
              </tr>
            </thead>
            <tbody>
              {(data.top_hosts ?? []).map((h, i) => (
                <tr key={h.host} className="border-b border-gray-50">
                  <td className="py-1.5 px-2 text-gray-400">{i + 1}</td>
                  <td className="py-1.5 px-2 font-mono text-xs break-all">{h.host}</td>
                  <td className="py-1.5 px-2 text-right">{h.count.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Method PieChart */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-bold text-gray-800 mb-3">HTTP Methods</h3>
          {methodData.length === 0 ? (
            <p className="text-gray-500 text-sm">無資料</p>
          ) : (
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie data={methodData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={90} label={({ name, percent }) => `${name} ${((percent ?? 0) * 100).toFixed(0)}%`}>
                  {methodData.map((_, idx) => (
                    <Cell key={idx} fill={COLORS[idx % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top URIs */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-bold text-gray-800 mb-3">Top URIs</h3>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b">
                <th className="text-left py-2 px-2 font-medium text-gray-600">URI</th>
                <th className="text-right py-2 px-2 font-medium text-gray-600">次數</th>
              </tr>
            </thead>
            <tbody>
              {(data.top_uris ?? []).map((u) => (
                <tr key={u.uri} className="border-b border-gray-50">
                  <td className="py-1.5 px-2 font-mono text-xs break-all">{u.uri}</td>
                  <td className="py-1.5 px-2 text-right">{u.count.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Status Code BarChart */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-bold text-gray-800 mb-3">狀態碼分布</h3>
          {statusData.length === 0 ? (
            <p className="text-gray-500 text-sm">無資料</p>
          ) : (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={statusData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" fontSize={12} />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {statusData.map((d, idx) => (
                    <Cell key={idx} fill={statusColor(d.name)} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* User Agents */}
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-bold text-gray-800 mb-3">User-Agent 統計</h3>
        {(data.user_agent_dist ?? []).length === 0 ? (
          <p className="text-gray-500 text-sm">無 User-Agent 記錄</p>
        ) : (
          <div className="max-h-64 overflow-y-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-white">
                <tr className="border-b">
                  <th className="text-left py-2 px-2 font-medium text-gray-600">#</th>
                  <th className="text-left py-2 px-2 font-medium text-gray-600">User-Agent</th>
                  <th className="text-right py-2 px-2 font-medium text-gray-600">次數</th>
                </tr>
              </thead>
              <tbody>
                {(data.user_agent_dist ?? []).map((ua, i) => (
                  <tr key={ua.user_agent} className="border-b border-gray-50 hover:bg-gray-50">
                    <td className="py-1.5 px-2 text-gray-400">{i + 1}</td>
                    <td className="py-1.5 px-2 font-mono text-xs break-all">{ua.user_agent}</td>
                    <td className="py-1.5 px-2 text-right">{ua.count.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
