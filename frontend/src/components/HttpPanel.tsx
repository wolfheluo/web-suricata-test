import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts';

interface HttpData {
  top_hosts: { host: string; count: number }[];
  top_uris: { uri: string; count: number }[];
  methods: Record<string, number>;
  user_agents: { ua: string; count: number }[];
  status_codes: Record<string, number>;
}

interface Props {
  data: HttpData | null;
}

const COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#06b6d4', '#f97316'];

export default function HttpPanel({ data }: Props) {
  if (!data) return <div className="text-gray-500">無 HTTP 深度資料</div>;

  const methodData = Object.entries(data.methods).map(([name, value]) => ({ name, value }));
  const statusData = Object.entries(data.status_codes)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value);

  return (
    <div className="space-y-6">
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
              {data.top_hosts.map((h, i) => (
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
              {data.top_uris.map((u) => (
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
                <Bar dataKey="value" fill="#3b82f6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* User Agents */}
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-bold text-gray-800 mb-3">User-Agent 統計</h3>
        {data.user_agents.length === 0 ? (
          <p className="text-gray-500 text-sm">無 User-Agent 記錄</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b">
                <th className="text-left py-2 px-2 font-medium text-gray-600">#</th>
                <th className="text-left py-2 px-2 font-medium text-gray-600">User-Agent</th>
                <th className="text-right py-2 px-2 font-medium text-gray-600">次數</th>
              </tr>
            </thead>
            <tbody>
              {data.user_agents.map((ua, i) => (
                <tr key={ua.ua} className="border-b border-gray-50">
                  <td className="py-1.5 px-2 text-gray-400">{i + 1}</td>
                  <td className="py-1.5 px-2 font-mono text-xs break-all">{ua.ua}</td>
                  <td className="py-1.5 px-2 text-right">{ua.count.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
