import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';

interface TlsData {
  top_sni: { sni: string; count: number }[];
  versions: Record<string, number>;
  cipher_suites: { cipher: string; count: number }[];
}

interface Props {
  data: TlsData | null;
}

const COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#06b6d4', '#f97316'];

export default function TlsPanel({ data }: Props) {
  if (!data) return <div className="text-gray-500">無 TLS 深度資料</div>;

  const versionData = Object.entries(data.versions).map(([name, value]) => ({ name, value }));

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top SNI */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-bold text-gray-800 mb-3">Top SNI</h3>
          {data.top_sni.length === 0 ? (
            <p className="text-gray-500 text-sm">無 SNI 記錄</p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b">
                  <th className="text-left py-2 px-2 font-medium text-gray-600">#</th>
                  <th className="text-left py-2 px-2 font-medium text-gray-600">SNI</th>
                  <th className="text-right py-2 px-2 font-medium text-gray-600">次數</th>
                </tr>
              </thead>
              <tbody>
                {data.top_sni.map((s, i) => (
                  <tr key={s.sni} className="border-b border-gray-50">
                    <td className="py-1.5 px-2 text-gray-400">{i + 1}</td>
                    <td className="py-1.5 px-2 font-mono text-xs break-all">{s.sni}</td>
                    <td className="py-1.5 px-2 text-right">{s.count.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Version PieChart */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-bold text-gray-800 mb-3">TLS 版本分布</h3>
          {versionData.length === 0 ? (
            <p className="text-gray-500 text-sm">無版本資料</p>
          ) : (
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie data={versionData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={90} label={({ name, percent }) => `${name} ${((percent ?? 0) * 100).toFixed(0)}%`}>
                  {versionData.map((_, idx) => (
                    <Cell key={idx} fill={COLORS[idx % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Cipher Suites */}
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-bold text-gray-800 mb-3">Cipher Suites</h3>
        {data.cipher_suites.length === 0 ? (
          <p className="text-gray-500 text-sm">無 Cipher Suite 記錄</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b">
                <th className="text-left py-2 px-2 font-medium text-gray-600">#</th>
                <th className="text-left py-2 px-2 font-medium text-gray-600">Cipher Suite</th>
                <th className="text-right py-2 px-2 font-medium text-gray-600">次數</th>
              </tr>
            </thead>
            <tbody>
              {data.cipher_suites.map((c, i) => (
                <tr key={c.cipher} className="border-b border-gray-50">
                  <td className="py-1.5 px-2 text-gray-400">{i + 1}</td>
                  <td className="py-1.5 px-2 font-mono text-xs break-all">{c.cipher}</td>
                  <td className="py-1.5 px-2 text-right">{c.count.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
