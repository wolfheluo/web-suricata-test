import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts';

interface TlsData {
  top_sni: { sni: string; count: number }[];
  version_dist: Record<string, number>;
  cipher_suite_dist: { cipher: string; count: number }[];
  total_handshakes?: number;
  total_records?: number;
}

interface Props {
  data: TlsData | null;
}

const COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#06b6d4', '#f97316'];

export default function TlsPanel({ data }: Props) {
  if (!data) return <div className="text-gray-500">無 TLS 深度資料</div>;

  if ((data.total_handshakes ?? 0) === 0 && (data.total_records ?? 0) === 0 && (data.top_sni ?? []).length === 0) {
    return (
      <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-8 text-center">
        <div className="text-4xl mb-3">🔒</div>
        <div className="text-yellow-800 font-semibold text-lg">未偵測到 TLS 交握資料</div>
        <div className="text-yellow-600 text-sm mt-1">此 PCAP 可能僅包含 TLS 資料傳輸封包，未捕獲到交握過程（Client Hello / Server Hello）。</div>
      </div>
    );
  }

  const versionData = Object.entries(data.version_dist ?? {}).map(([name, value]) => ({ name, value }));
  const cipherData = (data.cipher_suite_dist ?? []).slice(0, 10).map((c) => ({
    name: c.cipher.length > 30 ? c.cipher.slice(0, 27) + '...' : c.cipher,
    count: c.count,
    full: c.cipher,
  }));

  return (
    <div className="space-y-6">
      {/* Stats Row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white rounded-lg shadow p-5 border-l-4 border-blue-500">
          <div className="text-xs text-gray-500 uppercase tracking-wide">總握手數</div>
          <div className="text-2xl font-bold text-blue-700 mt-1">{(data.total_handshakes ?? 0).toLocaleString()}</div>
        </div>
        <div className="bg-white rounded-lg shadow p-5 border-l-4 border-cyan-500">
          <div className="text-xs text-gray-500 uppercase tracking-wide">總 TLS 記錄數</div>
          <div className="text-2xl font-bold text-cyan-700 mt-1">{(data.total_records ?? 0).toLocaleString()}</div>
        </div>
        <div className="bg-white rounded-lg shadow p-5 border-l-4 border-green-500">
          <div className="text-xs text-gray-500 uppercase tracking-wide">不同 SNI 數</div>
          <div className="text-2xl font-bold text-green-700 mt-1">{(data.top_sni ?? []).length}</div>
        </div>
        <div className="bg-white rounded-lg shadow p-5 border-l-4 border-purple-500">
          <div className="text-xs text-gray-500 uppercase tracking-wide">TLS 版本數</div>
          <div className="text-2xl font-bold text-purple-700 mt-1">{versionData.length}</div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top SNI */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-bold text-gray-800 mb-3">Top SNI</h3>
          {(data.top_sni ?? []).length === 0 ? (
            <p className="text-gray-500 text-sm">無 SNI 記錄</p>
          ) : (
            <div className="max-h-[300px] overflow-y-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-white">
                  <tr className="border-b">
                    <th className="text-left py-2 px-2 font-medium text-gray-600">#</th>
                    <th className="text-left py-2 px-2 font-medium text-gray-600">SNI</th>
                    <th className="text-right py-2 px-2 font-medium text-gray-600">次數</th>
                  </tr>
                </thead>
                <tbody>
                  {(data.top_sni ?? []).map((s, i) => (
                    <tr key={s.sni} className="border-b border-gray-50 hover:bg-gray-50">
                      <td className="py-1.5 px-2 text-gray-400">{i + 1}</td>
                      <td className="py-1.5 px-2 font-mono text-xs break-all">{s.sni}</td>
                      <td className="py-1.5 px-2 text-right">{s.count.toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
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

      {/* Cipher Suites Bar Chart */}
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-bold text-gray-800 mb-3">Cipher Suites</h3>
        {cipherData.length === 0 ? (
          <p className="text-gray-500 text-sm">無 Cipher Suite 記錄</p>
        ) : (
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={cipherData} layout="vertical" margin={{ left: 150, right: 20 }}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis type="number" />
              <YAxis type="category" dataKey="name" fontSize={11} width={145} />
              <Tooltip formatter={(v) => [Number(v).toLocaleString(), '次數']} labelFormatter={(label) => {
                const item = cipherData.find(d => d.name === label);
                return item ? item.full : label;
              }} />
              <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                {cipherData.map((_, idx) => (
                  <Cell key={idx} fill={COLORS[idx % COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
