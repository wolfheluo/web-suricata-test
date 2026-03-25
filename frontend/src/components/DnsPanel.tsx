interface DnsData {
  top_queries: { domain: string; count: number }[];
  nxdomain: { domain: string; count: number }[];
  tunnel_suspects: { domain: string; reason: string; subdomain_count?: number; avg_length?: number }[];
}

interface Props {
  data: DnsData | null;
}

export default function DnsPanel({ data }: Props) {
  if (!data) return <div className="text-gray-500">無 DNS 深度資料</div>;

  return (
    <div className="space-y-6">
      {/* Top Queries */}
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-bold text-gray-800 mb-3">Top DNS 查詢</h3>
        {data.top_queries.length === 0 ? (
          <p className="text-gray-500 text-sm">無查詢記錄</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b">
                <th className="text-left py-2 px-2 font-medium text-gray-600">#</th>
                <th className="text-left py-2 px-2 font-medium text-gray-600">Domain</th>
                <th className="text-right py-2 px-2 font-medium text-gray-600">次數</th>
              </tr>
            </thead>
            <tbody>
              {data.top_queries.map((q, i) => (
                <tr key={q.domain} className="border-b border-gray-50">
                  <td className="py-1.5 px-2 text-gray-400">{i + 1}</td>
                  <td className="py-1.5 px-2 font-mono text-xs break-all">{q.domain}</td>
                  <td className="py-1.5 px-2 text-right">{q.count.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* NXDOMAIN */}
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-bold text-gray-800 mb-3">NXDOMAIN 紀錄</h3>
        {data.nxdomain.length === 0 ? (
          <p className="text-gray-500 text-sm">無 NXDOMAIN 紀錄</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b">
                <th className="text-left py-2 px-2 font-medium text-gray-600">Domain</th>
                <th className="text-right py-2 px-2 font-medium text-gray-600">次數</th>
              </tr>
            </thead>
            <tbody>
              {data.nxdomain.map((n) => (
                <tr key={n.domain} className="border-b border-gray-50">
                  <td className="py-1.5 px-2 font-mono text-xs break-all">{n.domain}</td>
                  <td className="py-1.5 px-2 text-right">{n.count.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Tunnel Suspects */}
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-bold text-red-700 mb-3">DNS 隧道嫌疑</h3>
        {data.tunnel_suspects.length === 0 ? (
          <div className="bg-green-50 border border-green-200 rounded p-3 text-green-700 text-sm">
            ✓ 未偵測到 DNS 隧道嫌疑
          </div>
        ) : (
          <div className="space-y-3">
            {data.tunnel_suspects.map((t, i) => (
              <div key={i} className="bg-red-50 border border-red-200 rounded-lg p-4">
                <div className="font-mono text-sm font-bold text-red-800">{t.domain}</div>
                <div className="text-sm text-red-700 mt-1">{t.reason}</div>
                <div className="text-xs text-red-500 mt-1 flex gap-4">
                  {t.subdomain_count !== undefined && <span>子域數: {t.subdomain_count}</span>}
                  {t.avg_length !== undefined && <span>平均長度: {t.avg_length.toFixed(1)}</span>}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
