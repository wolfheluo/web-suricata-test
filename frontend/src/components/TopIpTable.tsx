interface TopIpEntry {
  connection: string;
  bytes: number;
  protocol: string;
  top_3_time_periods: { rank: number; time_period: string; bytes: number; percentage_of_total: number }[];
}

interface Props {
  data: TopIpEntry[];
}

export default function TopIpTable({ data }: Props) {
  if (!data || data.length === 0) return <div className="text-gray-500">無資料</div>;

  const fmtBytes = (b: number) => {
    if (b >= 1 << 30) return `${(b / (1 << 30)).toFixed(2)} GB`;
    if (b >= 1 << 20) return `${(b / (1 << 20)).toFixed(2)} MB`;
    return `${(b / (1 << 10)).toFixed(1)} KB`;
  };

  return (
    <div className="bg-white rounded-lg shadow overflow-hidden">
      <h3 className="text-lg font-bold text-gray-800 p-6 pb-3">Top 10 IP 連線</h3>
      <table className="w-full text-sm">
        <thead className="bg-gray-50">
          <tr>
            <th className="px-4 py-2 text-left font-medium text-gray-600">#</th>
            <th className="px-4 py-2 text-left font-medium text-gray-600">連線</th>
            <th className="px-4 py-2 text-left font-medium text-gray-600">協定</th>
            <th className="px-4 py-2 text-right font-medium text-gray-600">流量</th>
            <th className="px-4 py-2 text-left font-medium text-gray-600">主要時段</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100">
          {data.map((item, i) => (
            <tr key={i} className="hover:bg-gray-50">
              <td className="px-4 py-2 text-gray-400">{i + 1}</td>
              <td className="px-4 py-2 font-mono text-xs">{item.connection}</td>
              <td className="px-4 py-2">
                <span className="px-2 py-0.5 bg-blue-100 text-blue-700 rounded text-xs">{item.protocol}</span>
              </td>
              <td className="px-4 py-2 text-right font-medium">{fmtBytes(item.bytes)}</td>
              <td className="px-4 py-2 text-xs text-gray-500">
                {item.top_3_time_periods?.slice(0, 2).map((tp) => (
                  <div key={tp.rank}>{tp.time_period} ({tp.percentage_of_total}%)</div>
                ))}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
