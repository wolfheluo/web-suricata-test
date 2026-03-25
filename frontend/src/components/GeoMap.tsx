import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';

interface Props {
  data: Record<string, number>;
}

const COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#06b6d4', '#f97316', '#14b8a6', '#a855f7'];

const COUNTRY_NAMES: Record<string, string> = {
  TW: '台灣', US: '美國', CN: '中國', JP: '日本', KR: '韓國',
  DE: '德國', GB: '英國', FR: '法國', SG: '新加坡', HK: '香港',
  NL: '荷蘭', CA: '加拿大', AU: '澳洲', IN: '印度', RU: '俄羅斯',
  BR: '巴西', IE: '愛爾蘭', SE: '瑞典', IT: '義大利', ES: '西班牙',
  LOCAL: '內網 (Private)', UNKNOWN: '未知',
};

export default function GeoMap({ data }: Props) {
  if (!data || Object.keys(data).length === 0) return <div className="text-gray-500">無地理資料</div>;

  const entries = Object.entries(data)
    .filter(([cc]) => cc !== 'LOCAL' && cc !== 'UNKNOWN')
    .sort((a, b) => b[1] - a[1]);

  const totalBytes = entries.reduce((sum, [, b]) => sum + b, 0);

  // Top 8 for pie chart, rest grouped as "其他"
  const top8 = entries.slice(0, 8);
  const otherBytes = entries.slice(8).reduce((sum, [, b]) => sum + b, 0);
  const pieData = top8.map(([cc, bytes]) => ({
    name: COUNTRY_NAMES[cc] || cc,
    value: bytes,
  }));
  if (otherBytes > 0) {
    pieData.push({ name: '其他', value: otherBytes });
  }

  const fmtBytes = (b: number) => {
    if (b >= 1 << 30) return `${(b / (1 << 30)).toFixed(2)} GB`;
    if (b >= 1 << 20) return `${(b / (1 << 20)).toFixed(2)} MB`;
    return `${(b / (1 << 10)).toFixed(1)} KB`;
  };

  return (
    <div className="space-y-6">
      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-white rounded-lg shadow p-5 border-l-4 border-blue-500">
          <div className="text-xs text-gray-500 uppercase tracking-wide">外部流量總計</div>
          <div className="text-2xl font-bold text-blue-700 mt-1">{fmtBytes(totalBytes)}</div>
        </div>
        <div className="bg-white rounded-lg shadow p-5 border-l-4 border-green-500">
          <div className="text-xs text-gray-500 uppercase tracking-wide">涉及國家數</div>
          <div className="text-2xl font-bold text-green-700 mt-1">{entries.length}</div>
        </div>
        <div className="bg-white rounded-lg shadow p-5 border-l-4 border-orange-500">
          <div className="text-xs text-gray-500 uppercase tracking-wide">內網流量</div>
          <div className="text-2xl font-bold text-orange-700 mt-1">{data.LOCAL ? fmtBytes(data.LOCAL) : 'N/A'}</div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Pie Chart */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-bold text-gray-800 mb-4">國家流量分布</h3>
          {pieData.length === 0 ? (
            <p className="text-gray-500 text-sm">無資料</p>
          ) : (
            <ResponsiveContainer width="100%" height={320}>
              <PieChart>
                <Pie
                  data={pieData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={120}
                  label={({ name, percent }) => `${name} ${((percent ?? 0) * 100).toFixed(1)}%`}
                  labelLine={true}
                >
                  {pieData.map((_, idx) => (
                    <Cell key={idx} fill={COLORS[idx % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip formatter={(v) => fmtBytes(Number(v))} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Country Ranking Table */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-bold text-gray-800 mb-4">國家排行</h3>
          <div className="max-h-[320px] overflow-y-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-white">
                <tr className="border-b">
                  <th className="text-left py-2 px-2 font-medium text-gray-600">#</th>
                  <th className="text-left py-2 px-2 font-medium text-gray-600">國家</th>
                  <th className="text-right py-2 px-2 font-medium text-gray-600">流量</th>
                  <th className="text-right py-2 px-2 font-medium text-gray-600">佔比</th>
                </tr>
              </thead>
              <tbody>
                {entries.map(([cc, bytes], i) => (
                  <tr key={cc} className="border-b border-gray-50 hover:bg-gray-50">
                    <td className="py-1.5 px-2 text-gray-400">{i + 1}</td>
                    <td className="py-1.5 px-2">
                      <span className="font-mono text-xs mr-2">{cc}</span>
                      <span className="text-gray-500 text-xs">{COUNTRY_NAMES[cc] || ''}</span>
                    </td>
                    <td className="py-1.5 px-2 text-right font-medium">{fmtBytes(bytes)}</td>
                    <td className="py-1.5 px-2 text-right text-gray-500">
                      {totalBytes > 0 ? ((bytes / totalBytes) * 100).toFixed(1) : 0}%
                    </td>
                  </tr>
                ))}
                {data.LOCAL && (
                  <tr className="border-b border-gray-50 bg-gray-50">
                    <td className="py-1.5 px-2 text-gray-400">-</td>
                    <td className="py-1.5 px-2">
                      <span className="font-mono text-xs mr-2">LOCAL</span>
                      <span className="text-gray-500 text-xs">內網</span>
                    </td>
                    <td className="py-1.5 px-2 text-right font-medium">{fmtBytes(data.LOCAL)}</td>
                    <td className="py-1.5 px-2 text-right text-gray-400">-</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
