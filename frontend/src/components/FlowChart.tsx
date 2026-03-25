import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

interface Props {
  data: any;
}

export default function FlowChart({ data }: Props) {
  if (!data || !data.per_10_minutes) return <div className="text-gray-500">無流量資料</div>;

  const chartData = Object.entries(data.per_10_minutes).map(([time, bytes]) => ({
    time: time.slice(11),
    bytes: bytes as number,
    mb: Number(((bytes as number) / (1 << 20)).toFixed(2)),
  }));

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h3 className="text-lg font-bold text-gray-800 mb-4">流量趨勢（每 10 分鐘）</h3>
      <ResponsiveContainer width="100%" height={400}>
        <AreaChart data={chartData}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="time" fontSize={12} />
          <YAxis fontSize={12} tickFormatter={(v) => `${(v / (1 << 20)).toFixed(0)} MB`} />
          <Tooltip formatter={(v) => [`${(Number(v) / (1 << 20)).toFixed(2)} MB`, '流量']} />
          <Area type="monotone" dataKey="bytes" stroke="#3b82f6" fill="#93c5fd" />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
