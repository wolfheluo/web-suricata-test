import { BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer, Cell } from 'recharts';

interface Props {
  data: Record<string, number> | { protocol: string; count: number }[] | null;
}

const COLORS = ['#3b82f6', '#ef4444', '#10b981', '#f59e0b', '#8b5cf6', '#ec4899', '#06b6d4', '#f97316'];

export default function EventChart({ data }: Props) {
  if (!data) return <div className="text-gray-500">無事件資料</div>;

  const items = Array.isArray(data)
    ? data
    : Object.entries(data).map(([protocol, count]) => ({ protocol, count }));

  if (items.length === 0) return <div className="text-gray-500">無事件資料</div>;

  const sorted = [...items].sort((a, b) => b.count - a.count);

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h3 className="text-lg font-bold text-gray-800 mb-4">協議事件統計</h3>
      <ResponsiveContainer width="100%" height={400}>
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
  );
}
