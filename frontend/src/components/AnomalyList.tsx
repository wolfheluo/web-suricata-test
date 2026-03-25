interface AnomalyItem {
  rule: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  detail: string;
  value?: number;
  threshold?: number;
}

interface Props {
  data: AnomalyItem[];
}

const sevColor: Record<string, string> = {
  HIGH: 'bg-red-100 text-red-800 border-red-300',
  MEDIUM: 'bg-yellow-100 text-yellow-800 border-yellow-300',
  LOW: 'bg-blue-100 text-blue-800 border-blue-300',
};

const sevLabel: Record<string, string> = {
  HIGH: '高',
  MEDIUM: '中',
  LOW: '低',
};

export default function AnomalyList({ data }: Props) {
  if (!data || data.length === 0)
    return (
      <div className="bg-green-50 border border-green-200 rounded-lg p-6 text-green-800">
        ✓ 未偵測到異常行為
      </div>
    );

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-bold text-gray-800">異常偵測結果 ({data.length})</h3>
      {data.map((a, i) => (
        <div key={i} className={`border rounded-lg p-4 ${sevColor[a.severity] || sevColor.LOW}`}>
          <div className="flex items-center gap-3 mb-2">
            <span className="text-xs font-bold px-2 py-0.5 rounded border">{sevLabel[a.severity] || a.severity}</span>
            <span className="font-semibold">{a.rule}</span>
          </div>
          <p className="text-sm">{a.detail}</p>
          {a.value !== undefined && a.threshold !== undefined && (
            <p className="text-xs mt-1 opacity-75">
              偵測值: {a.value} | 閾值: {a.threshold}
            </p>
          )}
        </div>
      ))}
    </div>
  );
}
