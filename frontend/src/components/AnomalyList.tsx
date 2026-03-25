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
  HIGH: 'bg-red-50 text-red-800 border-red-200',
  MEDIUM: 'bg-yellow-50 text-yellow-800 border-yellow-200',
  LOW: 'bg-blue-50 text-blue-800 border-blue-200',
};

const sevBadge: Record<string, string> = {
  HIGH: 'bg-red-600 text-white',
  MEDIUM: 'bg-yellow-500 text-white',
  LOW: 'bg-blue-500 text-white',
};

const sevLabel: Record<string, string> = {
  HIGH: '高',
  MEDIUM: '中',
  LOW: '低',
};

export default function AnomalyList({ data }: Props) {
  if (!data || data.length === 0)
    return (
      <div className="bg-green-50 border border-green-200 rounded-lg p-8 text-center">
        <div className="text-4xl mb-3">&#x2705;</div>
        <div className="text-green-800 font-semibold text-lg">未偵測到異常行為</div>
        <div className="text-green-600 text-sm mt-1">所有指標皆在正常範圍內</div>
      </div>
    );

  // Group by severity
  const grouped = { HIGH: [] as AnomalyItem[], MEDIUM: [] as AnomalyItem[], LOW: [] as AnomalyItem[] };
  data.forEach((a) => {
    const sev = a.severity in grouped ? a.severity : 'LOW';
    grouped[sev].push(a);
  });

  const highCount = grouped.HIGH.length;
  const medCount = grouped.MEDIUM.length;
  const lowCount = grouped.LOW.length;

  return (
    <div className="space-y-6">
      {/* Summary */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-white rounded-lg shadow p-5 border-l-4 border-red-500">
          <div className="text-xs text-gray-500 uppercase tracking-wide">高風險</div>
          <div className="text-2xl font-bold text-red-700 mt-1">{highCount}</div>
        </div>
        <div className="bg-white rounded-lg shadow p-5 border-l-4 border-yellow-500">
          <div className="text-xs text-gray-500 uppercase tracking-wide">中風險</div>
          <div className="text-2xl font-bold text-yellow-700 mt-1">{medCount}</div>
        </div>
        <div className="bg-white rounded-lg shadow p-5 border-l-4 border-blue-500">
          <div className="text-xs text-gray-500 uppercase tracking-wide">低風險</div>
          <div className="text-2xl font-bold text-blue-700 mt-1">{lowCount}</div>
        </div>
      </div>

      {/* Grouped alerts */}
      {(['HIGH', 'MEDIUM', 'LOW'] as const).map((sev) => {
        const items = grouped[sev];
        if (items.length === 0) return null;
        return (
          <div key={sev} className="space-y-3">
            <h3 className="text-sm font-bold text-gray-500 uppercase tracking-wide">
              {sevLabel[sev]}風險 ({items.length})
            </h3>
            {items.map((a, i) => (
              <div key={i} className={`border rounded-lg p-4 ${sevColor[sev]}`}>
                <div className="flex items-center gap-3 mb-2">
                  <span className={`text-xs font-bold px-2 py-0.5 rounded ${sevBadge[sev]}`}>
                    {sevLabel[sev]}
                  </span>
                  <span className="font-semibold">{a.rule}</span>
                </div>
                <p className="text-sm">{a.detail}</p>
                {a.value !== undefined && a.threshold !== undefined && a.threshold > 0 && (
                  <div className="mt-2">
                    <div className="flex justify-between text-xs mb-1">
                      <span>偵測值: {a.value}</span>
                      <span>閾值: {a.threshold}</span>
                    </div>
                    <div className="w-full bg-gray-200 rounded-full h-2">
                      <div
                        className={`h-2 rounded-full ${
                          sev === 'HIGH' ? 'bg-red-500' : sev === 'MEDIUM' ? 'bg-yellow-500' : 'bg-blue-500'
                        }`}
                        style={{ width: `${Math.min((a.value / a.threshold) * 100, 100)}%` }}
                      />
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        );
      })}
    </div>
  );
}
