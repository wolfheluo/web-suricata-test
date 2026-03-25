import { ComposableMap, Geographies, Geography } from 'react-simple-maps';

const GEO_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json';

interface Props {
  data: Record<string, number>;
}

export default function GeoMap({ data }: Props) {
  if (!data || Object.keys(data).length === 0) return <div className="text-gray-500">無地理資料</div>;

  const entries = Object.entries(data)
    .filter(([cc]) => cc !== 'LOCAL' && cc !== 'UNKNOWN')
    .sort((a, b) => b[1] - a[1]);

  const fmtBytes = (b: number) => {
    if (b >= 1 << 30) return `${(b / (1 << 30)).toFixed(2)} GB`;
    if (b >= 1 << 20) return `${(b / (1 << 20)).toFixed(2)} MB`;
    return `${(b / (1 << 10)).toFixed(1)} KB`;
  };

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h3 className="text-lg font-bold text-gray-800 mb-4">地理分布</h3>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div>
          <ComposableMap projection="geoMercator" projectionConfig={{ scale: 120, center: [0, 30] }} height={350}>
            <Geographies geography={GEO_URL}>
              {({ geographies }) =>
                geographies.map((geo) => (
                  <Geography key={geo.rsmKey} geography={geo} fill="#e5e7eb" stroke="#d1d5db" strokeWidth={0.5} />
                ))
              }
            </Geographies>
          </ComposableMap>
        </div>
        <div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b">
                <th className="text-left py-2 px-2 font-medium text-gray-600">國家</th>
                <th className="text-right py-2 px-2 font-medium text-gray-600">流量</th>
              </tr>
            </thead>
            <tbody>
              {entries.slice(0, 20).map(([cc, bytes]) => (
                <tr key={cc} className="border-b border-gray-50">
                  <td className="py-1.5 px-2 font-mono">{cc}</td>
                  <td className="py-1.5 px-2 text-right">{fmtBytes(bytes)}</td>
                </tr>
              ))}
              {data.LOCAL && (
                <tr className="border-b border-gray-50 bg-gray-50">
                  <td className="py-1.5 px-2">LOCAL (Private)</td>
                  <td className="py-1.5 px-2 text-right">{fmtBytes(data.LOCAL)}</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
