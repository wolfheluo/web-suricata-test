import { useEffect, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import client from '../api/client';

interface Task {
  id: string;
  name: string;
  status: string;
  nas_project: string;
  pcap_count: number;
  created_at: string;
  finished_at: string | null;
  error_msg: string | null;
}

export default function TaskListPage() {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const pageSize = 20;
  const navigate = useNavigate();

  const fetchTasks = async () => {
    setLoading(true);
    try {
      const { data } = await client.get('/api/v1/tasks', { params: { page, page_size: pageSize } });
      setTasks(data.data);
      setTotal(data.total);
    } catch {
      // handled by interceptor
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchTasks(); }, [page]);

  const handleDelete = async (id: string) => {
    if (!confirm('確定要刪除此任務？')) return;
    await client.delete(`/api/v1/tasks/${id}`);
    fetchTasks();
  };

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    navigate('/login');
  };

  const statusColor: Record<string, string> = {
    pending: 'bg-yellow-100 text-yellow-800',
    running: 'bg-blue-100 text-blue-800',
    done: 'bg-green-100 text-green-800',
    failed: 'bg-red-100 text-red-800',
  };

  const totalPages = Math.ceil(total / pageSize);

  return (
    <div className="min-h-screen bg-gray-100">
      <nav className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 py-3 flex justify-between items-center">
          <h1 className="text-xl font-bold text-gray-800">Suricata 分析任務</h1>
          <div className="flex gap-3">
            <Link to="/tasks/new" className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 text-sm">
              新增任務
            </Link>
            <button onClick={handleLogout} className="text-gray-500 hover:text-gray-700 text-sm">
              登出
            </button>
          </div>
        </div>
      </nav>
      <div className="max-w-7xl mx-auto px-4 py-6">
        {loading ? (
          <div className="text-center py-10 text-gray-500">載入中...</div>
        ) : tasks.length === 0 ? (
          <div className="text-center py-10 text-gray-500">
            尚無分析任務，
            <Link to="/tasks/new" className="text-blue-600 hover:underline">建立第一個任務</Link>
          </div>
        ) : (
          <>
            <div className="bg-white rounded-lg shadow overflow-hidden">
              <table className="w-full text-sm">
                <thead className="bg-gray-50 text-left">
                  <tr>
                    <th className="px-4 py-3 font-medium text-gray-600">任務名稱</th>
                    <th className="px-4 py-3 font-medium text-gray-600">NAS 專案</th>
                    <th className="px-4 py-3 font-medium text-gray-600">PCAP 數</th>
                    <th className="px-4 py-3 font-medium text-gray-600">狀態</th>
                    <th className="px-4 py-3 font-medium text-gray-600">建立時間</th>
                    <th className="px-4 py-3 font-medium text-gray-600">操作</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {tasks.map((t) => (
                    <tr key={t.id} className="hover:bg-gray-50">
                      <td className="px-4 py-3">{t.name}</td>
                      <td className="px-4 py-3 text-gray-500">{t.nas_project}</td>
                      <td className="px-4 py-3">{t.pcap_count}</td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-1 rounded-full text-xs font-medium ${statusColor[t.status] || ''}`}>
                          {t.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-gray-500">
                        {new Date(t.created_at).toLocaleString('zh-TW')}
                      </td>
                      <td className="px-4 py-3 space-x-2">
                        {t.status === 'done' && (
                          <Link to={`/dashboard/${t.id}`} className="text-blue-600 hover:underline text-xs">
                            查看
                          </Link>
                        )}
                        <button
                          onClick={() => handleDelete(t.id)}
                          className="text-red-500 hover:underline text-xs"
                        >
                          刪除
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {totalPages > 1 && (
              <div className="flex justify-center gap-2 mt-4">
                <button
                  disabled={page <= 1}
                  onClick={() => setPage(page - 1)}
                  className="px-3 py-1 text-sm bg-white border rounded disabled:opacity-50"
                >
                  上一頁
                </button>
                <span className="px-3 py-1 text-sm text-gray-600">
                  {page} / {totalPages}
                </span>
                <button
                  disabled={page >= totalPages}
                  onClick={() => setPage(page + 1)}
                  className="px-3 py-1 text-sm bg-white border rounded disabled:opacity-50"
                >
                  下一頁
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
