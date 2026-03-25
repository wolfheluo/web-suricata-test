import { useEffect, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import client from '../api/client';
import ProgressModal from '../components/ProgressModal';

interface FileInfo {
  name: string;
  size_bytes: number;
}

export default function NewTaskPage() {
  /* Folder navigation state */
  const [pathSegments, setPathSegments] = useState<string[]>([]);
  const [folders, setFolders] = useState<string[]>([]);
  const [files, setFiles] = useState<FileInfo[]>([]);
  const [browsing, setBrowsing] = useState(false);

  /* Task creation state */
  const [selectedFiles, setSelectedFiles] = useState<Set<string>>(new Set());
  const [taskName, setTaskName] = useState('');
  const [loading, setLoading] = useState(false);
  const [taskId, setTaskId] = useState<string | null>(null);
  const navigate = useNavigate();

  const currentPath = pathSegments.join('/');

  /* Load directory contents whenever path changes */
  useEffect(() => {
    setBrowsing(true);
    client
      .get('/api/v1/nas/browse', { params: { path: currentPath } })
      .then(({ data }) => {
        setFolders(data.data.folders);
        const f: FileInfo[] = data.data.files;
        setFiles(f);
        // Auto-select all pcap files when entering a folder
        setSelectedFiles(new Set(f.map((x) => x.name)));
      })
      .catch(() => {
        setFolders([]);
        setFiles([]);
      })
      .finally(() => setBrowsing(false));
  }, [currentPath]);

  /* Navigate into a subfolder */
  const enterFolder = (name: string) => {
    setPathSegments((prev) => [...prev, name]);
  };

  /* Navigate to a specific breadcrumb level (-1 = root) */
  const goToLevel = (index: number) => {
    setPathSegments((prev) => prev.slice(0, index + 1));
  };

  const toggleFile = (name: string) => {
    const next = new Set(selectedFiles);
    next.has(name) ? next.delete(name) : next.add(name);
    setSelectedFiles(next);
  };

  const toggleAll = () => {
    if (selectedFiles.size === files.length) {
      setSelectedFiles(new Set());
    } else {
      setSelectedFiles(new Set(files.map((f) => f.name)));
    }
  };

  const fmtSize = (b: number) => {
    if (b >= 1 << 30) return `${(b / (1 << 30)).toFixed(2)} GB`;
    if (b >= 1 << 20) return `${(b / (1 << 20)).toFixed(2)} MB`;
    if (b >= 1 << 10) return `${(b / (1 << 10)).toFixed(1)} KB`;
    return `${b} B`;
  };

  const totalSelected = files
    .filter((f) => selectedFiles.has(f.name))
    .reduce((s, f) => s + f.size_bytes, 0);

  const handleSubmit = async () => {
    if (!taskName || !currentPath || selectedFiles.size === 0) return;
    setLoading(true);
    try {
      const { data } = await client.post('/api/v1/tasks', {
        name: taskName,
        nas_project: currentPath,
        pcap_files: [...selectedFiles],
      });
      const id = data.data.id;
      await client.post(`/api/v1/tasks/${id}/start`);
      setTaskId(id);
    } catch (err: any) {
      alert(err.response?.data?.message || '建立失敗');
      setLoading(false);
    }
  };

  const handleDone = () => {
    if (taskId) navigate(`/dashboard/${taskId}`);
  };

  const handleError = () => {
    setTaskId(null);
    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-gray-100">
      <nav className="bg-white shadow">
        <div className="max-w-4xl mx-auto px-4 py-3 flex justify-between items-center">
          <h1 className="text-xl font-bold text-gray-800">新增分析任務</h1>
          <Link to="/tasks" className="text-gray-500 hover:text-gray-700 text-sm">
            返回列表
          </Link>
        </div>
      </nav>
      <div className="max-w-4xl mx-auto px-4 py-6 space-y-6">
        {/* Task Name */}
        <div className="bg-white p-6 rounded-lg shadow">
          <label className="block text-sm font-medium text-gray-700 mb-2">任務名稱</label>
          <input
            type="text"
            value={taskName}
            onChange={(e) => setTaskName(e.target.value)}
            placeholder="例如：Project Alpha 分析"
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        {/* Folder Navigator */}
        <div className="bg-white p-6 rounded-lg shadow">
          <label className="block text-sm font-medium text-gray-700 mb-2">NAS 資料夾路徑</label>

          {/* Breadcrumb */}
          <div className="flex items-center flex-wrap gap-1 mb-4 text-sm bg-gray-50 px-3 py-2 rounded-md">
            <button
              onClick={() => goToLevel(-1)}
              className={`hover:text-blue-600 ${pathSegments.length === 0 ? 'text-blue-600 font-semibold' : 'text-gray-500'}`}
            >
              NAS 根目錄
            </button>
            {pathSegments.map((seg, i) => (
              <span key={i} className="flex items-center gap-1">
                <span className="text-gray-400">/</span>
                <button
                  onClick={() => goToLevel(i)}
                  className={`hover:text-blue-600 ${i === pathSegments.length - 1 ? 'text-blue-600 font-semibold' : 'text-gray-500'}`}
                >
                  {seg}
                </button>
              </span>
            ))}
          </div>

          {/* Folder List */}
          {browsing ? (
            <div className="text-center text-gray-400 py-4">載入中...</div>
          ) : folders.length > 0 ? (
            <div className="max-h-64 overflow-y-auto divide-y divide-gray-100 border border-gray-200 rounded-md">
              {folders.map((f) => (
                <button
                  key={f}
                  onClick={() => enterFolder(f)}
                  className="w-full flex items-center px-3 py-2.5 hover:bg-blue-50 text-left transition"
                >
                  <svg className="w-5 h-5 text-yellow-500 mr-2 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                    <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
                  </svg>
                  <span className="text-sm text-gray-700">{f}</span>
                  <svg className="w-4 h-4 text-gray-400 ml-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </button>
              ))}
            </div>
          ) : files.length === 0 ? (
            <div className="text-center text-gray-400 py-4">此資料夾為空</div>
          ) : null}

          {/* Current selection hint */}
          {currentPath && (
            <div className="mt-3 text-xs text-gray-500">
              已選擇路徑：<span className="font-mono text-gray-700">{currentPath}</span>
            </div>
          )}
        </div>

        {/* File List */}
        {files.length > 0 && (
          <div className="bg-white p-6 rounded-lg shadow">
            <div className="flex justify-between items-center mb-3">
              <span className="text-sm font-medium text-gray-700">
                PCAP 檔案（已選 {selectedFiles.size} 個，共 {fmtSize(totalSelected)}）
              </span>
              <button onClick={toggleAll} className="text-blue-600 text-xs hover:underline">
                {selectedFiles.size === files.length ? '取消全選' : '全選'}
              </button>
            </div>
            <div className="max-h-80 overflow-y-auto divide-y divide-gray-100">
              {files.map((f) => (
                <label key={f.name} className="flex items-center px-2 py-2 hover:bg-gray-50 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={selectedFiles.has(f.name)}
                    onChange={() => toggleFile(f.name)}
                    className="mr-3"
                  />
                  <span className="flex-1 text-sm">{f.name}</span>
                  <span className="text-xs text-gray-400">{fmtSize(f.size_bytes)}</span>
                </label>
              ))}
            </div>
          </div>
        )}

        {/* Submit */}
        <button
          onClick={handleSubmit}
          disabled={loading || !taskName || !currentPath || selectedFiles.size === 0}
          className="w-full bg-blue-600 text-white py-3 rounded-md hover:bg-blue-700 disabled:opacity-50 transition font-medium"
        >
          {loading ? '處理中...' : '開始分析'}
        </button>
      </div>

      {taskId && <ProgressModal taskId={taskId} onDone={handleDone} onError={handleError} />}
    </div>
  );
}
