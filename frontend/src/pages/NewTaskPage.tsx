import { useEffect, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import client from '../api/client';
import ProgressModal from '../components/ProgressModal';

interface FileInfo {
  name: string;
  size_bytes: number;
}

export default function NewTaskPage() {
  const [projects, setProjects] = useState<string[]>([]);
  const [selectedProject, setSelectedProject] = useState('');
  const [files, setFiles] = useState<FileInfo[]>([]);
  const [selectedFiles, setSelectedFiles] = useState<Set<string>>(new Set());
  const [taskName, setTaskName] = useState('');
  const [loading, setLoading] = useState(false);
  const [taskId, setTaskId] = useState<string | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    client.get('/api/v1/nas/projects').then(({ data }) => {
      setProjects(data.data.projects);
    });
  }, []);

  useEffect(() => {
    if (!selectedProject) { setFiles([]); return; }
    client.get(`/api/v1/nas/projects/${selectedProject}/files`).then(({ data }) => {
      const f: FileInfo[] = data.data.files;
      setFiles(f);
      setSelectedFiles(new Set(f.map((x) => x.name)));
    });
  }, [selectedProject]);

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

  const totalSelected = files.filter((f) => selectedFiles.has(f.name)).reduce((s, f) => s + f.size_bytes, 0);

  const handleSubmit = async () => {
    if (!taskName || !selectedProject || selectedFiles.size === 0) return;
    setLoading(true);
    try {
      const { data } = await client.post('/api/v1/tasks', {
        name: taskName,
        nas_project: selectedProject,
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
          <Link to="/tasks" className="text-gray-500 hover:text-gray-700 text-sm">返回列表</Link>
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

        {/* Project Selector */}
        <div className="bg-white p-6 rounded-lg shadow">
          <label className="block text-sm font-medium text-gray-700 mb-2">NAS 專案資料夾</label>
          <select
            value={selectedProject}
            onChange={(e) => setSelectedProject(e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="">— 選擇專案 —</option>
            {projects.map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
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
          disabled={loading || !taskName || !selectedProject || selectedFiles.size === 0}
          className="w-full bg-blue-600 text-white py-3 rounded-md hover:bg-blue-700 disabled:opacity-50 transition font-medium"
        >
          {loading ? '處理中...' : '開始分析'}
        </button>
      </div>

      {taskId && <ProgressModal taskId={taskId} onDone={handleDone} onError={handleError} />}
    </div>
  );
}
