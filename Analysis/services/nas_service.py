"""NAS 瀏覽服務 — 讀取已掛載的 CIFS/NFS 共享目錄"""

from pathlib import Path
import config


class NASService:
    BASE_PATH: Path = Path(config.NAS_MOUNT_PATH)

    def list_project_folders(self) -> list[str]:
        """列出根目錄下的子資料夾名稱"""
        if not self.BASE_PATH.exists():
            raise FileNotFoundError("NAS 掛載點不存在")
        return [p.name for p in sorted(self.BASE_PATH.iterdir()) if p.is_dir()]

    def browse_directory(self, subpath: str = "") -> dict:
        """瀏覽任意層級目錄，回傳 folders 與 files"""
        target = self._validate_path(subpath) if subpath else self.BASE_PATH.resolve()
        if not target.is_dir():
            raise FileNotFoundError(f"資料夾不存在：{subpath}")

        folders: list[str] = []
        files: list[dict] = []
        for p in sorted(target.iterdir()):
            if p.name.startswith(".") or p.name.startswith("#"):
                continue
            if p.is_dir():
                folders.append(p.name)
            elif p.suffix.lower() in (".pcap", ".pcapng"):
                files.append({"name": p.name, "size_bytes": p.stat().st_size})
        return {"folders": folders, "files": files}

    def get_pcap_paths(self, subpath: str, filenames: list[str]) -> list[str]:
        """回傳驗證過的 pcap 絕對路徑列表"""
        base = self._validate_path(subpath)
        paths = []
        for fn in filenames:
            fpath = (base / fn).resolve()
            if not fpath.is_relative_to(base):
                raise ValueError("偵測到路徑穿越攻擊")
            if not fpath.exists():
                raise FileNotFoundError(f"檔案不存在：{fn}")
            paths.append(str(fpath))
        return paths

    def _validate_path(self, rel_path: str) -> Path:
        """驗證相對路徑安全性"""
        if ".." in rel_path.split("/"):
            raise ValueError("偵測到路徑穿越攻擊")
        resolved = (self.BASE_PATH / rel_path).resolve()
        if not resolved.is_relative_to(self.BASE_PATH.resolve()):
            raise ValueError("偵測到路徑穿越攻擊")
        return resolved


nas_service = NASService()
