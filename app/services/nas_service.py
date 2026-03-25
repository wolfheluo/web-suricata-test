"""NAS browsing service — reads from pre-mounted CIFS share."""

import re
from pathlib import Path

from app.config import settings


class NASService:
    BASE_PATH: Path = Path(settings.NAS_MOUNT_PATH)
    _SAFE_NAME = re.compile(r"^[a-zA-Z0-9_\-.\s]+$")

    def list_project_folders(self) -> list[str]:
        """Return direct subdirectory names under BASE_PATH."""
        return [p.name for p in sorted(self.BASE_PATH.iterdir()) if p.is_dir()]

    def get_pcap_files(self, project_folder: str) -> list[dict]:
        """Return list of dicts with name and size_bytes for pcap/pcapng files."""
        base = self._validate_path(project_folder)
        result = []
        for p in sorted(base.iterdir()):
            if p.suffix.lower() in (".pcap", ".pcapng"):
                result.append({"name": p.name, "size_bytes": p.stat().st_size})
        return result

    def get_pcap_paths(self, project_folder: str, filenames: list[str]) -> list[str]:
        """Return validated absolute paths for given pcap filenames."""
        base = self._validate_path(project_folder)
        paths = []
        for fn in filenames:
            if not self._SAFE_NAME.match(fn):
                raise ValueError(f"無效的檔案名稱：{fn!r}")
            fpath = (base / fn).resolve()
            if not fpath.is_relative_to(base):
                raise ValueError("偵測到路徑穿越攻擊")
            if not fpath.exists():
                raise FileNotFoundError(f"檔案不存在：{fn}")
            paths.append(str(fpath))
        return paths

    def _validate_path(self, folder_name: str) -> Path:
        if not self._SAFE_NAME.match(folder_name):
            raise ValueError(f"無效的資料夾名稱：{folder_name!r}")
        resolved = (self.BASE_PATH / folder_name).resolve()
        if not resolved.is_relative_to(self.BASE_PATH.resolve()):
            raise ValueError("偵測到路徑穿越攻擊")
        return resolved


nas_service = NASService()
