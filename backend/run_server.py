import os
import sys
import uvicorn


def _ensure_streams(log_dir: str) -> None:
    """Ensure stdout/stderr are valid streams when launched via pythonw.exe."""
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "uvicorn.log")
    if sys.stdout is None or sys.stderr is None:
        log_file = open(log_path, "a", encoding="utf-8", buffering=1)
        if sys.stdout is None:
            sys.stdout = log_file
        if sys.stderr is None:
            sys.stderr = log_file


def main():
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, backend_dir)
    _ensure_streams(os.path.join(backend_dir, "logs"))
    print("==================================================================")
    print("  FortiRecon / OpenRecon Enterprise Backend (FastAPI Engine)")
    print("  EASM, DRP, CTI, Cloud & Continuous Exposure Management")
    print("==================================================================")
    print("[*] Listening on: http://127.0.0.1:8000")
    print("[*] Interactive Swagger API Docs: http://127.0.0.1:8000/docs")
    print("[*] OpenAPI Specification: http://127.0.0.1:8000/api/v1/openapi.json")
    print("==================================================================")
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=False, log_level="info", use_colors=False)


if __name__ == "__main__":
    main()
