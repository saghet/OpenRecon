import sys
import os
import uvicorn

def main():
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, backend_dir)
    print("==================================================================")
    print("  FortiRecon / OpenRecon Enterprise Backend (FastAPI Engine)")
    print("  EASM, DRP, CTI, Cloud & Continuous Exposure Management")
    print("==================================================================")
    print("[*] Listening on: http://127.0.0.1:8000")
    print("[*] Interactive Swagger API Docs: http://127.0.0.1:8000/docs")
    print("[*] OpenAPI Specification: http://127.0.0.1:8000/api/v1/openapi.json")
    print("==================================================================")
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=False, log_level="info")

if __name__ == "__main__":
    main()
