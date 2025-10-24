# URLValidator

urlvalidator/
  ├─ main.py
  ├─ settings.py
  ├─ requirements.txt
  └─ Dockerfile   (선택)

## API 실행

uvicorn main:app --host 0.0.0.0 --port 8000

## WEB 실행

python -m http.server 80