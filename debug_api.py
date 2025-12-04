import requests
import json

try:
    res = requests.get('http://localhost:8000/api/servers')
    data = res.json()
    # Print first 3 servers to check status and type
    print(json.dumps(data[:3], indent=2))
except Exception as e:
    print(e)
