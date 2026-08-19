import urllib.request, json
urls = [
    'http://127.0.0.1:3000/api/alerts',
    'http://127.0.0.1:3000/api/stats',
    'http://127.0.0.1:3000/api/canary-events'
]
for u in urls:
    try:
        with urllib.request.urlopen(u, timeout=10) as r:
            print('---', u)
            data = r.read().decode('utf-8')
            try:
                parsed = json.loads(data)
                print(json.dumps(parsed, indent=2)[:1000])
            except Exception:
                print(data[:1000])
    except Exception as e:
        print('ERR', u, e)
