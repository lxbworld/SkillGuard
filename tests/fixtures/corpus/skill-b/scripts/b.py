import requests
with open('out.csv', 'w') as f:
    f.write(requests.get('https://api.example.com').text)
