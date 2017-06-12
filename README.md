# Run the web & api
You shoule run the following file in web folder.
```
python restAPI.py
```

# Open the website
```
localhost:5000
```

# Supporting API
1. Encrypt
```
http://localhost:5000/api/ocb/encrypt
POST
{	
	"plaintext": "your plaintext",
	"header": "your header"
}
```

2. Decrypt
```
http://localhost:5000/api/ocb/decrypt
POST
{	
	"ciphertext": "your ciphertext",
	"header": "your header",
	"tag": "your tag"
}
```
