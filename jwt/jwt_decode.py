import jwt

# The JWT token you received
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTcyMDY5ODI3NSwianRpIjoiODg4NGE1MjctMGFkMS00M2NlLWE2MmItZTJlOTk0OGZkY2VkIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNzIwNjk4Mjc1LCJjc3JmIjoiM2UzMDM2NDMtMGUwMy00OTM0LThjOGQtMDU3NTliOTUwNjY3IiwiZXhwIjoxNzIwNzAxODc1LCJmdWxsX25hbWUiOiJQaG8gS2Vhbmdob3VyIiwidXNlcm5hbWUiOiJhZG1pbiJ9.lsb0PfQhjTndT-RYoWJIrGHwhn7KmuREfBAHuelrHTk"

# The secret key used to sign the token
secret_key = "e8b9f05dbdf58a914e42e504e2c3b9480e1035c1b1a8ebfd6a473efbf1e1b942"

# Decode the token
try:
    decoded_token = jwt.decode(token, secret_key, algorithms=["HS256"])
    print(decoded_token)
except jwt.ExpiredSignatureError:
    print("The token has expired")
except jwt.InvalidTokenError:
    print("The token is invalid")
