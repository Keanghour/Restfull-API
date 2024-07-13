import jwt

# The JWT token you received
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTcyMDc2NzU0NiwianRpIjoiMWUzNzQwYjItMmU1NC00MDA4LTgyNTQtZDg3N2I4ZjBlODZjIiwidHlwZSI6Imp3dCIsInN1YiI6Ik55bFJReUdaVWdMUk1tRldjSmJtRjZCZiIsIm5iZiI6MTcyMDc2NzU0NiwiY3NyZiI6IjM2Y2I4YTdlLTk2OWQtNGEwNi04YjkzLTlhZTQ5NmE3MjY3ZSIsImV4cCI6MTcyMDc2ODQ0NiwiY2xpZW50X2lkIjoiTnlsUlF5R1pVZ0xSTW1GV2NKYm1GNkJmIiwiZ3JhbnRfdHlwZSI6ImNsaWVudF9jcmVkZW50aWFscyIsImNsaWVudF9zZWNyZXQiOiJjaWd5eUZ2bXF5dUdFc1F5cExURkJYdXRSY0lta3JqT2lzUG0ifQ.am-F1HpAPws-ApMferQg1axkfQyQt7BzR2ftt-_CXjw"

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
