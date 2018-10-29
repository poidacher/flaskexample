import oauth2 as oauth

# Create your consumer with the proper key/secret.
consumer = oauth.Consumer(key="your-twitter-consumer-key",
    secret="your-twitter-consumer-secret")

# Request token URL for Twitter.
request_token_url = "https://api.twitter.com/oauth/request_token"

# Create our client.
client = oauth.Client(consumer)

# The OAuth Client request works just like httplib2 for the most part.
resp, content = client.request(request_token_url, "GET")


