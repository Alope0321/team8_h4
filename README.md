# team8_h4
## CSCI 4406 - Computer Networks - Homework 4
## Team 8:
Adrian Lopez, Mallory Sorola, Isabel Villarreal, Emma Whitehead, Anthony Whitmore

## Questions

### What is your strategy for identifying unique clients?

Our strategy for identifying unique clients is in the compute_client_id function. Our program checks the x-client-app header value, which is where the client can name its application identity. If there's no x-client-app header, the program falls back to check the user-agent, source IP, and host ID to identify unique clients.

### How do you prevent the clients from opening more connections once they have opened the maximum number of connections?

The admit_connection function will use the client_id value to identify connections and provided that it is under the connection limit, it will increment a counter until it reaches the limit. Once it's at the limit, it will close send an error response and close the connection immediately so it does not exceed the limit.

### Report the times and speedup for concurrent fetch of the URLs in testcase 1 and 2 with the stock http server.

### Report the times and speedup for concurrent fetch of the URLs in testcase 1 and 2 with your http_server_conc. Are these numbers same as above? Why or why not?

