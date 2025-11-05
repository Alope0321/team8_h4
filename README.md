# CSCI 4406 - Computer Networks - Fall 2025 - Homework 4
### Team 8: Adrian Lopez, Mallory Sorola, Isabel Villarreal, Emma Whitehead, Anthony Whitmore

## How to run the program:
Run the command ``` python http_server_conc.py -p [port number] -maxclient 10 -maxtotal 60 --root [root]``` in one terminal, then open another and run: \
for a single file: \
``` curl http://localhost:20001/[test file] -o [output] ``` \

for multiple files: \
```curl -s http://localhost:20001/[test files].txt \``` \
```| while read -r url; do``` \
```   [ -z "$url" ] && continue``` \
```   curl -O "$url"``` \
```done```


## Questions

### What is your strategy for identifying unique clients?

Our strategy for identifying unique clients is in the compute_client_id function. Our program checks the x-client-app header value, which is where the client can name its application identity. If there's no x-client-app header, the program falls back to check the user-agent, source IP, and host ID to identify unique clients.

### How do you prevent the clients from opening more connections once they have opened the maximum number of connections?

The admit_connection function will use the client_id value to identify connections and provided that it is under the connection limit, it will increment a counter until it reaches the limit. Once it's at the limit, it will close send an error response and close the connection immediately so it does not exceed the limit.

### Report the times for sequential fetch of the URLs in testcase 1 and 2 with the stock http server.

http_client (hw2): 
| Testcase          | Time (s) |
| ----------------- | -------- |
| Testfiles1        | 26.301   |
| Testfiles2        | 7.035    |
| Testfiles1.tar.gz | 0.372    |
| Testfiles2.tar.gz | 3.136    |

### Report the times and speedup for concurrent fetch of the URLs in testcase 1 and 2 with your http_server_conc. Are these numbers same as above? Why or why not?
http_server_conc:
| Testcase          | Time (s) | Speedup vs stock        |
| ----------------- | -------- | ----------------------- |
| Testfiles1        | 15.734   | 26.301 / 15.734 = 1.67x |
| Testfiles2        | 2.514    | 7.035 / 2.514 = 2.80x   |
| Testfiles1.tar.gz | 0.042    | 0.372 / 0.042 = 8.86x   |
| Testfiles2.tar.gz | 0.043    | 3.136 / 0.043 = 72.93x  |


These numbers are not the same since the stock http server is programmed to download files sequentially. http_server_conc is designed to download files concurrently. Concurrent downloads are faster than sequential downloads since there are multiple download streams running instead of a single download stream when downloading sequentially.
