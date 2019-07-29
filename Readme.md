Steps: 

Client will create his account first

This means it will request the server to create a public-private key pair for him and send back the private key.

Then client is ready to send his request with his private key. 

Client sends the stream after signing his info. 

Server uses the public key of the client to authenticate and then send result back. 

Is it okay to create and send private key from server to client? If not, then is the client supposed to just create his own private key, from this create public key and then send it to server? 

