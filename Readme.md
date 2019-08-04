**TL;DR**

Clone the repository (Assuming you have Go installed)

Execute the following commands:

  `go run server/main.go`

  `go run client/main.go`

You will see responses of 1 5 6 20 

**What this code is about**
1. This code base includes a gRPC server including bidirectional streaming facility
2. The function in the server takes a stream of Request message that has one integer, and returns a stream of Responses that represent the current maximum between all these integers so far
3. Client generates its own public-private key.
4. Client signs every request message in the stream. Each requested message is verified against the signature at the server end. Only those numbers are considered to be processed whose sign is successfully verified.

**Description of code base**
1. The client creates public and private key pair,
2. Converts them to bytes,
3. Client has a series of numbers as input, each is converted to []byte
4. Client also create signature with private key
5. Client sends all the above information as streams across a gRPC network
6. Server accepts the stream and verifies using the signature
7. Only if it is verified, then the server converts and does processing on the input number to find out maximum so far
8. Then it returns the max number using a stream over gRPC 
9. Run `go test ./...` to run the tests



