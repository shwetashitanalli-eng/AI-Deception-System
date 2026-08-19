const http = require('http');

// Define the hostname and port
const HOSTNAME = '127.0.0.1';
const PORT = 3000;

// Create the server
const server = http.createServer((req, res) => {
  // Set the response HTTP header with HTTP status and Content Type
  res.writeHead(200, { 'Content-Type': 'application/json' });
  
  // Send the response body
  const responseObj = {
    message: "Hello from the Node.js server!",
    url: req.url,
    method: req.method
  };
  
  res.end(JSON.stringify(responseObj));
});

// Start listening for requests
server.listen(PORT, HOSTNAME, () => {
  console.log(`Node.js server running at http://${HOSTNAME}:${PORT}/`);
});