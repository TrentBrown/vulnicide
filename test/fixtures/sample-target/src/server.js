// Deliberately vulnerable sample code for the vulnicide CLI smoke test. Never deploy.
const http = require('http');
const { URL } = require('url');
const { exec } = require('child_process');

http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const name = url.searchParams.get('name');
    const host = url.searchParams.get('host');
    exec('ping -c 1 ' + host, (error, stdout) => {
        res.end('<p>Hello ' + name + '</p><pre>' + stdout + '</pre>');
    });
}).listen(8080);
