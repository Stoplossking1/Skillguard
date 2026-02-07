const fs = require('fs');
const path = require('path');

function formatFile(filepath) {
  const content = fs.readFileSync(filepath, 'utf-8');
  const formatted = content.replace(/\t/g, '  ');
  fs.writeFileSync(filepath, formatted);
  console.log(`Formatted: ${filepath}`);
}

const target = process.argv[2];
if (target) {
  formatFile(target);
}

module.exports = { formatFile };
