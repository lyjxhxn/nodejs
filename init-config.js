'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const base = process.env.KATABUMP_BASE || __dirname;
fs.mkdirSync(path.join(base, 'singbox'), { recursive: true });

function create(file, value) {
  try {
    fs.writeFileSync(path.join(base, file), JSON.stringify(value, null, 2) + '\n', {
      flag: 'wx', mode: 0o600
    });
    console.log('Created:', file);
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    console.log('Preserved existing file:', file);
  }
}

const config = JSON.parse(fs.readFileSync(path.join(__dirname, 'singbox/config.example.json'), 'utf8'));
for (const inbound of config.inbounds) {
  for (const user of inbound.users) {
    if ('uuid' in user) user.uuid = crypto.randomUUID();
    if ('password' in user) user.password = crypto.randomBytes(32).toString('hex');
  }
}
create('singbox/config.json', config);
create('ssl-config.json', JSON.parse(fs.readFileSync(path.join(__dirname, 'ssl-config.example.json'), 'utf8')));
console.log('Fill in ssl-config.json locally. Never commit private configuration.');
