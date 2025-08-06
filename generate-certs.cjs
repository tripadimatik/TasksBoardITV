const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

console.log('Generating SSL certificates...');

// Create certs directory
const certsDir = path.join(__dirname, 'server', 'certs');
if (!fs.existsSync(certsDir)) {
    fs.mkdirSync(certsDir, { recursive: true });
}

// Generate RSA key pair
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
    }
});

// Extract public key from private key and create matching certificate
const publicKeyDer = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
const publicKeyPem = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'pem' });

// Create a simple self-signed certificate that matches the private key
const selfsigned = require('selfsigned');
const attrs = [{ name: 'commonName', value: 'localhost' }];
const opts = {
  keySize: 2048,
  days: 365,
  algorithm: 'sha256',
  extensions: [
    {
      name: 'keyUsage',
      keyCertSign: true,
      digitalSignature: true,
      nonRepudiation: true,
      keyEncipherment: true,
      dataEncipherment: true
    },
    {
      name: 'extKeyUsage',
      serverAuth: true,
      clientAuth: true,
      codeSigning: true,
      timeStamping: true
    },
    {
      name: 'subjectAltName',
      altNames: [
        { type: 2, value: 'localhost' },
        { type: 7, ip: '127.0.0.1' },
        { type: 7, ip: '192.168.8.69' }
      ]
    }
  ]
};

// Generate certificate with existing private key
const pems = selfsigned.generate(attrs, { ...opts, keyPair: { privateKey, publicKey: publicKeyPem } });
const cert = pems.cert;

// Write files
fs.writeFileSync(path.join(certsDir, 'cert.pem'), cert);
fs.writeFileSync(path.join(certsDir, 'key.pem'), privateKey);

console.log('✅ SSL certificates generated successfully!');
console.log('📄 Certificate: server/certs/cert.pem');
console.log('🔑 Private Key: server/certs/key.pem');
console.log('🔐 Certificates are ready for HTTPS configuration.');