const forge = require('node-forge');

function encryptForClientRSA(publicKeyPem, plaintext) {
  const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
  const encrypted = publicKey.encrypt(plaintext, 'RSA-OAEP', {
    md: forge.md.sha256.create(),
    mgf1: forge.mgf.mgf1.create()
  });
  return Buffer.from(encrypted, 'binary').toString('base64');
}

module.exports = { encryptForClientRSA };
