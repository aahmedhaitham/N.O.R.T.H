const { randomBytes } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

function makeIntegrityKey(directory, protection, hasChain) {
  const filename = path.join(directory, 'evidence-integrity.key');
  let key;
  return () => {
    if (key) return key;
    if (!protection.isEncryptionAvailable()) throw new Error('Windows key protection unavailable');
    if (fs.existsSync(filename)) {
      const encrypted = fs.readFileSync(filename);
      if (encrypted.length > 8192) throw new Error('Invalid protected evidence key');
      const decrypted = protection.decryptString(encrypted);
      if (!/^[a-f0-9]{64}$/.test(decrypted)) throw new Error('Invalid protected evidence key');
      key = decrypted;
      return key;
    }
    if (hasChain()) throw new Error('Existing evidence chain is missing its protected key');
    const generated = randomBytes(32).toString('hex');
    fs.mkdirSync(directory, { recursive: true });
    fs.writeFileSync(filename, protection.encryptString(generated), { flag: 'wx', mode: 0o600 });
    key = generated;
    return key;
  };
}

module.exports = { makeIntegrityKey };
