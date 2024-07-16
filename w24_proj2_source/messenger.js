'use strict'

/** ******* Imports ********/
const { subtle } = require('crypto');
const {
  bufferToString,
  genRandomSalt,
  generateEG, // async: generates an Elliptic-curve Diffie-Hellman (ECDH) key pair
  computeDH, // async: computes the shared secret using the private key and peer's public key
  verifyWithECDSA, // async: verifies the ECDSA signature
  HMACtoAESKey, // async: converts an HMAC key to an AES key
  HMACtoHMACKey, // async: derives an HMAC key using HMAC
  HKDF, // async: key derivation function
  encryptWithGCM, // async: encrypts data with AES-GCM
  decryptWithGCM, // async: decrypts data with AES-GCM
  cryptoKeyToJSON, // async: converts a CryptoKey to JSON
  govEncryptionDataStr // constant: used for government encryption data
} = require('./lib');

/** ******* Helper Function ********/
function byteArrayToString(byteArray) {
  // Converts a byte array to a string
  return String.fromCharCode.apply(null, new Uint8Array(byteArray));
}

/** ******* MessengerClient Class ********/
class MessengerClient {
  constructor(certAuthorityPublicKey, govPublicKey) {
    // Initialize with CA and government public keys
    this.caPublicKey = certAuthorityPublicKey;
    this.govPublicKey = govPublicKey;
    this.conns = {}; // Stores connection data for different users
    this.certs = {}; // Stores certificates for different users
    this.EGKeyPair = {}; // Stores the user's own ECDH key pair
  }

  async generateCertificate(username) {
    // Generates a certificate containing the username and public key
    this.EGKeyPair = await generateEG();
    const certificate = {
      username: username,
      pub: this.EGKeyPair.pub
    };
    return certificate;
  }

  async receiveCertificate(certificate, signature) {
    // Verifies and stores a received certificate
    const certString = JSON.stringify(certificate);
    const verification = await verifyWithECDSA(this.caPublicKey, certString, signature);

    if (verification) {
      this.certs[certificate.username] = certificate.pub;
      this.conns[certificate.username] = {
        SKs: this.EGKeyPair.sec, // User's own private key
        PKs: this.EGKeyPair.pub, // User's own public key
        PKr: certificate.pub, // Peer public key
        sendChain: [],
        recChain: [],
        oldPairs: [],
        SKsLast: this.EGKeyPair.sec,
        PKrFirst: certificate.pub
      };
    } else {
      throw ('Invalid certificate');
    }
  }

  async sendMessage(name, plaintext) {
    // Sends an encrypted message to a peer
    this.conns[name].recChain = [];
    const dhSecret1 = await computeDH(this.conns[name].SKs, this.conns[name].PKr);

    let kdfInput;
    if (this.conns[name].sendChain.length === 0) {
      // Perform a ratchet step if it's the first message
      this.conns[name].oldPairs.push({ sec: this.conns[name].SKs, secLast: this.conns[name].SKsLast });
      while (this.conns[name].oldPairs.length > 5) {
        this.conns[name].oldPairs.shift();
      }

      const newKeyPair = await generateEG();
      this.conns[name].SKsLast = this.conns[name].SKs;
      this.conns[name].SKs = newKeyPair.sec;
      this.conns[name].PKs = newKeyPair.pub;

      const secKey = this.conns[name].SKs;
      const pubKey = this.conns[name].PKr;
      const dhSecret2 = await computeDH(secKey, pubKey);
      kdfInput = dhSecret2;
    } else {
      kdfInput = this.conns[name].sendChain[this.conns[name].sendChain.length - 1][0];
    }

    const hkdfSalt = await HMACtoHMACKey(dhSecret1, "HMAC");
    let derivedKeyPair = await HKDF(kdfInput, hkdfSalt, "ratchet-str");
    this.conns[name].sendChain.push(derivedKeyPair);

    let derivedKey = derivedKeyPair[1];
    let derivedKeyAES = await HMACtoAESKey(derivedKey, "AESKeyGen");
    const salt = await genRandomSalt();

    // Encrypting with government key
    let govKey = await computeDH(this.EGKeyPair.sec, this.govPublicKey);
    govKey = await HMACtoAESKey(govKey, govEncryptionDataStr);
    const saltGov = await genRandomSalt();
    const plaintextGov = await HMACtoAESKey(derivedKey, "AESKeyGen", true);
    const ciphertextGov = await encryptWithGCM(govKey, plaintextGov, saltGov);

    const header = {
      newPubKey: this.conns[name].PKs,
      receiverIV: salt,
      vGov: this.EGKeyPair.pub,
      cGov: ciphertextGov,
      ivGov: saltGov,
      sendChainIndex: this.conns[name].sendChain.length
    };

    const ciphertext = await encryptWithGCM(derivedKeyAES, plaintext, salt, JSON.stringify(header));
    return [header, ciphertext];
  }

  async receiveMessage(name, [header, ciphertext]) {
    // Receives and decrypts a message from a peer
    const dhSecret1 = await computeDH(this.conns[name].SKs, this.conns[name].PKr);
    if (header.newPubKey !== this.conns[name].PKr) {
      // Update public key if a new one is received
      this.conns[name].PKr = header.newPubKey;
      this.conns[name].recChain = [];
    }
    this.conns[name].sendChain = [];

    let derivedKeyPair;
    let hkdfSalt;

    if (this.conns[name].recChain.length === 0) {
      // Perform a ratchet step if it's the first message
      const secKey = this.conns[name].SKs;
      const pubKey = this.conns[name].PKr;
      const dhSecret2 = await computeDH(secKey, pubKey);

      hkdfSalt = await HMACtoHMACKey(dhSecret1, "HMAC");

      derivedKeyPair = await HKDF(dhSecret2, hkdfSalt, "ratchet-str");
      derivedKeyPair.push("UNREAD");
      this.conns[name].recChain.push(derivedKeyPair);
    }

    if (header.sendChainIndex > this.conns[name].recChain.length) {
      // Derive keys up to the current sendChainIndex
      for (let i = this.conns[name].recChain.length - 1; i < header.sendChainIndex - 1; i++) {
        let kdfInput = this.conns[name].recChain[i][0];
        hkdfSalt = await HMACtoHMACKey(dhSecret1, "HMAC");
        derivedKeyPair = await HKDF(kdfInput, hkdfSalt, "ratchet-str");
        derivedKeyPair.push("UNREAD");
        this.conns[name].recChain.push(derivedKeyPair);
      }
    }

    if (this.conns[name].recChain[header.sendChainIndex - 1][2] === "READ") {
      throw "REPLAY ATTACK"; // Detect replay attack
    }

    let derivedKey = this.conns[name].recChain[header.sendChainIndex - 1][1];
    derivedKey = await HMACtoAESKey(derivedKey, "AESKeyGen");
    let plaintext;
    try {
      plaintext = await decryptWithGCM(derivedKey, ciphertext, header.receiverIV, JSON.stringify(header));
    } catch {
      // Attempt to decrypt with old key pairs if the initial decryption fails
      for (let i = 0; i < this.conns[name].oldPairs.length; i++) {
        let pubKeyTest = header.newPubKey;
        let secKeyTest = this.conns[name].oldPairs[i].sec;
        let secKeyLastTest = this.conns[name].oldPairs[i].secLast;

        let dhSecret1Test = await computeDH(secKeyLastTest, this.conns[name].PKrFirst);
        let dhSecret2Test = await computeDH(secKeyTest, pubKeyTest);
        let hkdfSaltTest = await HMACtoHMACKey(dhSecret1Test, "HMAC");

        derivedKeyPair = await HKDF(dhSecret2Test, hkdfSaltTest, "ratchet-str");
        derivedKeyPair.push("UNREAD");
        let recChainTest = [];
        recChainTest.push(derivedKeyPair);

        let kdfInputTest;
        for (let i = recChainTest.length - 1; i < header.sendChainIndex - 1; i++) {
          dhSecret1Test = dhSecret2Test;

          kdfInputTest = recChainTest[i][0];
          hkdfSaltTest = await HMACtoHMACKey(dhSecret1Test, "HMAC");
          derivedKeyPair = await HKDF(kdfInputTest, hkdfSaltTest, "ratchet-str");
          derivedKeyPair.push("UNREAD");
          recChainTest.push(derivedKeyPair);
        }

        let derivedKeyTest = recChainTest[header.sendChainIndex - 1][1];
        derivedKeyTest = await HMACtoAESKey(derivedKeyTest, "AESKeyGen");
        try {
          plaintext = await decryptWithGCM(derivedKeyTest, ciphertext, header.receiverIV, JSON.stringify(header));
          break;
        } catch { }
      }
    }

    if (!plaintext) {
      throw "Decryption failed"; // Decryption failed even after retrying with old keys
    }

    this.conns[name].recChain[header.sendChainIndex - 1][2] = "READ";
    return byteArrayToString(plaintext);
  }
}

module.exports = {
  MessengerClient
};
