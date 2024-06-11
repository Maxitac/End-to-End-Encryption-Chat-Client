'use strict'

const forge = require('node-forge/lib/forge')
/** ******* Imports ********/

const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  bufferToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')

/** ******* Implementation ********/

class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.conns = {} // data for each active connection
    this.certs = {} // certificates of other users
    this.EGKeyPair = {} // keypair from generateCertificate
    this.receivedMessages = new Set();// Track received messages
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate (username) {
    try{
      //generate ephemeral key pair
      this.EGKeyPair = await generateEG();
    // Extract public key in PEM
      const publicKeyPem = forge.pki.publicKeyToPem(this.EGKeyPair.publicKey)

      //create certificate object
      const certificate = {
        username: username,
        publicKey: forge.pki.publicKeyToPem(this.EGKeyPair,publicKey),
        issuedAt: new Date().toISOString
      };
      return certificate;
    } catch (err){
      console.error('Error generating certificate: ', err);
      throw err;
    }
  }

  /**
 * Receive and store another user's certificate.
 *
 * Arguments:
 *   certificate: certificate object/dictionary
 *   signature: ArrayBuffer
 *
 * Return Type: void
 */
  async receiveCertificate(certificate, signature) {
    try {
      // Convert the certificate object to a JSON string
      const certString = JSON.stringify(certificate);

      // Verify the signature using the certificate authority's public key
      const verified = await verifyWithECDSA(this.caPublicKey, signature, certString);

      if (verified) {
        // Store the certificate if the signature is valid
        this.certs[certificate.username] = certificate;
        console.log(`Certificate for ${certificate.username} stored successfully.`);
      } else {
        throw new Error('Invalid certificate signature');
      }
    } catch (err) {
      console.error('Error receiving certificate:', err);
      throw err;
    }
  }

  /**
 * Generate the message to be sent to another user.
 *
 * Arguments:
 *   name: string
 *   plaintext: string
 *
 * Return Type: Tuple of [dictionary, ArrayBuffer]
 */
  async sendMessage(recipient, plaintext) {
    if (!this.certificates[recipient]) {
      throw new Error(`No certificate for recipient: ${recipient}`);
    }
  
    const messageID = crypto.randomUUID(); // Generate a unique message ID
    const timestamp = Date.now(); // Current timestamp
  
    const header = {
      sender: this.cert.identity,
      recipient,
      timestamp,
      messageID,
      vGov: this.govPublicKey
    };
  
    const sharedSecret = await computeDH(this.cert.privateKey, this.certificates[recipient].publicKey);
    const encryptionKey = await HMACtoAESKey(sharedSecret, govEncryptionDataStr);
  
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await encryptWithGCM(encryptionKey, plaintext, iv, JSON.stringify(header));
  
    return [header, ciphertext];
  }
  
  

  /**
 * Decrypt a message received from another user.
 *
 * Arguments:
 *   name: string
 *   [header, ciphertext]: Tuple of [dictionary, ArrayBuffer]
 *
 * Return Type: string
 */
  async receiveMessage(sender, [header, ciphertext]) {
    if (!this.certificates[sender]) {
      throw new Error(`No certificate for sender: ${sender}`);
    }
  
    const { messageID, timestamp } = header;
  
    // Check for replay attack
    if (this.receivedMessages.has(messageID)) {
      throw new Error(`Replay attack detected: message ID ${messageID} has already been received`);
    }
  
    // Check timestamp (optional, for more strict validation)
    const currentTime = Date.now();
    const timeDifference = currentTime - timestamp;
    const acceptableDelay = 300000; // 5 minutes
    if (timeDifference > acceptableDelay) {
      throw new Error('Message too old, possible replay attack');
    }
  
    const sharedSecret = await computeDH(this.cert.privateKey, this.certificates[sender].publicKey);
    const encryptionKey = await HMACtoAESKey(sharedSecret, govEncryptionDataStr);
  
    const plaintext = await decryptWithGCM(encryptionKey, ciphertext, header.receiverIV, JSON.stringify(header));
  
    // Add message ID to the receivedMessages set
    this.receivedMessages.add(messageID);
  
    return bufferToString(plaintext);
  }
  
  
};

module.exports = {
  MessengerClient
}