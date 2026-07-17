// Generates cross-implementation known-answer vectors from the REAL
// @railgun-community/engine, for the Go railguncrypto package to validate against.
// Every crypto operation here is the engine's own code path.
const E = 'node_modules/@railgun-community/engine/dist';
const keys = require(`./${E}/utils/keys-utils.js`);
const { AES } = require(`./${E}/utils/encryption/aes.js`);
const { ByteUtils } = require(`./${E}/utils/bytes.js`);
const { TransactNote } = require(`./${E}/note/transact-note.js`);
const { MEMO_SENDER_RANDOM_NULL } = require(`./${E}/models/transaction-constants.js`);

const hx = (u8) => Buffer.from(u8).toString('hex');

async function main() {
  const out = { ecdh: [], blinding: [], gcm: [], notes: [] };

  // Fixed key material (deterministic).
  const senderSeed = 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1';
  const receiverSeed = 'b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2';
  const senderSeedB = ByteUtils.hexStringToBytes(senderSeed);
  const receiverSeedB = ByteUtils.hexStringToBytes(receiverSeed);
  const senderPub = await keys.getPublicViewingKey(senderSeedB);
  const receiverPub = await keys.getPublicViewingKey(receiverSeedB);

  // --- ECDH ---
  {
    const s = await keys.getSharedSymmetricKey(senderSeedB, receiverPub);
    out.ecdh.push({ seed: senderSeed, blindedPub: hx(receiverPub), sharedKey: hx(s) });
    const s2 = await keys.getSharedSymmetricKey(receiverSeedB, senderPub);
    out.ecdh.push({ seed: receiverSeed, blindedPub: hx(senderPub), sharedKey: hx(s2) });
  }

  // --- Blinding (byte-exact) + unblind ---
  {
    const random = '85b08a7cd73ee433072f1d410aeb4801';
    for (const senderRandom of [MEMO_SENDER_RANDOM_NULL, '0102030405060708090a0b0c0d0e0f']) {
      const { blindedSenderViewingKey, blindedReceiverViewingKey } = keys.getNoteBlindingKeys(
        senderPub, receiverPub, random, senderRandom);
      out.blinding.push({
        senderPub: hx(senderPub), receiverPub: hx(receiverPub),
        random, senderRandom,
        blindedSenderViewingKey: hx(blindedSenderViewingKey),
        blindedReceiverViewingKey: hx(blindedReceiverViewingKey),
      });
    }
  }

  // --- AES-256-GCM (engine encrypts; Go must decrypt byte-exact) ---
  {
    const key = 'b8b0ee90e05cec44880f1af4d20506265f44684eb3b6a4327bcf811244dc0a7f';
    const blocks = [
      '6595f9a971c7471695948a445aedcbb9d624a325dbe68c228dea25eccf61919d',
      '0000000000000000000000007f4925cdf66ddf5b88016df1fe915e68eff8f192',
      '85b08a7cd73ee433072f1d410aeb4801000000000000000000000000e61ccb53',
    ];
    const ct = AES.encryptGCM(blocks, ByteUtils.hexStringToBytes(key));
    out.gcm.push({ key, blocks, iv: ByteUtils.hexlify(ct.iv), tag: ByteUtils.hexlify(ct.tag),
      data: ct.data.map((d) => ByteUtils.hexlify(d)) });
  }

  // --- Full transact note: engine builds the on-chain CommitmentCiphertext exactly
  //     as transaction.js does; Go must decrypt it to recover the note fields. ---
  {
    const random = '85b08a7cd73ee433072f1d410aeb4801'; // 16 bytes
    const value = '0000000000000000086aa1ade61ccb53';  // 16 bytes
    const tokenHash = '0000000000000000000000007f4925cdf66ddf5b88016df1fe915e68eff8f192';
    const receiverMPK = ByteUtils.hexToBigInt('3049bce13a3ba76cd96e5dc0287061ebf92df2fa3badf68d55d6a5dbc806a0f0');
    const senderMPK = ByteUtils.hexToBigInt('0aa1bce13a3ba76cd96e5dc0287061ebf92df2fa3badf68d55d6a5dbc8010203');
    const senderRandom = MEMO_SENDER_RANDOM_NULL; // address-visible mode

    // Encoded MPK exactly as the engine (getEncodedMasterPublicKey).
    const encodedMPK = TransactNote.getEncodedMasterPublicKey(senderRandom, receiverMPK, senderMPK);

    // Blinded keys (engine).
    const { blindedSenderViewingKey, blindedReceiverViewingKey } = keys.getNoteBlindingKeys(
      senderPub, receiverPub, random, senderRandom);
    // Shared key = sender view priv · blinded receiver key (engine), matches transaction.js.
    const sharedKey = await keys.getSharedSymmetricKey(senderSeedB, blindedReceiverViewingKey);

    // AES-GCM over the 4 V2 fields (engine), packed as transaction.js does.
    const ct = AES.encryptGCM(
      [ByteUtils.nToHex(encodedMPK, ByteUtils.ByteLength ? 32 : 32), tokenHash, `${random}${value}`, ''],
      sharedKey);
    const ivTag = ByteUtils.hexlify(`${ByteUtils.hexlify(ct.iv)}${ByteUtils.hexlify(ct.tag)}`);
    out.notes.push({
      senderSeed, receiverSeed, receiverPub: hx(receiverPub),
      senderMPK: senderMPK.toString(16), receiverMPK: receiverMPK.toString(16),
      random, value, tokenHash,
      ciphertext: [ivTag, ByteUtils.hexlify(ct.data[0]), ByteUtils.hexlify(ct.data[1]), ByteUtils.hexlify(ct.data[2])],
      memo: ByteUtils.hexlify(ct.data[3] || ''),
      blindedSenderViewingKey: hx(blindedSenderViewingKey),
      blindedReceiverViewingKey: hx(blindedReceiverViewingKey),
    });
  }

  process.stdout.write(JSON.stringify(out, null, 2));
}
main().catch((e) => { console.error(e); process.exit(1); });
