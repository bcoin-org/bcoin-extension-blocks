/*!
 * block.js - block object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var util = require('../utils/util');
var encoding = require('../utils/encoding');
var crypto = require('../crypto/crypto');
var consensus = require('../protocol/consensus');
var AbstractBlock = require('./abstractblock');
var VerifyResult = require('../protocol/errors').VerifyResult;
var BufferReader = require('../utils/reader');
var StaticWriter = require('../utils/staticwriter');
var TX = require('./tx');
var MerkleBlock = require('./merkleblock');
var Headers = require('./headers');
var Network = require('../protocol/network');

/**
 * Represents a full block.
 * @alias module:primitives.Block
 * @constructor
 * @extends AbstractBlock
 * @param {NakedBlock} options
 */

function Block(options) {
  if (!(this instanceof Block))
    return new Block(options);

  AbstractBlock.call(this);

  this.txs = [];
  this.ext = [];

  this._raw = null;
  this._base = -1;
  this._extension = -1;

  if (options)
    this.fromOptions(options);
}

util.inherits(Block, AbstractBlock);

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

Block.prototype.fromOptions = function fromOptions(options) {
  var i;

  this.parseOptions(options);

  if (options.txs) {
    assert(Array.isArray(options.txs));
    for (i = 0; i < options.txs.length; i++)
      this.addTX(options.txs[i]);
  }
};

/**
 * Instantiate block from options.
 * @param {Object} options
 * @returns {Block}
 */

Block.fromOptions = function fromOptions(options) {
  return new Block().fromOptions(options);
};

/**
 * Clear any cached values.
 * @param {Boolean?} all - Clear transactions.
 */

Block.prototype.refresh = function refresh(all) {
  this._raw = null;
  this._refresh(all);
};

/**
 * Serialize the block. Include witnesses if present.
 * @returns {Buffer}
 */

Block.prototype.toRaw = function toRaw() {
  return this.frame().data;
};

/**
 * Serialize the block, do not include witnesses.
 * @returns {Buffer}
 */

Block.prototype.toNormal = function toNormal() {
  if (this.hasExtension())
    return this.frameNormal().data;
  return this.toRaw();
};

/**
 * Serialize the block. Include witnesses if present.
 * @param {BufferWriter} bw
 */

Block.prototype.toWriter = function toWriter(bw) {
  var raw;

  if (this.mutable)
    return this.writeExtended(bw);

  raw = this.frame();
  bw.writeBytes(raw.data);

  return bw;
};

/**
 * Serialize the block, do not include witnesses.
 * @param {BufferWriter} bw
 */

Block.prototype.toNormalWriter = function toNormalWriter(bw) {
  if (this.hasExtension()) {
    this.writeNormal(bw);
    return bw;
  }
  return this.toWriter(bw);
};

/**
 * Get the raw block serialization.
 * Include witnesses if present.
 * @private
 * @returns {RawBlock}
 */

Block.prototype.frame = function frame() {
  var raw;

  if (this.mutable) {
    assert(!this._raw);
    return this.frameExtended();
  }

  if (this._raw) {
    assert(this._base > 0);
    assert(this._extension >= 0);
    raw = new RawBlock(this._base, this._extension);
    raw.data = this._raw;
    return raw;
  }

  raw = this.frameExtended();

  this._raw = raw.data;
  this._base = raw.base;
  this._extension = raw.extension;

  return raw;
};

/**
 * Calculate real size and size of the witness bytes.
 * @returns {Object} Contains `total` and `witness`.
 */

Block.prototype.getSizes = function getSizes() {
  if (this.mutable)
    return this.getExtendedSizes();
  return this.frame();
};

/**
 * Get real block size.
 * @returns {Number} size
 */

Block.prototype.getSize = function getSize() {
  var sizes = this.getSizes();
  return sizes.base + sizes.extension;
};

/**
 * Get base block size (without witness).
 * @returns {Number} size
 */

Block.prototype.getBaseSize = function getBaseSize() {
  var sizes = this.getSizes();
  return sizes.base;
};

/**
 * Get base block size (without witness).
 * @returns {Number} size
 */

Block.prototype.getExtensionSize = function getExtensionSize() {
  var sizes = this.getSizes();
  return sizes.extension;
};

/**
 * Test whether the block contains a
 * transaction with a non-empty witness.
 * @returns {Boolean}
 */

Block.prototype.hasWitness = function hasWitness() {
  var i, tx;

  for (i = 0; i < this.txs.length; i++) {
    tx = this.txs[i];
    if (tx.hasWitness())
      return true;
  }

  return false;
};

/**
 * Test whether the block contains a
 * transaction with a non-empty witness.
 * @returns {Boolean}
 */

Block.prototype.hasExtension = function hasExtension() {
  return this.ext.length > 0;
};

/**
 * Test whether the block has an entering output.
 * @returns {Boolean}
 */

Block.prototype.hasEntrance = function hasEntrance() {
  var i, j, tx, output;

  for (i = 0; i < this.txs.length; i++) {
    tx = this.txs[i];
    for (j = 0; j < tx.outputs.length; j++) {
      output = tx.outputs[j];
      if (output.script.isProgram())
        return true;
    }
  }

  return false;
};

/**
 * Add a transaction to the block's tx vector.
 * @param {TX} tx
 * @returns {Number}
 */

Block.prototype.addTX = function addTX(tx) {
  return this.txs.push(tx) - 1;
};

/**
 * Test the block's transaction vector against a hash.
 * @param {Hash} hash
 * @returns {Boolean}
 */

Block.prototype.hasTX = function hasTX(hash) {
  return this.indexOf(hash) !== -1;
};

/**
 * Find the index of a transaction in the block.
 * @param {Hash} hash
 * @returns {Number} index (-1 if not present).
 */

Block.prototype.indexOf = function indexOf(hash) {
  var i, tx;

  for (i = 0; i < this.txs.length; i++) {
    tx = this.txs[i];
    if (tx.hash('hex') === hash)
      return i;
  }

  return -1;
};

/**
 * Calculate merkle root. Returns null
 * if merkle tree has been malleated.
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Hash|null}
 */

Block.prototype.createMerkleRoot = function createMerkleRoot(enc) {
  var leaves = [];
  var i, tx, root;

  for (i = 0; i < this.txs.length; i++) {
    tx = this.txs[i];
    leaves.push(tx.hash());
  }

  root = crypto.createMerkleRoot(leaves);

  if (root.malleated)
    return null;

  return enc === 'hex'
    ? root.hash.toString('hex')
    : root.hash;
};

/**
 * Create a witness nonce (for mining).
 * @returns {Buffer}
 */

Block.prototype.createWitnessNonce = function createWitnessNonce() {
  return util.copy(encoding.ZERO_HASH);
};

/**
 * Calculate commitment hash (the root of the
 * witness merkle tree hashed with the witnessNonce).
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Hash}
 */

Block.prototype.createCommitmentHash = function createCommitmentHash(enc) {
  var leaves = [];
  var i, tx, root, hash;

  for (i = 0; i < this.ext.length; i++) {
    tx = this.ext[i];
    leaves.push(tx.hash());
  }

  for (i = 0; i < this.ext.length; i++) {
    tx = this.ext[i];
    leaves.push(tx.witnessHash());
  }

  root = crypto.createMerkleRoot(leaves);

  // Note: malleation check ignored here.
  // assert(!root.malleated);

  hash = root.hash;

  return enc === 'hex'
    ? hash.toString('hex')
    : hash;
};

/**
 * Retrieve the merkle root from the block header.
 * @param {String?} enc
 * @returns {Hash}
 */

Block.prototype.getMerkleRoot = function getMerkleRoot(enc) {
  if (enc === 'hex')
    return this.merkleRoot;
  return new Buffer(this.merkleRoot, 'hex');
};

/**
 * Retrieve the witness nonce from the
 * coinbase's witness vector (if present).
 * @returns {Buffer|null}
 */

Block.prototype.getWitnessNonce = function getWitnessNonce() {
  var coinbase, input;

  if (this.ext.length === 0)
    return null;

  coinbase = this.ext[0];

  if (coinbase.inputs.length !== 1)
    return null;

  input = coinbase.inputs[0];

  if (input.witness.items.length !== 1)
    return null;

  if (input.witness.items[0].length !== 32)
    return null;

  return input.witness.items[0];
};

/**
 * Retrieve the commitment hash
 * from the coinbase's outputs.
 * @param {String?} enc
 * @returns {Hash|null}
 */

Block.prototype.getCommitmentHash = function getCommitmentHash(enc) {
  var i, coinbase, hash, output;

  if (this.txs.length === 0)
    return null;

  coinbase = this.txs[0];

  for (i = coinbase.outputs.length - 1; i >= 0; i--) {
    output = coinbase.outputs[i];
    if (output.script.isCommitment()) {
      hash = output.script.getCommitmentHash();
      break;
    }
  }

  if (!hash)
    return null;

  return enc === 'hex'
    ? hash.toString('hex')
    : hash;
};

/**
 * Do non-contextual verification on the block. Including checking the block
 * size, the coinbase and the merkle root. This is consensus-critical.
 * @alias Block#verify
 * @param {Object?} ret - Return object, may be
 * set with properties `reason` and `score`.
 * @returns {Boolean}
 */

Block.prototype.verifyBody = function verifyBody(ret) {
  var sigops = 0;
  var scale = consensus.WITNESS_SCALE_FACTOR;
  var i, tx, merkle;

  if (!ret)
    ret = new VerifyResult();

  // Check merkle root.
  merkle = this.createMerkleRoot('hex');

  // If the merkle is mutated,
  // we have duplicate txs.
  if (!merkle) {
    ret.reason = 'bad-txns-duplicate';
    ret.score = 100;
    return false;
  }

  if (this.merkleRoot !== merkle) {
    ret.reason = 'bad-txnmrklroot';
    ret.score = 100;
    return false;
  }

  // Check base size.
  if (this.txs.length === 0
      || this.txs.length > consensus.MAX_BLOCK_SIZE
      || this.getBaseSize() > consensus.MAX_BLOCK_SIZE) {
    ret.reason = 'bad-blk-length';
    ret.score = 100;
    return false;
  }

  // First TX must be a coinbase.
  if (this.txs.length === 0 || !this.txs[0].isCoinbase()) {
    ret.reason = 'bad-cb-missing';
    ret.score = 100;
    return false;
  }

  // Test all transactions.
  for (i = 0; i < this.txs.length; i++) {
    tx = this.txs[i];

    // The rest of the txs must not be coinbases.
    if (i > 0 && tx.isCoinbase()) {
      ret.reason = 'bad-cb-multiple';
      ret.score = 100;
      return false;
    }

    // Sanity checks.
    if (!tx.isSane(ret))
      return false;

    // Count legacy sigops (do not count scripthash or witness).
    sigops += tx.getLegacySigops();
    if (sigops * scale > consensus.MAX_BLOCK_SIGOPS_COST) {
      ret.reason = 'bad-blk-sigops';
      ret.score = 100;
      return false;
    }

    // Witness vectors cannot be
    // present in the canonical block.
    if (tx.hasWitness()) {
      ret.reason = 'unexpected-witness';
      ret.score = 100;
      return false;
    }
  }

  // Test all transactions.
  for (i = 0; i < this.ext.length; i++) {
    tx = this.ext[i];

    // Extension txs must not be coinbases.
    if (tx.isCoinbase()) {
      ret.reason = 'bad-cb-multiple';
      ret.score = 100;
      return false;
    }

    // Sanity checks.
    if (!tx.isSane(ret))
      return false;
  }

  return true;
};

/**
 * Retrieve the coinbase height from the coinbase input script.
 * @returns {Number} height (-1 if not present).
 */

Block.prototype.getCoinbaseHeight = function getCoinbaseHeight() {
  var coinbase;

  if (this.version < 2)
    return -1;

  if (this.txs.length === 0)
    return -1;

  coinbase = this.txs[0];

  if (coinbase.inputs.length === 0)
    return -1;

  return coinbase.inputs[0].script.getCoinbaseHeight();
};

/**
 * Get the "claimed" reward by the coinbase.
 * @returns {Amount} claimed
 */

Block.prototype.getClaimed = function getClaimed() {
  assert(this.txs.length > 0);
  assert(this.txs[0].isCoinbase());
  return this.txs[0].getOutputValue();
};

/**
 * Get all unique outpoint hashes in the
 * block. Coinbases are ignored.
 * @returns {Hash[]} Outpoint hashes.
 */

Block.prototype.getPrevout = function getPrevout() {
  var prevout = {};
  var i, j, tx, input;

  for (i = 1; i < this.txs.length; i++) {
    tx = this.txs[i];

    for (j = 0; j < tx.inputs.length; j++) {
      input = tx.inputs[j];
      prevout[input.prevout.hash] = true;
    }
  }

  return Object.keys(prevout);
};

/**
 * Inspect the block and return a more
 * user-friendly representation of the data.
 * @returns {Object}
 */

Block.prototype.inspect = function inspect() {
  return this.format();
};

/**
 * Inspect the block and return a more
 * user-friendly representation of the data.
 * @param {CoinView} view
 * @param {Number} height
 * @returns {Object}
 */

Block.prototype.format = function format(view, height) {
  var commitmentHash = this.getCommitmentHash('hex');
  return {
    hash: this.rhash(),
    height: height != null ? height : -1,
    size: this.getSize(),
    date: util.date(this.ts),
    version: util.hex32(this.version),
    prevBlock: util.revHex(this.prevBlock),
    merkleRoot: util.revHex(this.merkleRoot),
    commitmentHash: commitmentHash
      ? util.revHex(commitmentHash)
      : null,
    ts: this.ts,
    bits: this.bits,
    nonce: this.nonce,
    txs: this.txs.map(function(tx, i) {
      return tx.format(view, null, i);
    }, this),
    ext: this.ext.map(function(tx, i) {
      return tx.format(view, null, i);
    }, this)
  };
};

/**
 * Convert the block to an object suitable
 * for JSON serialization.
 * @returns {Object}
 */

Block.prototype.toJSON = function toJSON() {
  return this.getJSON();
};

/**
 * Convert the block to an object suitable
 * for JSON serialization. Note that the hashes
 * will be reversed to abide by bitcoind's legacy
 * of little-endian uint256s.
 * @param {Network} network
 * @param {CoinView} view
 * @param {Number} height
 * @returns {Object}
 */

Block.prototype.getJSON = function getJSON(network, view, height) {
  network = Network.get(network);
  return {
    hash: this.rhash(),
    height: height,
    version: this.version,
    prevBlock: util.revHex(this.prevBlock),
    merkleRoot: util.revHex(this.merkleRoot),
    ts: this.ts,
    bits: this.bits,
    nonce: this.nonce,
    txs: this.txs.map(function(tx, i) {
      return tx.getJSON(network, view, null, i);
    }, this),
    ext: this.ext.map(function(tx, i) {
      return tx.getJSON(network, view, null, i);
    }, this)
  };
};

/**
 * Inject properties from json object.
 * @private
 * @param {Object} json
 */

Block.prototype.fromJSON = function fromJSON(json) {
  var i;

  assert(json, 'Block data is required.');
  assert(Array.isArray(json.txs));

  this.parseJSON(json);

  for (i = 0; i < json.txs.length; i++)
    this.txs.push(TX.fromJSON(json.txs[i]));

  for (i = 0; i < json.ext.length; i++)
    this.ext.push(TX.fromJSON(json.ext[i]));

  return this;
};

/**
 * Instantiate a block from a jsonified block object.
 * @param {Object} json - The jsonified block object.
 * @returns {Block}
 */

Block.fromJSON = function fromJSON(json) {
  return new Block().fromJSON(json);
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

Block.prototype.fromReader = function fromReader(br, extended) {
  var base = 0;
  var extension = 0;
  var i, count, tx;

  br.start();
  br.start();

  this.parseAbbr(br);

  count = br.readVarint();

  for (i = 0; i < count; i++) {
    tx = TX.fromReader(br);
    this.txs.push(tx);
  }

  base = br.end();

  if (extension) {
    br.start();
    count = br.readVarint();

    for (i = 0; i < count; i++) {
      tx = TX.fromReader(br);
      this.ext.push(tx);
    }

    extension = br.end();
  }

  if (!this.mutable) {
    this._raw = br.endData();
    this._base = base;
    this._extension = extension;
  }

  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

Block.prototype.fromRaw = function fromRaw(data, extended) {
  return this.fromReader(new BufferReader(data), extended);
};

/**
 * Instantiate a block from a serialized Buffer.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Block}
 */

Block.fromReader = function fromReader(data) {
  return new Block().fromReader(data);
};

/**
 * Instantiate a block from a serialized Buffer.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Block}
 */

Block.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = new Buffer(data, enc);
  return new Block().fromRaw(data);
};

/**
 * Convert the Block to a MerkleBlock.
 * @param {Bloom} filter - Bloom filter for transactions
 * to match. The merkle block will contain only the
 * matched transactions.
 * @returns {MerkleBlock}
 */

Block.prototype.toMerkle = function toMerkle(filter) {
  return MerkleBlock.fromBlock(this, filter);
};

/**
 * Serialze block with or without witness data.
 * @private
 * @param {Boolean} witness
 * @param {BufferWriter?} writer
 * @returns {Buffer}
 */

Block.prototype.writeNormal = function writeNormal(bw) {
  var i, tx;

  this.writeAbbr(bw);

  bw.writeVarint(this.txs.length);

  for (i = 0; i < this.txs.length; i++) {
    tx = this.txs[i];
    tx.toNormalWriter(bw);
  }

  return bw;
};

/**
 * Serialze block with or without witness data.
 * @private
 * @param {Boolean} witness
 * @param {BufferWriter?} writer
 * @returns {Buffer}
 */

Block.prototype.writeExtended = function writeExtended(bw) {
  var i, tx;

  this.writeNormal(bw);

  bw.writeVarint(this.ext.length);

  for (i = 0; i < this.ext.length; i++) {
    tx = this.ext[i];
    tx.toWriter(bw);
  }

  return bw;
};

/**
 * Serialze block with or without witness data.
 * @private
 * @param {Boolean} witness
 * @param {BufferWriter?} writer
 * @returns {Buffer}
 */

Block.prototype.frameNormal = function frameNormal() {
  var sizes = this.getNormalSizes();
  var bw = new StaticWriter(sizes.base);
  this.writeNormal(bw);
  sizes.data = bw.render();
  return sizes;
};

/**
 * Serialze block without witness data.
 * @private
 * @param {BufferWriter?} writer
 * @returns {Buffer}
 */

Block.prototype.frameExtended = function frameExtended() {
  var sizes = this.getExtendedSizes();
  var bw = new StaticWriter(sizes.base + sizes.extension);
  this.writeExtended(bw);
  sizes.data = bw.render();
  return sizes;
};

/**
 * Convert the block to a headers object.
 * @returns {Headers}
 */

Block.prototype.toHeaders = function toHeaders() {
  return Headers.fromBlock(this);
};

/**
 * Get real block size without witness.
 * @returns {RawBlock}
 */

Block.prototype.getNormalSizes = function getNormalSizes() {
  var size = 0;
  var i, tx;

  size += 80;
  size += encoding.sizeVarint(this.txs.length);

  for (i = 0; i < this.txs.length; i++) {
    tx = this.txs[i];
    size += tx.getSize();
  }

  return new RawBlock(size, 0);
};

/**
 * Get real block size with witness.
 * @returns {RawBlock}
 */

Block.prototype.getExtendedSizes = function getExtendedSizes() {
  var size = 0;
  var extension = 0;
  var i, tx;

  size += 80;
  size += encoding.sizeVarint(this.txs.length);

  for (i = 0; i < this.txs.length; i++) {
    tx = this.txs[i];
    size += tx.getSize();
  }

  extension += encoding.sizeVarint(this.ext.length);

  for (i = 0; i < this.ext.length; i++) {
    tx = this.ext[i];
    extension += tx.getSize();
  }

  return new RawBlock(size, extension);
};

/**
 * Test whether an object is a Block.
 * @param {Object} obj
 * @returns {Boolean}
 */

Block.isBlock = function isBlock(obj) {
  return obj
    && typeof obj.merkleRoot === 'string'
    && typeof obj.getClaimed === 'function';
};

/*
 * Helpers
 */

function RawBlock(base, extension) {
  this.data = null;
  this.base = base;
  this.extension = extension;
}

/*
 * Expose
 */

module.exports = Block;
