/*!
 * bip152.js - compact block object for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module net/bip152
 */

var assert = require('assert');
var util = require('../utils/util');
var BufferReader = require('../utils/reader');
var BufferWriter = require('../utils/writer');
var StaticWriter = require('../utils/staticwriter');
var encoding = require('../utils/encoding');
var consensus = require('../protocol/consensus');
var crypto = require('../crypto/crypto');
var siphash = require('../crypto/siphash');
var AbstractBlock = require('../primitives/abstractblock');
var TX = require('../primitives/tx');
var Headers = require('../primitives/headers');
var Block = require('../primitives/block');

/**
 * Represents a compact block (bip152): `cmpctblock` packet.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki
 * @constructor
 * @extends AbstractBlock
 * @param {Object} options
 * @property {Buffer|null} keyNonce - Nonce for siphash key.
 * @property {Number[]} ids - Short IDs.
 * @property {Object[]} ptx - Prefilled transactions.
 * @property {TX[]} available - Available transaction vector.
 * @property {Object} idMap - Map of short ids to indexes.
 * @property {Number} count - Transactions resolved.
 * @property {Buffer|null} sipKey - Siphash key.
 */

function CompactBlock(options) {
  if (!(this instanceof CompactBlock))
    return new CompactBlock(options);

  AbstractBlock.call(this);

  this.keyNonce = null;
  this.ids = [];
  this.ptx = [];

  this.available = [];
  this.idMap = {};
  this.count = 0;
  this.sipKey = null;
  this.totalTX = 0;
  this.now = 0;

  this.extids = [];
  this.extptx = [];
  this.extAvailable = [];
  this.extIDMap = {};
  this.extCount = 0;
  this.extTotalTX = 0;

  if (options)
    this.fromOptions(options);
}

util.inherits(CompactBlock, AbstractBlock);

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

CompactBlock.prototype.fromOptions = function fromOptions(options) {
  this.parseOptions(options);

  assert(Buffer.isBuffer(options.keyNonce));
  assert(Array.isArray(options.ids));
  assert(Array.isArray(options.ptx));

  this.keyNonce = options.keyNonce;
  this.ids = options.ids;
  this.ptx = options.ptx;

  if (options.available)
    this.available = options.available;

  if (options.idMap)
    this.idMap = options.idMap;

  if (options.count)
    this.count = options.count;

  if (options.totalTX != null)
    this.totalTX = options.totalTX;

  this.sipKey = options.sipKey;

  this.extids = options.extids;
  this.extptx = options.extptx;

  if (options.extAvailable)
    this.extAvailable = options.extAvailable;

  if (options.extIDMap)
    this.extIDMap = options.extIDMap;

  if (options.extCount)
    this.extCount = options.extCount;

  if (options.extTotalTX != null)
    this.extTotalTX = options.extTotalTX;

  this.initKey();

  return this;
};

/**
 * Instantiate compact block from options.
 * @param {Object} options
 * @returns {CompactBlock}
 */

CompactBlock.fromOptions = function fromOptions(options) {
  return new CompactBlock().fromOptions(options);
};

/**
 * Verify the block.
 * @param {Object?} ret - Return object, may be
 * set with properties `reason` and `score`.
 * @returns {Boolean}
 */

CompactBlock.prototype.verifyBody = function verifyBody(ret) {
  return true;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

CompactBlock.prototype.fromRaw = function fromRaw(data) {
  var br = new BufferReader(data);
  var i, count, index, tx;

  this.version = br.readU32();
  this.prevBlock = br.readHash('hex');
  this.merkleRoot = br.readHash('hex');
  this.ts = br.readU32();
  this.bits = br.readU32();
  this.nonce = br.readU32();

  this.keyNonce = br.readBytes(8);

  this.initKey();

  count = br.readVarint();

  this.totalTX += count;

  for (i = 0; i < count; i++)
    this.ids.push(br.readU32() + br.readU16() * 0x100000000);

  count = br.readVarint();

  this.totalTX += count;

  for (i = 0; i < count; i++) {
    index = br.readVarint();
    assert(index <= 0xffff);
    assert(index < this.totalTX);
    tx = TX.fromReader(br);
    this.ptx.push(new PrefilledTX(index, tx));
  }

  if (br.left() > 0) {
    count = br.readVarint();

    this.extTotalTX += count;

    for (i = 0; i < count; i++)
      this.extids.push(br.readU32() + br.readU16() * 0x100000000);

    count = br.readVarint();

    this.extTotalTX += count;

    for (i = 0; i < count; i++) {
      index = br.readVarint();
      assert(index <= 0xffff);
      assert(index < this.totalTX);
      tx = TX.fromReader(br);
      this.extptx.push(new PrefilledTX(index, tx));
    }
  }

  return this;
};

/**
 * Instantiate a block from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {CompactBlock}
 */

CompactBlock.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = new Buffer(data, enc);
  return new CompactBlock().fromRaw(data);
};

/**
 * Serialize compact block with extension data.
 * @returns {Buffer}
 */

CompactBlock.prototype.toRaw = function toRaw() {
  return this.frameRaw(true);
};

/**
 * Serialize compact block without extension data.
 * @returns {Buffer}
 */

CompactBlock.prototype.toNormal = function toNormal() {
  return this.frameRaw(false);
};

/**
 * Write serialized block to a buffer
 * writer (includes extension data).
 * @param {BufferWriter} bw
 */

CompactBlock.prototype.toWriter = function toWriter(bw) {
  return this.writeRaw(bw, true);
};

/**
 * Write serialized block to a buffer
 * writer (excludes extension data).
 * @param {BufferWriter} bw
 */

CompactBlock.prototype.toNormalWriter = function toNormalWriter(bw) {
  return this.writeRaw(bw, false);
};

/**
 * Serialize compact block.
 * @private
 * @param {Boolean} extension
 * @returns {Buffer}
 */

CompactBlock.prototype.frameRaw = function frameRaw(extension) {
  var size = this.getSize(extension);
  return this.writeRaw(new StaticWriter(size), extension).render();
};

/**
 * Calculate block serialization size.
 * @param {Boolean} extension
 * @returns {Number}
 */

CompactBlock.prototype.getSize = function getSize(extension) {
  var size = 0;
  var i, ptx;

  size += 80;
  size += 8;
  size += encoding.sizeVarint(this.ids.length);
  size += this.ids.length * 6;
  size += encoding.sizeVarint(this.ptx.length);

  for (i = 0; i < this.ptx.length; i++) {
    ptx = this.ptx[i];
    size += encoding.sizeVarint(ptx.index);
    size += ptx.tx.getSize();
  }

  if (extension) {
    size += encoding.sizeVarint(this.extids.length);
    size += this.extids.length * 6;
    size += encoding.sizeVarint(this.extptx.length);

    for (i = 0; i < this.extptx.length; i++) {
      ptx = this.extptx[i];
      size += encoding.sizeVarint(ptx.index);
      size += ptx.tx.getSize();
    }
  }

  return size;
};

/**
 * Serialize block to buffer writer.
 * @private
 * @param {BufferWriter} bw
 * @param {Boolean} extension
 */

CompactBlock.prototype.writeRaw = function writeRaw(bw, extension) {
  var i, id, lo, hi, ptx;

  this.writeAbbr(bw);

  bw.writeBytes(this.keyNonce);

  bw.writeVarint(this.ids.length);

  for (i = 0; i < this.ids.length; i++) {
    id = this.ids[i];
    lo = id % 0x100000000;
    hi = (id - lo) / 0x100000000;
    hi &= 0xffff;
    bw.writeU32(lo);
    bw.writeU16(hi);
  }

  bw.writeVarint(this.ptx.length);

  for (i = 0; i < this.ptx.length; i++) {
    ptx = this.ptx[i];
    bw.writeVarint(ptx.index);
    ptx.tx.toWriter(bw);
  }

  if (extension) {
    bw.writeVarint(this.extids.length);

    for (i = 0; i < this.extids.length; i++) {
      id = this.extids[i];
      lo = id % 0x100000000;
      hi = (id - lo) / 0x100000000;
      hi &= 0xffff;
      bw.writeU32(lo);
      bw.writeU16(hi);
    }

    bw.writeVarint(this.extptx.length);

    for (i = 0; i < this.extptx.length; i++) {
      ptx = this.extptx[i];
      bw.writeVarint(ptx.index);
      ptx.tx.toWriter(bw);
    }
  }

  return bw;
};

/**
 * Convert block to a TXRequest
 * containing missing indexes.
 * @returns {TXRequest}
 */

CompactBlock.prototype.toRequest = function toRequest() {
  return TXRequest.fromCompact(this);
};

/**
 * Attempt to fill missing transactions from mempool.
 * @param {Boolean} extension
 * @param {Mempool} mempool
 * @returns {Boolean}
 */

CompactBlock.prototype.fillMempool = function fillMempool(extension, mempool) {
  var have = {};
  var i, id, index, hash, tx, hashes;

  if (this.count === this.totalTX
      && this.extCount === this.extTotalTX) {
    return true;
  }

  hashes = mempool.getSnapshot();

  if (this.count !== this.totalTX) {
    for (i = 0; i < hashes.length; i++) {
      hash = hashes[i];
      tx = mempool.getTX(hash);
      assert(tx);
      hash = tx.hash();

      id = this.sid(hash);
      index = this.idMap[id];

      if (index == null)
        continue;

      if (have[index]) {
        // Siphash collision, just request it.
        this.available[index] = null;
        this.count--;
        continue;
      }

      this.available[index] = tx;
      have[index] = true;
      this.count++;

      // We actually may have a siphash collision
      // here, but exit early anyway for perf.
      if (this.count === this.totalTX)
        break;
    }
  }

  if (this.extCount !== this.extTotalTX) {
    for (i = 0; i < hashes.length; i++) {
      hash = hashes[i];
      tx = mempool.getTX(hash);
      assert(tx);
      hash = tx.witnessHash();

      id = this.sid(hash);
      index = this.idMap[id];

      if (index == null)
        continue;

      if (have[index]) {
        // Siphash collision, just request it.
        this.extAvailable[index] = null;
        this.extCount--;
        continue;
      }

      this.extAvailable[index] = tx;
      have[index] = true;
      this.extCount++;

      // We actually may have a siphash collision
      // here, but exit early anyway for perf.
      if (this.extCount === this.extTotalTX)
        break;
    }
  }

  if (this.count === this.totalTX
      && this.extCount === this.extTotalTX) {
    return true;
  }

  return false;
};

/**
 * Attempt to fill missing transactions from TXResponse.
 * @param {TXResponse} res
 * @returns {Boolean}
 */

CompactBlock.prototype.fillMissing = function fillMissing(res) {
  var offset = 0;
  var i;

  for (i = 0; i < this.available.length; i++) {
    if (this.available[i])
      continue;

    if (offset >= res.txs.length)
      return false;

    this.available[i] = res.txs[offset++];
  }

  if (offset !== res.txs.length)
    return false;

  offset = 0;

  for (i = 0; i < this.extAvailable.length; i++) {
    if (this.extAvailable[i])
      continue;

    if (offset >= res.ext.length)
      return false;

    this.extAvailable[i] = res.ext[offset++];
  }

  if (offset !== res.ext.length)
    return false;

  return true;
};

/**
 * Calculate a transaction short ID.
 * @param {Hash} hash
 * @returns {Number}
 */

CompactBlock.prototype.sid = function sid(hash) {
  var lo, hi;

  if (typeof hash === 'string')
    hash = new Buffer(hash, 'hex');

  hash = siphash(hash, this.sipKey);

  lo = hash.readUInt32LE(0, true);
  hi = hash.readUInt16LE(4, true);

  return hi * 0x100000000 + lo;
};

/**
 * Initialize the siphash key.
 * @private
 */

CompactBlock.prototype.initKey = function initKey() {
  var data = util.concat(this.abbr(), this.keyNonce);
  var hash = crypto.sha256(data);
  this.sipKey = hash.slice(0, 16);
};

/**
 * Initialize compact block and short id map.
 * @private
 */

CompactBlock.prototype.init = function init() {
  var i, last, ptx, offset, id;

  if (this.totalTX === 0)
    throw new Error('Empty vectors.');

  if (this.totalTX > consensus.MAX_BLOCK_SIZE / 10)
    throw new Error('Compact block too big.');

  if (this.extTotalTX > consensus.MAX_EXTENSION_SIZE / 10)
    throw new Error('Compact block extension too big.');

  // No sparse arrays here, v8.
  for (i = 0; i < this.totalTX; i++)
    this.available.push(null);

  last = -1;

  for (i = 0; i < this.ptx.length; i++) {
    ptx = this.ptx[i];
    assert(ptx);
    last += ptx.index + 1;
    assert(last <= 0xffff);
    assert(last <= this.ids.length + i);
    this.available[last] = ptx.tx;
    this.count++;
  }

  offset = 0;

  for (i = 0; i < this.ids.length; i++) {
    while (this.available[i + offset])
      offset++;

    id = this.ids[i];

    // Fails on siphash collision
    if (this.idMap[id])
      return false;

    this.idMap[id] = i + offset;

    // We're supposed to fail here if there's
    // more than 12 hash collisions, but we
    // don't have lowlevel access to our hash
    // table. Hopefully we don't get hashdos'd.
  }

  // No sparse arrays here, v8.
  for (i = 0; i < this.extTotalTX; i++)
    this.extAvailable.push(null);

  last = -1;

  for (i = 0; i < this.extptx.length; i++) {
    ptx = this.extptx[i];
    assert(ptx);
    last += ptx.index + 1;
    assert(last <= 0xffff);
    assert(last <= this.extids.length + i);
    this.extAvailable[last] = ptx.tx;
    this.extCount++;
  }

  offset = 0;

  for (i = 0; i < this.extids.length; i++) {
    while (this.extAvailable[i + offset])
      offset++;

    id = this.extids[i];

    // Fails on siphash collision
    if (this.extIdMap[id])
      return false;

    this.extIdMap[id] = i + offset;
  }

  return true;
};

/**
 * Convert completely filled compact
 * block to a regular block.
 * @returns {Block}
 */

CompactBlock.prototype.toBlock = function toBlock() {
  var block = new Block();
  var i, tx;

  block.version = this.version;
  block.prevBlock = this.prevBlock;
  block.merkleRoot = this.merkleRoot;
  block.ts = this.ts;
  block.bits = this.bits;
  block.nonce = this.nonce;
  block._hash = this._hash;
  block._hhash = this._hhash;

  for (i = 0; i < this.available.length; i++) {
    tx = this.available[i];
    assert(tx, 'Compact block is not full.');
    block.txs.push(tx);
  }

  for (i = 0; i < this.extAvailable.length; i++) {
    tx = this.extAvailable[i];
    assert(tx, 'Compact block is not full.');
    block.ext.push(tx);
  }

  return block;
};

/**
 * Inject properties from block.
 * @private
 * @param {Block} block
 * @param {Boolean} extension
 * @param {Buffer?} nonce
 * @returns {CompactBlock}
 */

CompactBlock.prototype.fromBlock = function fromBlock(block, extension, nonce) {
  var i, tx, hash, id, index;

  this.version = block.version;
  this.prevBlock = block.prevBlock;
  this.merkleRoot = block.merkleRoot;
  this.ts = block.ts;
  this.bits = block.bits;
  this.nonce = block.nonce;
  this.totalTX = block.txs.length;
  this._hash = block._hash;
  this._hhash = block._hhash;

  if (!nonce)
    nonce = util.nonce();

  this.keyNonce = nonce;

  this.initKey();

  for (i = 1; i < block.txs.length; i++) {
    tx = block.txs[i];
    hash = tx.hash();
    id = this.sid(hash);
    this.ids.push(id);
  }

  this.ptx.push(new PrefilledTX(0, block.txs[0]));

  // Push resolution onto ptx.
  if (block.getCommitmentHash()) {
    index = block.txs.length - 1;
    this.ptx.push(new PrefilledTX(index, block.txs[index]));
  }

  if (extension) {
    for (i = 0; i < block.ext.length; i++) {
      tx = block.ext[i];
      hash = tx.witnessHash();
      id = this.sid(hash);
      this.extids.push(id);
    }
  }

  return this;
};

/**
 * Instantiate compact block from a block.
 * @param {Block} block
 * @param {Boolean} extension
 * @param {Buffer?} nonce
 * @returns {CompactBlock}
 */

CompactBlock.fromBlock = function fromBlock(block, extension, nonce) {
  return new CompactBlock().fromBlock(block, extension, nonce);
};

/**
 * Convert block to headers.
 * @returns {Headers}
 */

CompactBlock.prototype.toHeaders = function toHeaders() {
  return Headers.fromBlock(this);
};

/**
 * Represents a BlockTransactionsRequest (bip152): `getblocktxn` packet.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki
 * @constructor
 * @param {Object} options
 * @property {Hash} hash
 * @property {Number[]} indexes
 */

function TXRequest(options) {
  if (!(this instanceof TXRequest))
    return new TXRequest(options);

  this.hash = null;
  this.indexes = [];
  this.extIndexes = [];

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options.
 * @private
 * @param {Object} options
 * @returns {TXRequest}
 */

TXRequest.prototype.fromOptions = function fromOptions(options) {
  this.hash = options.hash;

  if (options.indexes)
    this.indexes = options.indexes;

  return this;
};

/**
 * Instantiate request from options.
 * @param {Object} options
 * @returns {TXRequest}
 */

TXRequest.fromOptions = function fromOptions(options) {
  return new TXRequest().fromOptions(options);
};

/**
 * Inject properties from compact block.
 * @private
 * @param {CompactBlock} block
 * @returns {TXRequest}
 */

TXRequest.prototype.fromCompact = function fromCompact(block) {
  var i;

  this.hash = block.hash('hex');

  for (i = 0; i < block.available.length; i++) {
    if (!block.available[i])
      this.indexes.push(i);
  }

  for (i = 0; i < block.extAvailable.length; i++) {
    if (!block.extAvailable[i])
      this.extIndexes.push(i);
  }

  return this;
};

/**
 * Instantiate request from compact block.
 * @param {CompactBlock} block
 * @returns {TXRequest}
 */

TXRequest.fromCompact = function fromCompact(block) {
  return new TXRequest().fromCompact(block);
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 * @returns {TXRequest}
 */

TXRequest.prototype.fromReader = function fromReader(br) {
  var i, count, index, offset;

  this.hash = br.readHash('hex');

  count = br.readVarint();

  for (i = 0; i < count; i++) {
    index = br.readVarint();
    assert(index <= 0xffff);
    this.indexes.push(index);
  }

  offset = 0;

  for (i = 0; i < count; i++) {
    index = this.indexes[i];
    index += offset;
    assert(index <= 0xffff);
    this.indexes[i] = index;
    offset = index + 1;
  }

  if (br.left() > 0) {
    count = br.readVarint();

    for (i = 0; i < count; i++) {
      index = br.readVarint();
      assert(index <= 0xffff);
      this.extIndexes.push(index);
    }

    offset = 0;

    for (i = 0; i < count; i++) {
      index = this.extIndexes[i];
      index += offset;
      assert(index <= 0xffff);
      this.extIndexes[i] = index;
      offset = index + 1;
    }
  }

  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 * @returns {TXRequest}
 */

TXRequest.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Instantiate request from buffer reader.
 * @param {BufferReader} br
 * @returns {TXRequest}
 */

TXRequest.fromReader = function fromReader(br) {
  return new TXRequest().fromReader(br);
};

/**
 * Instantiate request from serialized data.
 * @param {Buffer} data
 * @returns {TXRequest}
 */

TXRequest.fromRaw = function fromRaw(data) {
  return new TXRequest().fromRaw(data);
};

/**
 * Calculate request serialization size.
 * @returns {Number}
 */

TXRequest.prototype.getSize = function getSize() {
  var size = 0;
  var i, index;

  size += 32;
  size += encoding.sizeVarint(this.indexes.length);

  for (i = 0; i < this.indexes.length; i++) {
    index = this.indexes[i] - (i === 0 ? 0 : this.indexes[i - 1] + 1);
    size += encoding.sizeVarint(index);
  }

  size += encoding.sizeVarint(this.extIndexes.length);

  for (i = 0; i < this.extIndexes.length; i++) {
    index = this.extIndexes[i] - (i === 0 ? 0 : this.extIndexes[i - 1] + 1);
    size += encoding.sizeVarint(index);
  }

  return size;
};

/**
 * Write serialized request to buffer writer.
 * @param {BufferWriter} bw
 */

TXRequest.prototype.toWriter = function toWriter(bw) {
  var i, index;

  bw.writeHash(this.hash);

  bw.writeVarint(this.indexes.length);

  for (i = 0; i < this.indexes.length; i++) {
    index = this.indexes[i] - (i === 0 ? 0 : this.indexes[i - 1] + 1);
    bw.writeVarint(index);
  }

  bw.writeVarint(this.extIndexes.length);

  for (i = 0; i < this.extIndexes.length; i++) {
    index = this.extIndexes[i] - (i === 0 ? 0 : this.extIndexes[i - 1] + 1);
    bw.writeVarint(index);
  }

  return bw;
};

/**
 * Serialize request.
 * @returns {Buffer}
 */

TXRequest.prototype.toRaw = function toRaw() {
  return this.toWriter(new BufferWriter()).render();
};

/**
 * Represents BlockTransactions (bip152): `blocktxn` packet.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki
 * @constructor
 * @param {Object} options
 * @property {Hash} hash
 * @property {TX[]} txs
 */

function TXResponse(options) {
  if (!(this instanceof TXResponse))
    return new TXResponse(options);

  this.hash = null;
  this.txs = [];
  this.ext = [];

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options.
 * @private
 * @param {Object} options
 * @returns {TXResponse}
 */

TXResponse.prototype.fromOptions = function fromOptions(options) {
  this.hash = options.hash;

  if (options.txs)
    this.txs = options.txs;

  if (options.ext)
    this.ext = options.ext;

  return this;
};

/**
 * Instantiate response from options.
 * @param {Object} options
 * @returns {TXResponse}
 */

TXResponse.fromOptions = function fromOptions(options) {
  return new TXResponse().fromOptions(options);
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 * @returns {TXResponse}
 */

TXResponse.prototype.fromReader = function fromReader(br) {
  var i, count;

  this.hash = br.readHash('hex');

  count = br.readVarint();

  for (i = 0; i < count; i++)
    this.txs.push(TX.fromReader(br));

  if (br.left() > 0) {
    count = br.readVarint();

    for (i = 0; i < count; i++)
      this.ext.push(TX.fromReader(br));
  }

  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 * @returns {TXResponse}
 */

TXResponse.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Instantiate response from buffer reader.
 * @param {BufferReader} br
 * @returns {TXResponse}
 */

TXResponse.fromReader = function fromReader(br) {
  return new TXResponse().fromReader(br);
};

/**
 * Instantiate response from serialized data.
 * @param {Buffer} data
 * @returns {TXResponse}
 */

TXResponse.fromRaw = function fromRaw(data) {
  return new TXResponse().fromRaw(data);
};

/**
 * Inject properties from block.
 * @private
 * @param {Block} block
 * @returns {TXResponse}
 */

TXResponse.prototype.fromBlock = function fromBlock(block, req) {
  var i, index;

  this.hash = req.hash;

  for (i = 0; i < req.indexes.length; i++) {
    index = req.indexes[i];

    if (index >= block.txs.length)
      break;

    this.txs.push(block.txs[index]);
  }

  for (i = 0; i < req.extIndexes.length; i++) {
    index = req.extIndexes[i];

    if (index >= block.ext.length)
      break;

    this.ext.push(block.ext[index]);
  }

  return this;
};

/**
 * Instantiate response from block.
 * @param {Block} block
 * @returns {TXResponse}
 */

TXResponse.fromBlock = function fromBlock(block, req) {
  return new TXResponse().fromBlock(block, req);
};

/**
 * Serialize response with extension data.
 * @returns {Buffer}
 */

TXResponse.prototype.toRaw = function toRaw() {
  return this.frameRaw(true);
};

/**
 * Serialize response without extension data.
 * @returns {Buffer}
 */

TXResponse.prototype.toNormal = function toNormal() {
  return this.frameRaw(false);
};

/**
 * Write serialized response to a buffer
 * writer (includes extension data).
 * @param {BufferWriter} bw
 */

TXResponse.prototype.toWriter = function toWriter(bw) {
  return this.writeRaw(bw, true);
};

/**
 * Write serialized response to a buffer
 * writer (excludes extension data).
 * @param {BufferWriter} bw
 */

TXResponse.prototype.toNormalWriter = function toNormalWriter(bw) {
  return this.writeRaw(bw, false);
};

/**
 * Calculate request serialization size.
 * @returns {Number}
 */

TXResponse.prototype.getSize = function getSize(extension) {
  var size = 0;
  var i, tx;

  size += 32;
  size += encoding.sizeVarint(this.txs.length);

  for (i = 0; i < this.txs.length; i++) {
    tx = this.txs[i];
    size += tx.getSize();
  }

  if (extension) {
    size += encoding.sizeVarint(this.ext.length);

    for (i = 0; i < this.ext.length; i++) {
      tx = this.ext[i];
      size += tx.getSize();
    }
  }

  return size;
};

/**
 * Write serialized response to buffer writer.
 * @private
 * @param {BufferWriter} bw
 * @param {Boolean} extension
 */

TXResponse.prototype.writeRaw = function writeRaw(bw, extension) {
  var i, tx;

  bw.writeHash(this.hash);

  bw.writeVarint(this.txs.length);

  for (i = 0; i < this.txs.length; i++) {
    tx = this.txs[i];
    tx.toWriter(bw);
  }

  if (extension) {
    bw.writeVarint(this.ext.length);

    for (i = 0; i < this.ext.length; i++) {
      tx = this.ext[i];
      tx.toWriter(bw);
    }
  }

  return bw;
};

/**
 * Serialize response with extension data.
 * @private
 * @param {Boolean} extension
 * @returns {Buffer}
 */

TXResponse.prototype.frameRaw = function frameRaw(extension) {
  var size = this.getSize(extension);
  return this.writeRaw(new StaticWriter(size), extension).render();
};

/**
 * Represents a prefilled TX.
 * @constructor
 * @param {Number} index
 * @param {TX} tx
 * @property {Number} index
 * @property {TX} tx
 */

function PrefilledTX(index, tx) {
  this.index = index;
  this.tx = tx;
}

/*
 * Expose
 */

exports.CompactBlock = CompactBlock;
exports.TXRequest = TXRequest;
exports.TXResponse = TXResponse;
