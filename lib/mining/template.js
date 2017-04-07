/*!
 * template.js - block template object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var BN = require('bn.js');
var util = require('../utils/util');
var crypto = require('../crypto/crypto');
var StaticWriter = require('../utils/staticwriter');
var Address = require('../primitives/address');
var TX = require('../primitives/tx');
var Block = require('../primitives/block');
var Input = require('../primitives/input');
var Output = require('../primitives/output');
var consensus = require('../protocol/consensus');
var policy = require('../protocol/policy');
var encoding = require('../utils/encoding');
var CoinView = require('../coins/coinview');
var Script = require('../script/script');
var common = require('./common');
var DUMMY = new Buffer(0);

/**
 * Block Template
 * @alias module:mining.BlockTemplate
 * @constructor
 * @param {Object} options
 */

function BlockTemplate(options) {
  if (!(this instanceof BlockTemplate))
    return new BlockTemplate(options);

  this.prevBlock = encoding.NULL_HASH;
  this.prevResolution = encoding.NULL_HASH;
  this.prevValue = 0;
  this.version = 1;
  this.height = 0;
  this.ts = 0;
  this.bits = 0;
  this.target = encoding.ZERO_HASH;
  this.locktime = 0;
  this.mtp = 0;
  this.flags = 0;
  this.extFlags = 0;
  this.coinbaseFlags = DUMMY;
  this.extended = false;
  this.address = new Address();
  this.sigops = 400;
  this.size = 1000;
  this.interval = 210000;
  this.fees = 0;
  this.extFees = 0;
  this.extCost = 0;
  this.extSize = 0;
  this.tree = new MerkleTree();
  this.resolution = null;
  this.commitment = encoding.ZERO_HASH;
  this.left = DUMMY;
  this.right = DUMMY;
  this.items = [];
  this.ext = [];

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options.
 * @private
 * @param {Object} options
 * @returns {BlockTemplate}
 */

BlockTemplate.prototype.fromOptions = function fromOptions(options) {
  assert(options);

  if (options.prevBlock != null) {
    assert(typeof options.prevBlock === 'string');
    this.prevBlock = options.prevBlock;
  }

  if (options.prevResolution != null) {
    assert(typeof options.prevResolution === 'string');
    this.prevResolution = options.prevResolution;
  }

  if (options.prevValue != null) {
    assert(typeof options.prevValue === 'number');
    this.prevValue = options.prevValue;
  }

  if (options.version != null) {
    assert(typeof options.version === 'number');
    this.version = options.version;
  }

  if (options.height != null) {
    assert(typeof options.height === 'number');
    this.height = options.height;
  }

  if (options.ts != null) {
    assert(typeof options.ts === 'number');
    this.ts = options.ts;
  }

  if (options.bits != null)
    this.setBits(options.bits);

  if (options.target != null)
    this.setTarget(options.target);

  if (options.locktime != null) {
    assert(typeof options.locktime === 'number');
    this.locktime = options.locktime;
  }

  if (options.mtp != null) {
    assert(typeof options.mtp === 'number');
    this.mtp = options.mtp;
  }

  if (options.flags != null) {
    assert(typeof options.flags === 'number');
    this.flags = options.flags;
  }

  if (options.extFlags != null) {
    assert(typeof options.extFlags === 'number');
    this.extFlags = options.extFlags;
  }

  if (options.coinbaseFlags != null) {
    assert(Buffer.isBuffer(options.coinbaseFlags));
    this.coinbaseFlags = options.coinbaseFlags;
  }

  if (options.extended != null) {
    assert(typeof options.extended === 'boolean');
    this.extended = options.extended;
  }

  if (options.address != null)
    this.address.fromOptions(options.address);

  if (options.sigops != null) {
    assert(typeof options.sigops === 'number');
    this.sigops = options.sigops;
  }

  if (options.size != null) {
    assert(typeof options.size === 'number');
    this.size = options.size;
  }

  if (options.interval != null) {
    assert(typeof options.interval === 'number');
    this.interval = options.interval;
  }

  if (options.fees != null) {
    assert(typeof options.fees === 'number');
    this.fees = options.fees;
  }

  if (options.extFees != null) {
    assert(typeof options.extFees === 'number');
    this.extFees = options.extFees;
  }

  if (options.extSize != null) {
    assert(typeof options.extSize === 'number');
    this.extSize = options.extSize;
  }

  if (options.items != null) {
    assert(Array.isArray(options.items));
    this.items = options.items;
  }

  if (options.ext != null) {
    assert(Array.isArray(options.ext));
    this.ext = options.ext;
  }

  return this;
};

/**
 * Instantiate block template from options.
 * @param {Object} options
 * @returns {BlockTemplate}
 */

BlockTemplate.fromOptions = function fromOptions(options) {
  return new BlockTemplate().fromOptions(options);
};

/**
 * Create resolution transaction.
 * @returns {TX}
 */

BlockTemplate.prototype.createResolution = function createResolution() {
  var res = new TX();
  var value = this.prevValue;
  var i, j, item, tx, input, output, pushdata;

  if (!this.extended)
    return null;

  // Version must be uint32_max.
  res.version = 0xffffffff;

  // Pushdata input.
  if (this.prevResolution !== encoding.NULL_HASH) {
    input = new Input();
    input.prevout.hash = this.prevResolution;
    input.prevout.index = 0;

    res.inputs.push(input);
  }

  // Get entering outputs.
  for (i = 0; i < this.items.length; i++) {
    item = this.items[i];
    tx = item.tx;
    for (j = 0; j < tx.outputs.length; j++) {
      output = tx.outputs[j];
      if (output.script.isProgram()) {
        value += output.value;
        input = new Input();
        input.prevout.hash = item.hash;
        input.prevout.index = j;
        res.inputs.push(input);
      }
    }
  }

  // Resolution pushdata output.
  pushdata = new Output();
  pushdata.script = new Script([Script.opcodes.OP_TRUE]);
  pushdata.value = 0;
  res.outputs.push(pushdata);

  // Get exiting outputs.
  for (i = 0; i < this.ext.length; i++) {
    item = this.ext[i];
    tx = item.tx;
    for (j = 0; j < tx.outputs.length; j++) {
      output = tx.outputs[j];
      if (!output.script.isProgram()) {
        value -= output.value;
        res.outputs.push(output);
      }
    }
  }

  pushdata.value = value - this.extFees;

  if (res.inputs.length === 0) {
    assert(this.prevResolution === encoding.NULL_HASH);
    assert(res.outputs.length === 1);
    return null;
  }

  res.refresh();

  return res;
};

/**
 * Create witness commitment hash.
 * @param {TX} res
 * @returns {Buffer}
 */

BlockTemplate.prototype.getCommitmentHash = function getCommitmentHash(res) {
  var leaves = [];
  var i, item, root;

  for (i = 0; i < this.items.length; i++) {
    item = this.items[i];
    leaves.push(item.tx.hash());
  }

  if (res)
    leaves.push(res.hash());

  for (i = 0; i < this.ext.length; i++) {
    item = this.ext[i];
    leaves.push(item.tx.hash());
  }

  for (i = 0; i < this.ext.length; i++) {
    item = this.ext[i];
    leaves.push(item.tx.witnessHash());
  }

  root = crypto.createMerkleRoot(leaves);

  assert(!root.malleated);

  return root.hash;
};

/**
 * Create witness commitment script.
 * @returns {Script}
 */

BlockTemplate.prototype.getCommitmentScript = function getCommitmentScript() {
  return Script.fromCommitment(this.commitment);
};

/**
 * Set the target (bits).
 * @param {Number} bits
 */

BlockTemplate.prototype.setBits = function setBits(bits) {
  assert(typeof bits === 'number');
  this.bits = bits;
  this.target = common.getTarget(bits);
};

/**
 * Set the target (uint256le).
 * @param {Buffer} target
 */

BlockTemplate.prototype.setTarget = function setTarget(target) {
  assert(Buffer.isBuffer(target));
  this.bits = common.getBits(target);
  this.target = target;
};

/**
 * Calculate the block reward.
 * @returns {Amount}
 */

BlockTemplate.prototype.getReward = function getReward() {
  var reward = consensus.getReward(this.height, this.interval);
  return reward + this.fees + this.extFees;
};

/**
 * Initialize the default coinbase.
 * @param {Buffer} hash - Witness commitment hash.
 * @returns {TX}
 */

BlockTemplate.prototype.createCoinbase = function createCoinbase(hash) {
  var cb = new TX();
  var padding = 0;
  var input, output, commit;

  // Coinbase input.
  input = new Input();

  // Height (required in v2+ blocks)
  input.script.push(new BN(this.height));

  // Coinbase flags.
  input.script.push(encoding.ZERO_HASH160);

  // Smaller nonce for good measure.
  input.script.push(util.nonce(4));

  // Extra nonce: incremented when
  // the nonce overflows.
  input.script.push(encoding.ZERO_U64);

  input.script.compile();

  cb.inputs.push(input);

  // Reward output.
  output = new Output();
  output.script.fromPubkeyhash(encoding.ZERO_HASH160);
  output.value = this.getReward();

  cb.outputs.push(output);

  // If we're using extension blocks, we
  // need to set up the commitment.
  if (this.extended) {
    // Commitment output.
    commit = new Output();
    commit.script.fromCommitment(hash);
    cb.outputs.push(commit);
  }

  // Padding for the CB height (constant size).
  padding = 5 - input.script.code[0].getSize();
  assert(padding >= 0);

  // Reserved size.
  // Without extension blocks:
  //   CB size = 500
  //   CB size = 125
  //   Sigops cost = 4
  // With extension blocks:
  //   CB size = 724
  //   CB size = 172
  //   Sigops cost = 4
  if (!this.extended) {
    assert.equal(cb.getSize() + padding, 125);
  } else {
    assert.equal(cb.getSize() + padding, 172);
  }

  // Setup coinbase flags (variable size).
  input.script.set(1, this.coinbaseFlags);
  input.script.compile();

  // Setup output script (variable size).
  output.script.clear();
  output.script.fromAddress(this.address);

  cb.refresh();

  assert(input.script.getSize() <= 100,
    'Coinbase input script is too large!');

  return cb;
};

/**
 * Refresh the coinbase and merkle tree.
 */

BlockTemplate.prototype.refresh = function refresh() {
  var res = this.createResolution();
  var hash = this.getCommitmentHash(res);
  var cb = this.createCoinbase(hash);
  var raw = cb.toNormal();
  var size = 0;
  var left, right;

  size += 4; // version
  size += 1; // varint inputs length
  size += cb.inputs[0].getSize(); // input size
  size -= 4 + 4 + 4; // -(nonce1 + nonce2 + sequence)

  // Cut off right after the nonce
  // push and before the sequence.
  left = raw.slice(0, size);

  // Include the sequence.
  size += 4 + 4; // nonce1 + nonce2
  right = raw.slice(size);

  this.resolution = res;
  this.commitment = hash;
  this.left = left;
  this.right = right;
  this.tree = MerkleTree.fromItems(this.items, res);
};

/**
 * Get raw coinbase with desired nonces.
 * @param {Number} nonce1
 * @param {Number} nonce2
 * @returns {Buffer}
 */

BlockTemplate.prototype.getRawCoinbase = function getRawCoinbase(nonce1, nonce2) {
  var size = 0;
  var bw;

  size += this.left.length;
  size += 4 + 4;
  size += this.right.length;

  bw = new StaticWriter(size);
  bw.writeBytes(this.left);
  bw.writeU32BE(nonce1);
  bw.writeU32BE(nonce2);
  bw.writeBytes(this.right);

  return bw.render();
};

/**
 * Calculate the merkle root with given nonces.
 * @param {Number} nonce1
 * @param {Number} nonce2
 * @returns {Buffer}
 */

BlockTemplate.prototype.getRoot = function getRoot(nonce1, nonce2) {
  var raw = this.getRawCoinbase(nonce1, nonce2);
  var hash = crypto.hash256(raw);
  return this.tree.withFirst(hash);
};

/**
 * Create raw block header with given parameters.
 * @param {Buffer} root
 * @param {Number} ts
 * @param {Number} nonce
 * @returns {Buffer}
 */

BlockTemplate.prototype.getHeader = function getHeader(root, ts, nonce) {
  var bw = new StaticWriter(80);

  bw.writeU32(this.version);
  bw.writeHash(this.prevBlock);
  bw.writeHash(root);
  bw.writeU32(ts);
  bw.writeU32(this.bits);
  bw.writeU32(nonce);

  return bw.render();
};

/**
 * Calculate proof with given parameters.
 * @param {Number} nonce1
 * @param {Number} nonce2
 * @param {Number} ts
 * @param {Number} nonce
 * @returns {BlockProof}
 */

BlockTemplate.prototype.getProof = function getProof(nonce1, nonce2, ts, nonce) {
  var root = this.getRoot(nonce1, nonce2);
  var data = this.getHeader(root, ts, nonce);
  var hash = crypto.hash256(data);
  return new BlockProof(hash, root, nonce1, nonce2, ts, nonce);
};

/**
 * Create coinbase from given parameters.
 * @param {Number} nonce1
 * @param {Number} nonce2
 * @returns {TX}
 */

BlockTemplate.prototype.getCoinbase = function getCoinbase(nonce1, nonce2) {
  var raw = this.getRawCoinbase(nonce1, nonce2);
  return TX.fromRaw(raw);
};

/**
 * Create block from calculated proof.
 * @param {BlockProof} proof
 * @returns {Block}
 */

BlockTemplate.prototype.commit = function commit(proof) {
  var root = proof.root;
  var n1 = proof.nonce1;
  var n2 = proof.nonce2;
  var ts = proof.ts;
  var nonce = proof.nonce;
  var block = new Block();
  var i, tx, item;

  block.version = this.version;
  block.prevBlock = this.prevBlock;
  block.merkleRoot = root.toString('hex');
  block.ts = ts;
  block.bits = this.bits;
  block.nonce = nonce;

  tx = this.getCoinbase(n1, n2);

  block.txs.push(tx);

  for (i = 0; i < this.items.length; i++) {
    item = this.items[i];
    block.txs.push(item.tx);
  }

  if (this.resolution)
    block.txs.push(this.resolution);

  for (i = 0; i < this.ext.length; i++) {
    item = this.ext[i];
    block.ext.push(item.tx);
  }

  return block;
};

/**
 * Quick and dirty way to
 * get a coinbase tx object.
 * @returns {TX}
 */

BlockTemplate.prototype.toCoinbase = function toCoinbase() {
  return this.getCoinbase(0, 0);
};

/**
 * Quick and dirty way to get a block
 * object (most likely to be an invalid one).
 * @returns {Block}
 */

BlockTemplate.prototype.toBlock = function toBlock() {
  var proof = this.getProof(0, 0, this.ts, 0);
  return this.commit(proof);
};

/**
 * Calculate the target difficulty.
 * @returns {Number}
 */

BlockTemplate.prototype.getDifficulty = function getDifficulty() {
  return common.getDifficulty(this.target);
};

/**
 * Set the reward output
 * address and refresh.
 * @param {Address} address
 */

BlockTemplate.prototype.setAddress = function setAddress(address) {
  this.address = Address(address);
  this.refresh();
};

/**
 * Add a transaction to the template.
 * @param {TX} tx
 * @param {CoinView} view
 */

BlockTemplate.prototype.addTX = function addTX(tx, view) {
  var item, size, extSize, sigops, extCost;

  assert(!tx.mutable, 'Cannot add mutable TX to block.');

  item = BlockEntry.fromTX(tx, view, this);

  if (!tx.isFinal(this.height, this.locktime))
    return false;

  if (item.extended) {
    if (!this.extended)
      return false;

    size = item.tx.getExitSize();

    if (this.size + size > consensus.MAX_BLOCK_SIZE)
      return false;

    extSize = item.tx.getSize();

    if (this.extSize + extSize > consensus.MAX_EXTENSION_SIZE)
      return false;

    sigops = item.tx.getExitSigops();

    if (this.sigops + sigops > consensus.MAX_BLOCK_SIGOPS)
      return false;

    extCost = item.cost;

    if (this.extCost + extCost > consensus.MAX_EXTENSION_COST)
      return false;

    this.size += size;
    this.extSize += extSize;
    this.sigops += sigops;
    this.extCost += extCost;
    this.extFees += item.fee;

    // Add the tx to our block
    this.ext.push(item);
  } else {
    size = item.tx.getSize();
    size += tx.getEnterSize();

    if (this.size + size > consensus.MAX_BLOCK_SIZE)
      return false;

    sigops = item.sigops;

    if (this.sigops + sigops > consensus.MAX_BLOCK_SIGOPS)
      return false;

    this.size += size;
    this.sigops += sigops;
    this.fees += item.fee;

    // Add the tx to our block
    this.items.push(item);
  }

  return true;
};

/**
 * Add a transaction to the template
 * (less verification than addTX).
 * @param {TX} tx
 * @param {CoinView?} view
 */

BlockTemplate.prototype.pushTX = function pushTX(tx, view) {
  var item, size, sigops, cost;

  assert(!tx.mutable, 'Cannot add mutable TX to block.');

  if (!view)
    view = new CoinView();

  item = BlockEntry.fromTX(tx, view, this);
  size = item.tx.getSize();
  sigops = item.sigops;
  cost = item.cost;

  this.size += size;
  this.sigops += sigops;
  this.cost += cost;
  this.fees += item.fee;

  // Add the tx to our block
  this.items.push(item);

  return true;
};

/**
 * BlockEntry
 * @alias module:mining.BlockEntry
 * @constructor
 * @param {TX} tx
 * @property {TX} tx
 * @property {Hash} hash
 * @property {Amount} fee
 * @property {Rate} rate
 * @property {Number} priority
 * @property {Boolean} free
 * @property {Sigops} sigops
 * @property {Number} depCount
 */

function BlockEntry(tx) {
  this.tx = tx;
  this.hash = tx.hash('hex');
  this.fee = 0;
  this.rate = 0;
  this.priority = 0;
  this.free = false;
  this.sigops = 0;
  this.cost = 0;
  this.extended = false;
  this.descRate = 0;
  this.depCount = 0;
}

/**
 * Instantiate block entry from transaction.
 * @param {TX} tx
 * @param {CoinView} view
 * @param {BlockTemplate} attempt
 * @returns {BlockEntry}
 */

BlockEntry.fromTX = function fromTX(tx, view, attempt) {
  var item = new BlockEntry(tx);

  item.fee = tx.getFee(view);
  item.rate = tx.getRate(view);
  item.priority = tx.getPriority(view, attempt.height);
  item.free = false;

  item.extended = tx.isExtension(view);

  if (item.extended)
    item.cost = tx.getExtensionCost(view);
  else
    item.sigops = tx.getSigops(view, attempt.flags);

  item.descRate = item.rate;

  return item;
};

/**
 * Instantiate block entry from mempool entry.
 * @param {MempoolEntry} entry
 * @param {BlockTemplate} attempt
 * @returns {BlockEntry}
 */

BlockEntry.fromEntry = function fromEntry(entry, attempt) {
  var item = new BlockEntry(entry.tx);
  item.fee = entry.getFee();
  item.rate = entry.getDeltaRate();
  item.priority = entry.getPriority(attempt.height);
  item.free = entry.getDeltaFee() < policy.getMinFee(entry.size);
  item.sigops = entry.sigops;
  item.cost = entry.cost;
  item.descRate = entry.getDescRate();
  item.extended = entry.extended;
  return item;
};

/*
 * BlockProof
 * @constructor
 * @param {Hash} hash
 * @param {Hash} root
 * @param {Number} nonce1
 * @param {Number} nonce2
 * @param {Number} ts
 * @param {Number} nonce
 */

function BlockProof(hash, root, nonce1, nonce2, ts, nonce) {
  this.hash = hash;
  this.root = root;
  this.nonce1 = nonce1;
  this.nonce2 = nonce2;
  this.ts = ts;
  this.nonce = nonce;
}

BlockProof.prototype.rhash = function rhash() {
  return util.revHex(this.hash.toString('hex'));
};

BlockProof.prototype.verify = function verify(target) {
  return common.rcmp(this.hash, target) <= 0;
};

BlockProof.prototype.getDifficulty = function getDifficulty() {
  return common.getDifficulty(this.hash);
};

/*
 * MerkleTree
 * @constructor
 * @property {Hash[]} steps
 */

function MerkleTree() {
  this.steps = [];
}

MerkleTree.prototype.withFirst = function withFirst(hash) {
  var i, step, data;

  for (i = 0; i < this.steps.length; i++) {
    step = this.steps[i];
    data = util.concat(hash, step);
    hash = crypto.hash256(data);
  }

  return hash;
};

MerkleTree.prototype.toJSON = function toJSON() {
  var steps = [];
  var i, step;

  for (i = 0; i < this.steps.length; i++) {
    step = this.steps[i];
    steps.push(step.toString('hex'));
  }

  return steps;
};

MerkleTree.prototype.fromItems = function fromItems(items, res) {
  var leaves = [];
  var i, item;

  leaves.push(encoding.ZERO_HASH);

  for (i = 0; i < items.length; i++) {
    item = items[i];
    leaves.push(item.tx.hash());
  }

  if (res)
    leaves.push(res.hash());

  return this.fromLeaves(leaves);
};

MerkleTree.fromItems = function fromItems(items, res) {
  return new MerkleTree().fromItems(items, res);
};

MerkleTree.prototype.fromBlock = function fromBlock(txs) {
  var leaves = [];
  var i, tx;

  leaves.push(encoding.ZERO_HASH);

  for (i = 1; i < txs.length; i++) {
    tx = txs[i];
    leaves.push(tx.hash());
  }

  return this.fromLeaves(leaves);
};

MerkleTree.fromBlock = function fromBlock(txs) {
  return new MerkleTree().fromBlock(txs);
};

MerkleTree.prototype.fromLeaves = function fromLeaves(leaves) {
  var len = leaves.length;
  var i, hashes, data, hash;

  while (len > 1) {
    this.steps.push(leaves[1]);

    if (len % 2)
      leaves.push(leaves[len - 1]);

    hashes = [null];

    for (i = 2; i < len; i += 2) {
      data = util.concat(leaves[i], leaves[i + 1]);
      hash = crypto.hash256(data);
      hashes.push(hash);
    }

    leaves = hashes;
    len = leaves.length;
  }

  return this;
};

MerkleTree.fromLeaves = function fromLeaves(leaves) {
  return new MerkleTree().fromLeaves(leaves);
};

/*
 * Expose
 */

exports = BlockTemplate;
exports.BlockTemplate = BlockTemplate;
exports.BlockEntry = BlockEntry;

module.exports = exports;
