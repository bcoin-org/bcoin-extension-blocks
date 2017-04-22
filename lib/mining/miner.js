/*!
 * miner.js - block generator for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var util = require('../utils/util');
var co = require('../utils/co');
var Heap = require('../utils/heap');
var AsyncObject = require('../utils/asyncobject');
var Amount = require('../btc/amount');
var Address = require('../primitives/address');
var BlockTemplate = require('./template');
var Network = require('../protocol/network');
var consensus = require('../protocol/consensus');
var policy = require('../protocol/policy');
var CPUMiner = require('./cpuminer');
var BlockEntry = BlockTemplate.BlockEntry;

/**
 * A bitcoin miner and block generator.
 * @alias module:mining.Miner
 * @constructor
 * @param {Object} options
 */

function Miner(options) {
  if (!(this instanceof Miner))
    return new Miner(options);

  AsyncObject.call(this);

  this.options = new MinerOptions(options);
  this.network = this.options.network;
  this.logger = this.options.logger.context('miner');
  this.chain = this.options.chain;
  this.mempool = this.options.mempool;
  this.addresses = this.options.addresses;
  this.locker = this.chain.locker;
  this.cpu = new CPUMiner(this);

  this.init();
}

util.inherits(Miner, AsyncObject);

/**
 * Open the miner, wait for the chain and mempool to load.
 * @method
 * @alias module:mining.Miner#open
 * @returns {Promise}
 */

Miner.prototype.init = function init() {
  var self = this;

  this.cpu.on('error', function(err) {
    self.emit('error', err);
  });
};

/**
 * Open the miner, wait for the chain and mempool to load.
 * @method
 * @alias module:mining.Miner#open
 * @returns {Promise}
 */

Miner.prototype._open = co(function* open() {
  yield this.chain.open();

  if (this.mempool)
    yield this.mempool.open();

  yield this.cpu.open();

  this.logger.info('Miner loaded (flags=%s).',
    this.options.coinbaseFlags.toString('utf8'));

  if (this.addresses.length === 0)
    this.logger.warning('No reward address is set for miner!');
});

/**
 * Close the miner.
 * @method
 * @alias module:mining.Miner#close
 * @returns {Promise}
 */

Miner.prototype._close = co(function* close() {
  yield this.cpu.close();
});

/**
 * Create a block template.
 * @method
 * @param {ChainEntry?} tip
 * @param {Address?} address
 * @returns {Promise} - Returns {@link BlockTemplate}.
 */

Miner.prototype.createBlock = co(function* createBlock(tip, address) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._createBlock(tip, address);
  } finally {
    unlock();
  }
});

/**
 * Create a block template (without a lock).
 * @method
 * @private
 * @param {ChainEntry?} tip
 * @param {Address?} address
 * @returns {Promise} - Returns {@link BlockTemplate}.
 */

Miner.prototype._createBlock = co(function* createBlock(tip, address) {
  var version = this.options.version;
  var ts, mtp, locktime, target, attempt, block, state;

  if (!tip)
    tip = this.chain.tip;

  if (!address)
    address = this.getAddress();

  if (version === -1)
    version = yield this.chain.computeBlockVersion(tip);

  mtp = yield tip.getMedianTime();
  ts = Math.max(this.network.now(), mtp + 1);
  locktime = ts;

  state = yield this.chain.getDeployments(ts, tip);

  if (state.hasMTP())
    locktime = mtp;

  target = yield this.chain.getTarget(ts, tip);

  attempt = new BlockTemplate({
    prevBlock: tip.hash,
    prevResolution: tip.resHash,
    prevValue: tip.resValue,
    height: tip.height + 1,
    version: version,
    ts: ts,
    bits: target,
    locktime: locktime,
    mtp: mtp,
    flags: state.flags,
    extFlags: state.extFlags,
    address: address,
    coinbaseFlags: this.options.coinbaseFlags,
    extended: state.hasExtension(),
    interval: this.network.halvingInterval,
    size: this.options.reservedSize,
    sigops: this.options.reservedSigops
  });

  this.assemble(attempt);

  this.logger.debug(
    'Created block template (height=%d, size=%d, fees=%d, txs=%s, diff=%d).',
    attempt.height,
    attempt.size + attempt.extSize,
    Amount.btc(attempt.fees + attempt.extFees),
    attempt.items.length + 1 + attempt.ext.length,
    attempt.getDifficulty());

  if (this.options.preverify) {
    block = attempt.toBlock();

    try {
      yield this.chain._verifyBlock(block);
    } catch (e) {
      if (e.type === 'VerifyError') {
        this.logger.warning('Miner created invalid block!');
        this.logger.error(e);
        throw new Error('BUG: Miner created invalid block.');
      }
      throw e;
    }

    this.logger.debug(
      'Preverified block %d successfully!',
      attempt.height);
  }

  return attempt;
});

/**
 * Update block timestamp.
 * @param {BlockTemplate} attempt
 */

Miner.prototype.updateTime = function updateTime(attempt) {
  attempt.ts = Math.max(this.network.now(), attempt.mtp + 1);
};

/**
 * Create a cpu miner job.
 * @method
 * @param {ChainEntry?} tip
 * @param {Address?} address
 * @returns {Promise} Returns {@link CPUJob}.
 */

Miner.prototype.createJob = function createJob(tip, address) {
  return this.cpu.createJob(tip, address);
};

/**
 * Mine a single block.
 * @method
 * @param {ChainEntry?} tip
 * @param {Address?} address
 * @returns {Promise} Returns {@link Block}.
 */

Miner.prototype.mineBlock = function mineBlock(tip, address) {
  return this.cpu.mineBlock(tip, address);
};

/**
 * Add an address to the address list.
 * @param {Address} address
 */

Miner.prototype.addAddress = function addAddress(address) {
  this.addresses.push(Address(address));
};

/**
 * Get a random address from the address list.
 * @returns {Address}
 */

Miner.prototype.getAddress = function getAddress() {
  var addr;

  if (this.addresses.length === 0)
    return new Address();

  addr = this.addresses[Math.random() * this.addresses.length | 0];

  if (addr.isProgram())
    throw new Error('Cannot mine with a witness address.');

  return addr;
};

/**
 * Get mempool entries, sort by dependency order.
 * Prioritize by priority and fee rates.
 * @param {BlockTemplate} attempt
 * @returns {MempoolEntry[]}
 */

Miner.prototype.assemble = function assemble(attempt) {
  var depMap = {};
  var queue = new Heap(cmpRate);
  var priority = this.options.prioritySize > 0;
  var i, j, entry, item, tx, hash, input;
  var prev, deps, hashes, size, extSize, extCost, extSigops, sigops, block;

  if (priority)
    queue.set(cmpPriority);

  if (!this.mempool) {
    attempt.refresh();
    return [];
  }

  assert(this.mempool.tip === this.chain.tip.hash,
    'Mempool/chain tip mismatch! Unsafe to create block.');

  hashes = this.mempool.getSnapshot();

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    entry = this.mempool.getEntry(hash);
    item = BlockEntry.fromEntry(entry, attempt);
    tx = item.tx;

    if (tx.isCoinbase())
      throw new Error('Cannot add coinbase to block.');

    for (j = 0; j < tx.inputs.length; j++) {
      input = tx.inputs[j];
      prev = input.prevout.hash;

      if (!this.mempool.hasEntry(prev))
        continue;

      item.depCount += 1;

      if (!depMap[prev])
        depMap[prev] = [];

      depMap[prev].push(item);
    }

    if (item.depCount > 0)
      continue;

    queue.insert(item);
  }

  while (queue.size() > 0) {
    item = queue.shift();
    tx = item.tx;
    hash = item.hash;
    size = attempt.size;
    sigops = attempt.sigops;
    extSize = attempt.extSize;
    extCost = attempt.extCost;
    extSigops = attempt.extSigops;

    if (!tx.isFinal(attempt.height, attempt.locktime))
      continue;

    if (item.extended) {
      if (!attempt.extended)
        continue;

      size += tx.getExitSize();

      if (size > this.options.maxSize)
        continue;

      sigops += tx.getExitSigops();

      if (sigops > this.options.maxSigops)
        continue;

      extSize += tx.getSize();

      if (extSize > this.options.extMaxSize)
        continue;

      extCost += item.cost;

      if (extCost > this.options.extMaxCost)
        continue;

      extSigops += item.sigops;

      if (extSigops > this.options.extMaxSigops)
        continue;

      if (priority) {
        if (size > this.options.prioritySize
            || item.priority < this.options.priorityThreshold) {
          priority = false;
          queue.set(cmpRate);
          queue.init();
          queue.insert(item);
          continue;
        }
      } else {
        if (item.free && extSize >= this.options.extMinSize)
          continue;
      }

      attempt.extFees += item.fee;
      attempt.ext.push(item);
    } else {
      size += tx.getSize();
      size += tx.getEnterSize();

      if (size > this.options.maxSize)
        continue;

      sigops += item.sigops;

      if (sigops > this.options.maxSigops)
        continue;

      if (priority) {
        if (size > this.options.prioritySize
            || item.priority < this.options.priorityThreshold) {
          priority = false;
          queue.set(cmpRate);
          queue.init();
          queue.insert(item);
          continue;
        }
      } else {
        if (item.free && size >= this.options.minSize)
          continue;
      }

      attempt.fees += item.fee;
      attempt.items.push(item);
    }

    attempt.size = size;
    attempt.sigops = sigops;
    attempt.extSize = extSize;
    attempt.extCost = extCost;
    attempt.extSigops = extSigops;

    deps = depMap[hash];

    if (!deps)
      continue;

    for (j = 0; j < deps.length; j++) {
      item = deps[j];
      if (--item.depCount === 0)
        queue.insert(item);
    }
  }

  attempt.refresh();

  assert(attempt.size <= consensus.MAX_BLOCK_SIZE,
    'Block exceeds reserved size!');

  assert(attempt.extSize <= consensus.MAX_EXTENSION_SIZE,
    'Block exceeds extension size!');

  if (this.options.preverify) {
    block = attempt.toBlock();

    assert(block.getSize() <= attempt.size,
      'Block exceeds reserved size!');

    assert(block.getBaseSize() <= consensus.MAX_BLOCK_SIZE,
      'Block exceeds max block size.');

    assert(block.getExtensionSize() <= consensus.MAX_EXTENSION_SIZE,
      'Block exceeds max block size.');
  }
};

/**
 * MinerOptions
 * @alias module:mining.MinerOptions
 * @constructor
 * @param {Object}
 */

function MinerOptions(options) {
  if (!(this instanceof MinerOptions))
    return new MinerOptions(options);

  this.network = Network.primary;
  this.logger = null;
  this.chain = null;
  this.mempool = null;

  this.version = -1;
  this.addresses = [];
  this.coinbaseFlags = new Buffer('mined by bcoin', 'ascii');
  this.preverify = false;

  this.minSize = policy.MIN_BLOCK_SIZE;
  this.maxSize = policy.MAX_BLOCK_SIZE;
  this.prioritySize = policy.BLOCK_PRIORITY_SIZE;
  this.priorityThreshold = policy.BLOCK_PRIORITY_THRESHOLD;
  this.maxSigops = consensus.MAX_BLOCK_SIGOPS;
  this.extMinSize = policy.MIN_EXTENSION_SIZE;
  this.extMaxSize = policy.MAX_EXTENSION_SIZE;
  this.extPrioritySize = policy.EXTENSION_PRIORITY_SIZE;
  this.extPriorityThreshold = policy.EXTENSION_PRIORITY_THRESHOLD;
  this.extMaxCost = consensus.MAX_EXTENSION_COST;
  this.extMaxSigops = consensus.MAX_EXTENSION_SIGOPS_COST;
  this.reservedSize = 1000;
  this.reservedSigops = 400;

  this.fromOptions(options);
}

/**
 * Inject properties from object.
 * @private
 * @param {Object} options
 * @returns {MinerOptions}
 */

MinerOptions.prototype.fromOptions = function fromOptions(options) {
  var i, flags, address;

  assert(options, 'Miner requires options.');
  assert(options.chain && typeof options.chain === 'object',
    'Miner requires a blockchain.');

  this.chain = options.chain;
  this.network = options.chain.network;
  this.logger = options.chain.logger;

  if (options.logger != null) {
    assert(typeof options.logger === 'object');
    this.logger = options.logger;
  }

  if (options.mempool != null) {
    assert(typeof options.mempool === 'object');
    this.mempool = options.mempool;
  }

  if (options.version != null) {
    assert(util.isNumber(options.version));
    this.version = options.version;
  }

  if (options.address) {
    if (Array.isArray(options.address)) {
      for (i = 0; i < options.address.length; i++) {
        address = new Address(options.address[i]);
        if (address.isProgram())
          throw new Error('Cannot mine with a witness address.');
        this.addresses.push(address);
      }
    } else {
      address = new Address(options.address);
      if (address.isProgram())
        throw new Error('Cannot mine with a witness address.');
      this.addresses.push(address);
    }
  }

  if (options.addresses) {
    assert(Array.isArray(options.addresses));
    for (i = 0; i < options.addresses.length; i++) {
      address = new Address(options.addresses[i]);
      if (address.isProgram())
        throw new Error('Cannot mine with a witness address.');
      this.addresses.push(address);
    }
  }

  if (options.coinbaseFlags) {
    flags = options.coinbaseFlags;
    if (typeof flags === 'string')
      flags = new Buffer(flags, 'utf8');
    assert(Buffer.isBuffer(flags));
    assert(flags.length <= 20, 'Coinbase flags > 20 bytes.');
    this.coinbaseFlags = flags;
  }

  if (options.preverify != null) {
    assert(typeof options.preverify === 'boolean');
    this.preverify = options.preverify;
  }

  if (options.minSize != null) {
    assert(util.isNumber(options.minSize));
    this.minSize = options.minSize;
  }

  if (options.maxSize != null) {
    assert(util.isNumber(options.maxSize));
    assert(options.maxSize <= consensus.MAX_BLOCK_SIZE,
      'Max size must be below MAX_BLOCK_SIZE');
    this.maxSize = options.maxSize;
  }

  if (options.maxSigops != null) {
    assert(util.isNumber(options.maxSigops));
    assert(options.maxSigops <= consensus.MAX_BLOCK_SIGOPS,
      'Max sigops must be below MAX_BLOCK_SIGOPS');
    this.maxSigops = options.maxSigops;
  }

  if (options.prioritySize != null) {
    assert(util.isNumber(options.prioritySize));
    this.prioritySize = options.prioritySize;
  }

  if (options.priorityThreshold != null) {
    assert(util.isNumber(options.priorityThreshold));
    this.priorityThreshold = options.priorityThreshold;
  }

  if (options.extMinSize != null) {
    assert(util.isNumber(options.extMinSize));
    this.extMinSize = options.extMinSize;
  }

  if (options.extMaxSize != null) {
    assert(util.isNumber(options.extMaxSize));
    assert(options.extMaxSize <= consensus.MAX_EXTENSION_SIZE,
      'Max size must be below MAX_EXTENSION_SIZE');
    this.extMaxSize = options.extMaxSize;
  }

  if (options.extMaxCost != null) {
    assert(util.isNumber(options.extMaxCost));
    assert(options.extMaxCost <= consensus.MAX_EXTENSION_COST,
      'Max sigops must be below MAX_EXTENSION_EXTENSION_COST');
    this.extMaxCost = options.extMaxCost;
  }

  if (options.extMaxSigops != null) {
    assert(util.isNumber(options.extMaxSigops));
    assert(options.extMaxSigops <= consensus.MAX_EXTENSION_COST,
      'Max sigops must be below MAX_EXTENSION_EXTENSION_COST');
    this.extMaxSigops = options.extMaxSigops;
  }

  if (options.extPrioritySize != null) {
    assert(util.isNumber(options.extPrioritySize));
    this.extPrioritySize = options.extPrioritySize;
  }

  if (options.extPriorityThreshold != null) {
    assert(util.isNumber(options.extPriorityThreshold));
    this.extPriorityThreshold = options.extPriorityThreshold;
  }

  if (options.reservedSize != null) {
    assert(util.isNumber(options.reservedSize));
    this.reservedSize = options.reservedSize;
  }

  if (options.reservedSigops != null) {
    assert(util.isNumber(options.reservedSigops));
    this.reservedSigops = options.reservedSigops;
  }

  return this;
};

/**
 * Instantiate miner options from object.
 * @param {Object} options
 * @returns {MinerOptions}
 */

MinerOptions.fromOptions = function fromOptions(options) {
  return new MinerOptions().fromOptions(options);
};

/*
 * Helpers
 */

function cmpPriority(a, b) {
  if (a.priority === b.priority)
    return cmpRate(a, b);
  return b.priority - a.priority;
}

function cmpRate(a, b) {
  var x = a.rate;
  var y = b.rate;

  if (a.descRate > a.rate)
    x = a.descRate;

  if (b.descRate > b.rate)
    y = b.descRate;

  if (x === y) {
    x = a.priority;
    y = b.priority;
  }

  return y - x;
}

/*
 * Expose
 */

module.exports = Miner;
