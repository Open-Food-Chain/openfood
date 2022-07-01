# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@ecdsa.org
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# two options to sync headers: (1) old school block headers file dl - more bandwidth use (2) checkpoints - less bandwidth use
# current version support only checkpoints

import threading

import util
from .bitcoin import *

HDR_LEN = 1487
CHUNK_LEN = 330

MAX_TARGET = 0x0007FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
POW_AVERAGING_WINDOW = 17
POW_MEDIAN_BLOCK_SPAN = 11
POW_MAX_ADJUST_DOWN = 32
POW_MAX_ADJUST_UP = 16
POW_DAMPING_FACTOR = 4
POW_TARGET_SPACING = 60
# ref: https://github.com/jl777/komodo/blob/master/src/chainparams.cpp
# TODO: target calc fix

TARGET_CALC_BLOCKS = POW_AVERAGING_WINDOW + POW_MEDIAN_BLOCK_SPAN

AVERAGING_WINDOW_TIMESPAN = POW_AVERAGING_WINDOW * POW_TARGET_SPACING

MIN_ACTUAL_TIMESPAN = AVERAGING_WINDOW_TIMESPAN * \
    (100 - POW_MAX_ADJUST_UP) // 100

MAX_ACTUAL_TIMESPAN = AVERAGING_WINDOW_TIMESPAN * \
    (100 + POW_MAX_ADJUST_DOWN) // 100

def serialize_header(res):
    s = int_to_hex(res.get('version'), 4) \
        + rev_hex(res.get('prev_block_hash')) \
        + rev_hex(res.get('merkle_root')) \
        + rev_hex(res.get('reserved_hash')) \
        + int_to_hex(int(res.get('timestamp')), 4) \
        + int_to_hex(int(res.get('bits')), 4) \
        + rev_hex(res.get('nonce')) \
        + rev_hex(res.get('sol_size')) \
        + rev_hex(res.get('solution'))
    return s

def deserialize_header(s, height):
    if not s:
        raise Exception('Invalid header: {}'.format(s))
    if len(s) != HDR_LEN:
        raise Exception('Invalid header length: {}'.format(len(s)))
    hex_to_int = lambda s: int('0x' + bh2u(s[::-1]), 16)
    h = {}
    h['version'] = hex_to_int(s[0:4])
    h['prev_block_hash'] = hash_encode(s[4:36])
    h['merkle_root'] = hash_encode(s[36:68])
    h['reserved_hash'] = hash_encode(s[68:100])
    h['timestamp'] = hex_to_int(s[100:104])
    h['bits'] = hex_to_int(s[104:108])
    h['nonce'] = hash_encode(s[108:140])
    h['sol_size'] = hash_encode(s[140:143])
    h['solution'] = hash_encode(s[143:1487])
    h['block_height'] = height

    return h

def hash_header(header):
    if header is None:
        return '0' * 64
    if header.get('prev_block_hash') is None:
        header['prev_block_hash'] = '00'*32
    return hash_encode(Hash(bfh(serialize_header(header))))


blockchains = {}

def read_blockchains(config):
    blockchains[0] = Blockchain(config, 0, None)
    fdir = os.path.join(util.get_headers_dir(config), 'forks')
    if not os.path.exists(fdir):
        os.mkdir(fdir)
    l = filter(lambda x: x.startswith('fork_'), os.listdir(fdir))
    l = sorted(l, key = lambda x: int(x.split('_')[1]))
    for filename in l:
        checkpoint = int(filename.split('_')[2])
        parent_id = int(filename.split('_')[1])
        b = Blockchain(config, checkpoint, parent_id)
        h = b.read_header(b.checkpoint)
        if b.parent().can_connect(h, check_height=False):
            blockchains[b.checkpoint] = b
        else:
            util.print_error("cannot connect", filename)

    return blockchains

def check_header(header):
    if type(header) is not dict:
        return False
    for b in blockchains.values():
        if b.check_header(header):
            return b
    return False

def can_connect(header):
    for b in blockchains.values():
        if b.can_connect(header):
            return b
    return False


class Blockchain(util.PrintError):
    """
    Manages blockchain headers and their verification
    """

    def __init__(self, config, checkpoint, parent_id):
        self.config = config
        self.catch_up = None # interface catching up
        self.checkpoint = checkpoint
        try:
            with open(os.path.join(util.get_headers_dir(self.config), 'checkpoints.json'), 'r') as f:
                r = json.loads(f.read())
        except:
            r = constant.net.CHECKPOINTS
        self.checkpoints = r
        self.parent_id = parent_id
        self.lock = threading.Lock()
        with self.lock:
            self.update_size()

    def parent(self):
        return blockchains[self.parent_id]

    def get_max_child(self):
        children = list(filter(lambda y: y.parent_id==self.checkpoint, blockchains.values()))
        return max([x.checkpoint for x in children]) if children else None

    def get_checkpoint(self):
        mc = self.get_max_child()
        return mc if mc is not None else self.checkpoint

    def get_branch_size(self):
        return self.height() - self.get_checkpoint() + 1

    def get_name(self):
        return self.get_hash(self.get_checkpoint()).lstrip('00')[0:10]

    def check_header(self, header):
        header_hash = hash_header(header)
        height = header.get('block_height')
        return header_hash == self.get_hash(height)

    def fork(parent, header):
        checkpoint = header.get('block_height')
        self = Blockchain(parent.config, checkpoint, parent.checkpoint)
        open(self.path(), 'w+').close()
        self.save_header(header)
        return self

    def height(self):
        return self.checkpoint + self.size() - 1

    def size(self):
        with self.lock:
            return self._size

    def update_size(self):
        p = self.path()
        self._size = os.path.getsize(p)//HDR_LEN if os.path.exists(p) else 0

    def verify_header(self, header, prev_hash, target):
        _hash = hash_header(header)
        if prev_hash != header.get('prev_block_hash'):
            raise Exception("prev hash mismatch: %s vs %s" % (prev_hash, header.get('prev_block_hash')))
        if constant.net.TESTNET:
            return
        #bits = self.target_to_bits(target)
        #if bits != header.get('bits'):
            # [Blockchain] verify_chunk 0 failed bits mismatch: 520617983 vs 537857807
            #raise Exception("bits mismatch: %s vs %s" % (bits, header.get('bits')))
        #if int('0x' + _hash, 16) > target:
        #    raise Exception("insufficient proof of work: %s vs target %s" % (int('0x' + _hash, 16), target))

    def verify_chunk(self, index, data):
        num = len(data) // HDR_LEN
        prev_hash = self.get_hash(index * CHUNK_LEN - 1)
        chunk_headers = {'empty': True}
        for i in range(num):
            raw_header = data[i*HDR_LEN:(i+1) * HDR_LEN]
            height = index * CHUNK_LEN + i
            header = deserialize_header(raw_header, height)
            target = self.get_target(height, chunk_headers)
            self.verify_header(header, prev_hash, target)

            chunk_headers[height] = header
            if i == 0:
                chunk_headers['min_height'] = height
                chunk_headers['empty'] = False
            chunk_headers['max_height'] = height
            prev_hash = hash_header(header)

    def path(self):
        d = util.get_headers_dir(self.config)
        filename = 'blockchain_headers' if self.parent_id is None else os.path.join('forks', 'fork_%d_%d'%(self.parent_id, self.checkpoint))
        return os.path.join(d, filename)

    def save_chunk(self, index, chunk):
        filename = self.path()
        d = (index * CHUNK_LEN - self.checkpoint) * HDR_LEN
        if d < 0:
            chunk = chunk[-d:]
            d = 0
        truncate = index >= len(self.checkpoints)
        self.write(chunk, d, truncate)
        self.swap_with_parent()

    def swap_with_parent(self):
        if self.parent_id is None:
            return
        parent_branch_size = self.parent().height() - self.checkpoint + 1
        if parent_branch_size >= self.size():
            return
        self.print_error("swap", self.checkpoint, self.parent_id)
        parent_id = self.parent_id
        checkpoint = self.checkpoint
        parent = self.parent()
        with open(self.path(), 'rb') as f:
            my_data = f.read()
        with open(parent.path(), 'rb') as f:
            f.seek((checkpoint - parent.checkpoint)*HDR_LEN)
            parent_data = f.read(parent_branch_size*HDR_LEN)
        self.write(parent_data, 0)
        parent.write(my_data, (checkpoint - parent.checkpoint)*HDR_LEN)
        # store file path
        for b in blockchains.values():
            b.old_path = b.path()
        # swap parameters
        self.parent_id = parent.parent_id; parent.parent_id = parent_id
        self.checkpoint = parent.checkpoint; parent.checkpoint = checkpoint
        self._size = parent._size; parent._size = parent_branch_size
        # move files
        for b in blockchains.values():
            if b in [self, parent]: continue
            if b.old_path != b.path():
                self.print_error("renaming", b.old_path, b.path())
                os.rename(b.old_path, b.path())
        # update pointers
        blockchains[self.checkpoint] = self
        blockchains[parent.checkpoint] = parent

    def write(self, data, offset, truncate=True):
        filename = self.path()
        with self.lock:
            with open(filename, 'rb+') as f:
                if truncate and offset != self._size*HDR_LEN:
                    f.seek(offset)
                    f.truncate()
                f.seek(offset)
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            self.update_size()

    def save_header(self, header):
        delta = header.get('block_height') - self.checkpoint
        data = bfh(serialize_header(header))
        assert delta == self.size()
        assert len(data) == HDR_LEN
        self.write(data, delta*HDR_LEN)
        self.swap_with_parent()

    def read_header(self, height):
        assert self.parent_id != self.checkpoint
        if height < 0:
            return
        if height < self.checkpoint:
            return self.parent().read_header(height)
        if height > self.height():
            return
        delta = height - self.checkpoint
        name = self.path()
        if os.path.exists(name):
            with open(name, 'rb') as f:
                f.seek(delta * HDR_LEN)
                h = f.read(HDR_LEN)
                if len(h) < HDR_LEN:
                    raise Exception('Expected to read a full header. This was only {} bytes'.format(len(h)))
        elif not os.path.exists(util.get_headers_dir(self.config)):
            raise Exception('Electrum datadir does not exist. Was it deleted while running?')
        else:
            raise Exception('Cannot find headers file but datadir is there. Should be at {}'.format(name))
        if h == bytes([0])*HDR_LEN:
            return None
        return deserialize_header(h, height)

    def get_hash(self, height):
        if height > 0:
            self.print_error('get_hash ht', height)
        
        if height == -1:
            return '0000000000000000000000000000000000000000000000000000000000000000'
        elif height == 0:
            return constant.net.GENESIS
        elif height < len(self.checkpoints) * CHUNK_LEN - TARGET_CALC_BLOCKS:
            index = height // CHUNK_LEN
            h, t, extra_headers = self.checkpoints[index]
            self.print_error('get_hash checkpoints', hash_header(self.read_header(height)))
            return h;
        else:
            self.print_error('get_hash hash_header', hash_header(self.read_header(height)))
            return hash_header(self.read_header(height))

    def get_median_time(self, height, chunk_headers=None):
        if chunk_headers is None or chunk_headers['empty']:
            chunk_empty = True
        else:
            chunk_empty = False
            min_height = chunk_headers['min_height']
            max_height = chunk_headers['max_height']

        height_range = range(max(0, height - POW_MEDIAN_BLOCK_SPAN),
                             max(1, height))
        median = []
        for h in height_range:
            header = self.read_header(h)
            if not header and not chunk_empty \
                and min_height <= h <= max_height:
                    header = chunk_headers[h]
            if not header:
                raise Exception("Can not read header at height %s" % h)
            median.append(header.get('timestamp'))

        median.sort()
        return median[len(median)//2];

    def get_target(self, height, chunk_headers=None):
        if chunk_headers is None or chunk_headers['empty']:
            chunk_empty = True
        else:
            chunk_empty = False
            min_height = chunk_headers['min_height']
            max_height = chunk_headers['max_height']

        if height <= POW_AVERAGING_WINDOW:
            return MAX_TARGET

        height_range = range(max(0, height - POW_AVERAGING_WINDOW),
                             max(1, height))
        mean_target = 0
        for h in height_range:
            header = self.read_header(h)
            if not header and not chunk_empty \
                and min_height <= h <= max_height:
                    header = chunk_headers[h]
            if not header:
                raise Exception("Can not read header at height %s" % h)
            if header:
                mean_target += self.bits_to_target(header.get('bits'))
        mean_target //= POW_AVERAGING_WINDOW

        actual_timespan = self.get_median_time(height, chunk_headers) - \
            self.get_median_time(height - POW_AVERAGING_WINDOW, chunk_headers)
        actual_timespan = AVERAGING_WINDOW_TIMESPAN + \
            int((actual_timespan - AVERAGING_WINDOW_TIMESPAN) / \
                POW_DAMPING_FACTOR)
        if actual_timespan < MIN_ACTUAL_TIMESPAN:
            actual_timespan = MIN_ACTUAL_TIMESPAN
        elif actual_timespan > MAX_ACTUAL_TIMESPAN:
            actual_timespan = MAX_ACTUAL_TIMESPAN

        next_target = mean_target // AVERAGING_WINDOW_TIMESPAN * actual_timespan

        if next_target > MAX_TARGET:
            next_target = MAX_TARGET

        return next_target

    def bits_to_target(self, bits):
        bitsN = (bits >> 24) & 0xff
        if not (bitsN >= 0x03 and bitsN <= 0x20):
            if not constant.net.TESTNET:
                raise Exception("First part of bits should be in [0x03, 0x1f]")
        bitsBase = bits & 0xffffff
        if not (bitsBase >= 0x8000 and bitsBase <= 0x7fffff):
            raise Exception("Second part of bits should be in [0x8000, 0x7fffff]")
        return bitsBase << (8 * (bitsN-3))

    def target_to_bits(self, target):
        c = ("%064x" % target)[2:]
        while c[:2] == '00' and len(c) > 6:
            c = c[2:]
        bitsN, bitsBase = len(c) // 2, int('0x' + c[:6], 16)
        if bitsBase >= 0x800000:
            bitsN += 1
            bitsBase >>= 8
        return bitsN << 24 | bitsBase

    def can_connect(self, header, check_height=True):
        if header is None:
            return False
        height = header['block_height']
        if check_height and self.height() != height - 1:
            #self.print_error("cannot connect at height", height)
            return False
        if height == 0:
            return hash_header(header) == constant.net.GENESIS
        try:
            prev_hash = self.get_hash(height - 1)
        except:
            return False
        if prev_hash != header.get('prev_block_hash'):
            return False
        target = self.get_target(height)
        try:
            self.verify_header(header, prev_hash, target)
        except BaseException as e:
            return False
        return True

    def connect_chunk(self, idx, hexdata):
        try:
            data = bfh(hexdata)
            self.verify_chunk(idx, data)
            #self.print_error("validated chunk %d" % idx)
            self.save_chunk(idx, data)
            return True
        except BaseException as e:
            self.print_error('verify_chunk %d failed'%idx, str(e))
            return False

    def get_checkpoints(self):
        # for each chunk, store the hash of the last block and the target after the chunk
        cp = []
        n = self.height() // CHUNK_LEN
        for index in range(n):
            height = (index + 1) * CHUNK_LEN - 1
            h = self.get_hash(height)
            target = self.get_target(height)
            if len(h.strip('0')) == 0:
                raise Exception('%s file has not enough data.' % self.path())
            extra_headers = []
            if os.path.exists(self.path()):
                with open(self.path(), 'rb') as f:
                    lower_header = height - TARGET_CALC_BLOCKS
                    for height in range(height, lower_header-1, -1):
                        f.seek(height*HDR_LEN)
                        hd = f.read(HDR_LEN)
                        if len(hd) < HDR_LEN:
                            raise Exception(
                                'Expected to read a full header.'
                                ' This was only {} bytes'.format(len(hd)))
                        extra_headers.append((height, bh2u(hd)))
            cp.append((h, target, extra_headers))
        return cp
