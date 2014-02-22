import collections
import itertools

import logging
l = logging.getLogger("cooldict")

class FinalizedError(Exception):
    pass

class BranchingDictError(Exception):
    pass

import sys
default_max_depth = sys.getrecursionlimit() * 0.2
default_min_depth = 100

# Returns the local storage of the dictionary
def get_storage(d):
    if isinstance(d, FinalizableDict):
        return { }
    elif isinstance(d, BackedDict):
        return d.storage
    elif isinstance(d, CachedDict):
        return d.cache
    elif isinstance(d, BranchingDict):
        return { }
    else:
        return d

# Returns the backers of the dictionary
def get_backers(d):
    if isinstance(d, FinalizableDict):
        return [ d.storage ]
    elif isinstance(d, BackedDict):
        return d.backers
    elif isinstance(d, CachedDict):
        return [ d.backer ]
    elif isinstance(d, BranchingDict):
        return [ d.cowdict ]
    else:
        return [ ]

# Returns the ancestry of this dict, back to the first dict that we don't recognize
# or that has more than one backer.
def ancestry_line(d):
    b = get_backers(d)

    while len(b) == 1:
        yield b[0]
        b = get_backers(b[0])

############################
### The dicts themselves ###
############################

class CachedDict(collections.MutableMapping):
    ''' Implements a write-through cache around another dict. '''
    def __init__(self, backer, cacher = None):
        self.backer = backer
        self.cache = { }
        self.cacher = cacher if cacher else self.default_cacher

    def default_cacher(self, k):
        v = self.backer[k]
        self.cache[k] = v
        return v

    def __getitem__(self, k):
        try:
            return self.cache[k]
        except KeyError:
            return self.cacher(k)

    def __setitem__(self, k, v):
        self.cache[k] = v
        self.backer[k] = v

    def __delitem__(self, k):
        self.cache.pop(k, None)
        self.backer.pop(k, None)

    def __iter__(self):
        return self.backer.__iter__()

    def __len__(self):
        return len(list(self.__iter__()))

class BackedDict(collections.MutableMapping):
    ''' Implements a mapping that's backed by other mappings. '''
    def __init__(self, *backers, **kwargs):
        self.backers = backers
        self.storage = { } if 'storage' not in kwargs else kwargs['storage']
        self.deleted = set()

    def __getitem__(self, a):
        # make sure we haven't deleted it
        if a in self.deleted:
            raise KeyError(a)

        # return it if we have it in storage
        if a in self.storage:
            return self.storage[a]

        # try the backers
        for p in self.backers:
            try:
                return p[a]
            except KeyError:
                pass

        # panic!
        raise KeyError(a)

    def __delitem__(self, a):
        # make sure we can do it
        if a not in self:
            raise KeyError(a)

        # and do it
        self.storage.pop(a, None)
        self.deleted.add(a)

    def __setitem__(self, k, v):
        self.deleted.discard(k)
        self.storage[k] = v

    def __iter__(self):
        chain = itertools.chain(self.storage, *[ p for p in self.backers ])
        seen = set()
        for k in chain:
            if k not in self.deleted and k not in seen:
                seen.add(k)
                yield k

    def __len__(self):
        return len(list(self.__iter__()))

    def flatten(self):
        l.info("Flattening backers of %s!", self)
        if len(self.backers) > 1:
            l.debug("Slow path")

            s_keys = set(self.storage.keys())
            for b in reversed(self.backers):
                b_keys = set(b.keys())
                for i in b_keys - s_keys:
                    self.storage[i] = b[i]
            self.backers = [ ]
        else:
            a_line = list(ancestry_line(self))
            ancestors = [ get_storage(a) for a in a_line ]
            ancestor_keys = [ set(a.keys()) for a in ancestors ]
            remaining = set()
            new_backers = [ ]

            try:
                #print "Checking for ignores"
                ignored_idx = [ getattr(a, 'cooldict_ignore', False) for a in a_line ].index(True)
                #print "... found at",ignored_idx
                new_backers = [ a_line[ignored_idx] ]
                ancestors = ancestors[:ignored_idx]
                ancestor_keys = ancestor_keys[:ignored_idx]
            except ValueError:
                #print "... not found"
                pass

            #print "ancestors:",ancestors
            #print "new ancestors:",ancestors

            for a in reversed(ancestors):
                keys = set(get_storage(a).iterkeys())
                ancestor_keys.append(keys)
                remaining |= keys
                if isinstance(a, BackedDict):
                    remaining -= a.deleted

            remaining -= set(self.storage.iterkeys())
            remaining -= self.deleted

            for a,keys in zip(ancestors, ancestor_keys):
                toadd = keys & remaining
                if len(toadd) == 0:
                    continue
                l.debug("Adding %d keys from %s", len(toadd), a)
                for k in toadd:
                    self.storage[k] = a[k]
                remaining -= keys

            if len(remaining) != 0:
                raise Exception("%d items remaining after flatten!", len(remaining))
            self.backers = new_backers

class FinalizableDict(collections.MutableMapping):
    ''' Implements a finalizable dict. This is meant to support BranchingDict, and offers no guarantee about the actual immutability of the underlying data. It's quite easy to bypass. You've been warned. '''
    def __init__(self, storage = None):
        self.finalized = False
        self.storage = { } if storage is None else storage

    def __getitem__(self, a):
        return self.storage[a]

    def __delitem__(self, a):
        if self.finalized:
            raise FinalizedError("dict is finalized")
        del self.storage[a]

    def __setitem__(self, k, v):
        if self.finalized:
            raise FinalizedError("dict is finalized")
        self.storage[k] = v

    def __iter__(self):
        return self.storage.__iter__()

    def __len__(self):
        return self.storage.__len__()

    def finalize(self):
        self.finalized = True

class BranchingDict(collections.MutableMapping):
    ''' This implements a branching dictionary. Basically, a BranchingDict can be branch()ed and the two copies will thereafter share a common backer, but will not write back to that backer. Can probably be reimplemented without FinalizableDict. '''
    def __init__(self, d = None, max_depth = None, min_depth = None):
        max_depth = default_max_depth if max_depth is None else max_depth
        min_depth = default_min_depth if min_depth is None else min_depth

        d = { } if d is None else d
        if not isinstance(d, FinalizableDict):
            d = FinalizableDict(d)
        self.cowdict = d

        ancestors = list(self.ancestry_line())
        if len(ancestors) > max_depth:
            l.debug("BranchingDict got too deep (%d)", len(ancestors))
            new_dictriarch = None
            for k in ancestors[min_depth:]:
                if isinstance(k, BackedDict):
                    new_dictriarch = k
                    break
            if new_dictriarch is not None:
                l.debug("Found ancestor %s", new_dictriarch)
                new_dictriarch.flatten()

        self.max_depth = max_depth
        self.min_depth = min_depth

    # Returns the ancestry of this dict, back to the first dict that we don't recognize
    # or that has more than one backer.
    def ancestry_line(self):
        return ancestry_line(self)

    # Returns the common ancestor between self and other.
    def common_ancestor(self, other):
        our_line = set([ id(a) for a in self.ancestry_line() ])
        for d in other.ancestry_line():
            if id(d) in our_line:
                return d
        return None

    # Returns the entries created and the entries deleted since the specified ancestor.
    def changes_since(self, ancestor):
        created = set()
        deleted = set()

        for a in self.ancestry_line():
            if a is ancestor:
                break
            elif isinstance(a, FinalizableDict):
                continue
            elif isinstance(a, BackedDict):
                created.update(set(a.storage.keys()) - deleted)
                deleted.update(a.deleted - created)
            elif isinstance(a, dict):
                created.update(a.keys())

        return created, deleted

    def __getitem__(self, a):
        return self.cowdict[a]

    def __setitem__(self, k, v):
        if self.cowdict.finalized:
            l.debug("Got a finalized dict. Making a child.")
            self.cowdict = FinalizableDict(BackedDict(self.cowdict))
        self.cowdict[k] = v

    def __delitem__(self, k):
        if self.cowdict.finalized:
            l.debug("Got a finalized dict. Making a child.")
            self.cowdict = FinalizableDict(BackedDict(self.cowdict))
        del self.cowdict[k]

    def __iter__(self):
        return self.cowdict.__iter__()

    def __len__(self):
        return self.cowdict.__len__()

    def branch(self):
        self.cowdict.finalize()
        return BranchingDict(self.cowdict, max_depth=self.max_depth, min_depth=self.min_depth)

def test():
    try:
        import standard_logging # pylint: disable=W0612,
    except ImportError:
        pass

    l.setLevel(logging.DEBUG)

    a = "aa"
    b = "bb"
    c = "cc"
    d = "dd"
    one = 11
    two = 12
    three = 13

    b1 = BackedDict()
    b2 = BackedDict()

    b1[a] = 'a'
    b1[one] = 1
    b2[b] = 'b'

    assert len(b1) == 2
    assert len(b2) == 1
    assert b1[a] == 'a'
    assert b1[one] == 1
    assert b2[b] == 'b'

    b3 = BackedDict(b1, b2)
    b3[c] = c
    assert len(b3) == 4
    assert b3[a] == 'a'
    assert b3[one] == 1
    assert b3[b] == 'b'
    assert b3[c] == c
    assert len(b1) == 2
    assert len(b2) == 1
    assert b1[a] == 'a'
    assert b1[one] == 1
    assert b2[b] == 'b'

    del b3[a]
    assert len(b3) == 3 
    d1 = BranchingDict(b3)
    d2 = d1.branch()
    d3 = d2.branch()

    d1[d] = d
    assert len(b3) == 3
    assert len(d1) == 4
    assert len(d2) == 3
    assert len(d3) == 3
    assert d1[d] == d
    assert d1[b] == 'b'
    assert d1[one] == 1

    b3.flatten()
    assert len(b3.backers) == 0
    assert len(b3) == 3

    d3[b] = "omg"
    assert d3[b] == "omg"
    assert d2[b] == 'b'

    d4 = d3.branch()
    del d4[b]
    del d4[c]

    d5 = d4.branch()
    d5['hmm'] = 5
    d6 = d5.branch()

    assert len(list(d5.ancestry_line())) == 8
    dnew = d5.branch()
    dnew['ohsnap'] = 1
    for _ in range(99):
        dnew = dnew.branch()
        dnew['ohsnap'] += 1
    assert len(list(dnew.ancestry_line())) == 108

    for _ in range(8000):
        print "Branching dict number", _
        dnew = dnew.branch()
        dnew['ohsnap'] += 1
    assert len(list(dnew.ancestry_line())) == 108

    common = d4.common_ancestor(d2)
    changed, deleted = d4.changes_since(common)
    assert len(changed) == 0
    assert len(deleted) == 2

    changed, deleted = d6.changes_since(common)
    assert len(changed) == 1
    assert len(deleted) == 2

    b0 = { }
    b4 = BackedDict(storage=b0)
    b4[one] = 'one'
    assert len(b0) == 1
    assert b0[one] == 'one'
    assert len(b4) == 1
    assert b4[one] == 'one'

    b5 = CachedDict(BackedDict(b4))
    assert len(b5) == 1
    assert len(b5.cache) == 0
    assert b5[one] == 'one'
    assert len(b5.cache) == 1
    assert len(b5) == 1
    assert len(b4) == 1
    b5[two] = 2
    assert len(b5) == 2

    b6 = BackedDict({three: 3})
    b6[three] = 3
    assert len(b6) == 1

if __name__ == "__main__":
    test()
