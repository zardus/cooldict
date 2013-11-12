import collections
import itertools

import logging
l = logging.getLogger("cowdict")

class FinalizedError(Exception):
	pass

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
		self.storage.update(self)
		self.backers = [ ]

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
	def __init__(self, d = None):
		d = { } if d is None else d
		if not isinstance(d, FinalizableDict):
			d = FinalizableDict(d)
		self.cowdict = d

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
		return BranchingDict(self.cowdict)

def test():
	import standard_logging; standard_logging
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

	d3[b] = "omg"
	assert d3[b] == "omg"
	assert d2[b] == 'b'

	b3.flatten()
	assert len(b3.backers) == 0
	assert len(b3) == 3

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
