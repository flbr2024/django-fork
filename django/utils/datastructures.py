import copy
import warnings
from collections import OrderedDict

from django.utils import six
from django.utils.deprecation import RemovedInDjango19Warning


class MergeDict(object):
    """
    A simple class for creating new "virtual" dictionaries that actually look
    up values in more than one dictionary, passed in the constructor.

    If a key appears in more than one of the given dictionaries, only the
    first occurrence will be used.
    """
    def __init__(self, *dicts):
        warnings.warn('`MergeDict` is deprecated, use `dict.update()` '
                      'instead.', RemovedInDjango19Warning, 2)
        self.dicts = dicts

    def __bool__(self):
        return any(self.dicts)

    def __nonzero__(self):
        return type(self).__bool__(self)

    def __getitem__(self, key):
        for dict_ in self.dicts:
            try:
                return dict_[key]
            except KeyError:
                pass
        raise KeyError(key)

    def __copy__(self):
        return self.__class__(*self.dicts)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    # This is used by MergeDicts of MultiValueDicts.
    def getlist(self, key):
        for dict_ in self.dicts:
            if key in dict_:
                return dict_.getlist(key)
        return []

    def _iteritems(self):
        seen = set()
        for dict_ in self.dicts:
            for item in six.iteritems(dict_):
                k = item[0]
                if k in seen:
                    continue
                seen.add(k)
                yield item

    def _iterkeys(self):
        for k, v in self._iteritems():
            yield k

    def _itervalues(self):
        for k, v in self._iteritems():
            yield v

    if six.PY3:
        items = _iteritems
        keys = _iterkeys
        values = _itervalues
    else:
        iteritems = _iteritems
        iterkeys = _iterkeys
        itervalues = _itervalues

        def items(self):
            return list(self.iteritems())

        def keys(self):
            return list(self.iterkeys())

        def values(self):
            return list(self.itervalues())

    def has_key(self, key):
        for dict_ in self.dicts:
            if key in dict_:
                return True
        return False

    __contains__ = has_key

    __iter__ = _iterkeys

    def copy(self):
        """Returns a copy of this object."""
        return self.__copy__()

    def __str__(self):
        '''
        Returns something like

            "{'key1': 'val1', 'key2': 'val2', 'key3': 'val3'}"

        instead of the generic "<object meta-data>" inherited from object.
        '''
        return str(dict(self.items()))

    def __repr__(self):
        '''
        Returns something like

            MergeDict({'key1': 'val1', 'key2': 'val2'}, {'key3': 'val3'})

        instead of generic "<object meta-data>" inherited from object.
        '''
        dictreprs = ', '.join(repr(d) for d in self.dicts)
        return '%s(%s)' % (self.__class__.__name__, dictreprs)


class SortedDict(dict):
    """
    A dictionary that keeps its keys in the order in which they're inserted.
    """
    def __new__(cls, *args, **kwargs):
        instance = super(SortedDict, cls).__new__(cls, *args, **kwargs)
        instance.keyOrder = []
        return instance

    def __init__(self, data=None):
        warnings.warn(
            "SortedDict is deprecated and will be removed in Django 1.9.",
            RemovedInDjango19Warning, stacklevel=2
        )
        if data is None or isinstance(data, dict):
            data = data or []
            super(SortedDict, self).__init__(data)
            self.keyOrder = list(data) if data else []
        else:
            super(SortedDict, self).__init__()
            super_set = super(SortedDict, self).__setitem__
            for key, value in data:
                # Take the ordering from first key
                if key not in self:
                    self.keyOrder.append(key)
                # But override with last value in data (dict() does this)
                super_set(key, value)

    def __deepcopy__(self, memo):
        return self.__class__([(key, copy.deepcopy(value, memo))
                               for key, value in self.items()])

    def __copy__(self):
        # The Python's default copy implementation will alter the state
        # of self. The reason for this seems complex but is likely related to
        # subclassing dict.
        return self.copy()

    def __setitem__(self, key, value):
        if key not in self:
            self.keyOrder.append(key)
        super(SortedDict, self).__setitem__(key, value)

    def __delitem__(self, key):
        super(SortedDict, self).__delitem__(key)
        self.keyOrder.remove(key)

    def __iter__(self):
        return iter(self.keyOrder)

    def __reversed__(self):
        return reversed(self.keyOrder)

    def pop(self, k, *args):
        result = super(SortedDict, self).pop(k, *args)
        try:
            self.keyOrder.remove(k)
        except ValueError:
            # Key wasn't in the dictionary in the first place. No problem.
            pass
        return result

    def popitem(self):
        result = super(SortedDict, self).popitem()
        self.keyOrder.remove(result[0])
        return result

    def _iteritems(self):
        for key in self.keyOrder:
            yield key, self[key]

    def _iterkeys(self):
        for key in self.keyOrder:
            yield key

    def _itervalues(self):
        for key in self.keyOrder:
            yield self[key]

    if six.PY3:
        items = _iteritems
        keys = _iterkeys
        values = _itervalues
    else:
        iteritems = _iteritems
        iterkeys = _iterkeys
        itervalues = _itervalues

        def items(self):
            return [(k, self[k]) for k in self.keyOrder]

        def keys(self):
            return self.keyOrder[:]

        def values(self):
            return [self[k] for k in self.keyOrder]

    def update(self, dict_):
        for k, v in six.iteritems(dict_):
            self[k] = v

    def setdefault(self, key, default):
        if key not in self:
            self.keyOrder.append(key)
        return super(SortedDict, self).setdefault(key, default)

    def copy(self):
        """Returns a copy of this object."""
        # This way of initializing the copy means it works for subclasses, too.
        return self.__class__(self)

    def __repr__(self):
        """
        Replaces the normal dict.__repr__ with a version that returns the keys
        in their sorted order.
        """
        return '{%s}' % ', '.join('%r: %r' % (k, v) for k, v in six.iteritems(self))

    def clear(self):
        super(SortedDict, self).clear()
        self.keyOrder = []


def dict_merge(a, b):
    """
    Utility to recursively merge two dicts, taking care not to overwrite subkeys
    (which would happen with dict.update), but keeping existing key including
    those from subdictionaries (optionnaly opted-out if a `_clear_defaults` key
    is present).
    Thanks Ross McFarland (https://www.xormedia.com/recursively-merge-dictionaries-in-python/)
    """
    if b.get('_clear_defaults'):
        return copy.deepcopy(b)

    result = copy.deepcopy(a)
    for key, value in six.iteritems(b):
        if key in a and isinstance(result[key], dict):
            result[key] = dict_merge(result[key], value)
        else:
            result[key] = value
    return result


class OrderedSet(object):
    """
    A set which keeps the ordering of the inserted items.
    Currently backs onto OrderedDict.
    """

    def __init__(self, iterable=None):
        self.dict = OrderedDict(((x, None) for x in iterable) if iterable else [])

    def add(self, item):
        self.dict[item] = None

    def remove(self, item):
        del self.dict[item]

    def discard(self, item):
        try:
            self.remove(item)
        except KeyError:
            pass

    def __iter__(self):
        return iter(self.dict.keys())

    def __contains__(self, item):
        return item in self.dict

    def __nonzero__(self):
        return bool(self.dict)


class MultiValueDictKeyError(KeyError):
    pass


class MultiValueDict(dict):
    """
    A subclass of dictionary customized to handle multiple values for the
    same key.

    >>> d = MultiValueDict({'name': ['Adrian', 'Simon'], 'position': ['Developer']})
    >>> d['name']
    'Simon'
    >>> d.getlist('name')
    ['Adrian', 'Simon']
    >>> d.getlist('doesnotexist')
    []
    >>> d.getlist('doesnotexist', ['Adrian', 'Simon'])
    ['Adrian', 'Simon']
    >>> d.get('lastname', 'nonexistent')
    'nonexistent'
    >>> d.setlist('lastname', ['Holovaty', 'Willison'])

    This class exists to solve the irritating problem raised by cgi.parse_qs,
    which returns a list for every key, even though most Web forms submit
    single name-value pairs.
    """
    def __init__(self, key_to_list_mapping=()):
        super(MultiValueDict, self).__init__(key_to_list_mapping)

    def __repr__(self):
        return "<%s: %s>" % (self.__class__.__name__,
                             super(MultiValueDict, self).__repr__())

    def __getitem__(self, key):
        """
        Returns the last data value for this key, or [] if it's an empty list;
        raises KeyError if not found.
        """
        try:
            list_ = super(MultiValueDict, self).__getitem__(key)
        except KeyError:
            raise MultiValueDictKeyError(repr(key))
        try:
            return list_[-1]
        except IndexError:
            return []

    def __setitem__(self, key, value):
        super(MultiValueDict, self).__setitem__(key, [value])

    def __copy__(self):
        return self.__class__([
            (k, v[:])
            for k, v in self.lists()
        ])

    def __deepcopy__(self, memo=None):
        if memo is None:
            memo = {}
        result = self.__class__()
        memo[id(self)] = result
        for key, value in dict.items(self):
            dict.__setitem__(result, copy.deepcopy(key, memo),
                             copy.deepcopy(value, memo))
        return result

    def __getstate__(self):
        obj_dict = self.__dict__.copy()
        obj_dict['_data'] = dict((k, self.getlist(k)) for k in self)
        return obj_dict

    def __setstate__(self, obj_dict):
        data = obj_dict.pop('_data', {})
        for k, v in data.items():
            self.setlist(k, v)
        self.__dict__.update(obj_dict)

    def get(self, key, default=None):
        """
        Returns the last data value for the passed key. If key doesn't exist
        or value is an empty list, then default is returned.
        """
        try:
            val = self[key]
        except KeyError:
            return default
        if val == []:
            return default
        return val

    def getlist(self, key, default=None):
        """
        Returns the list of values for the passed key. If key doesn't exist,
        then a default value is returned.
        """
        try:
            return super(MultiValueDict, self).__getitem__(key)
        except KeyError:
            if default is None:
                return []
            return default

    def setlist(self, key, list_):
        super(MultiValueDict, self).__setitem__(key, list_)

    def setdefault(self, key, default=None):
        if key not in self:
            self[key] = default
            # Do not return default here because __setitem__() may store
            # another value -- QueryDict.__setitem__() does. Look it up.
        return self[key]

    def setlistdefault(self, key, default_list=None):
        if key not in self:
            if default_list is None:
                default_list = []
            self.setlist(key, default_list)
            # Do not return default_list here because setlist() may store
            # another value -- QueryDict.setlist() does. Look it up.
        return self.getlist(key)

    def appendlist(self, key, value):
        """Appends an item to the internal list associated with key."""
        self.setlistdefault(key).append(value)

    def _iteritems(self):
        """
        Yields (key, value) pairs, where value is the last item in the list
        associated with the key.
        """
        for key in self:
            yield key, self[key]

    def _iterlists(self):
        """Yields (key, list) pairs."""
        return six.iteritems(super(MultiValueDict, self))

    def _itervalues(self):
        """Yield the last value on every key list."""
        for key in self:
            yield self[key]

    if six.PY3:
        items = _iteritems
        lists = _iterlists
        values = _itervalues
    else:
        iteritems = _iteritems
        iterlists = _iterlists
        itervalues = _itervalues

        def items(self):
            return list(self.iteritems())

        def lists(self):
            return list(self.iterlists())

        def values(self):
            return list(self.itervalues())

    def copy(self):
        """Returns a shallow copy of this object."""
        return copy.copy(self)

    def update(self, *args, **kwargs):
        """
        update() extends rather than replaces existing key lists.
        Also accepts keyword args.
        """
        if len(args) > 1:
            raise TypeError("update expected at most 1 arguments, got %d" % len(args))
        if args:
            other_dict = args[0]
            if isinstance(other_dict, MultiValueDict):
                for key, value_list in other_dict.lists():
                    self.setlistdefault(key).extend(value_list)
            else:
                try:
                    for key, value in other_dict.items():
                        self.setlistdefault(key).append(value)
                except TypeError:
                    raise ValueError("MultiValueDict.update() takes either a MultiValueDict or dictionary")
        for key, value in six.iteritems(kwargs):
            self.setlistdefault(key).append(value)

    def dict(self):
        """
        Returns current object as a dict with singular values.
        """
        return dict((key, self[key]) for key in self)


class ImmutableList(tuple):
    """
    A tuple-like object that raises useful errors when it is asked to mutate.

    Example::

        >>> a = ImmutableList(range(5), warning="You cannot mutate this.")
        >>> a[3] = '4'
        Traceback (most recent call last):
            ...
        AttributeError: You cannot mutate this.
    """

    def __new__(cls, *args, **kwargs):
        if 'warning' in kwargs:
            warning = kwargs['warning']
            del kwargs['warning']
        else:
            warning = 'ImmutableList object is immutable.'
        self = tuple.__new__(cls, *args, **kwargs)
        self.warning = warning
        return self

    def complain(self, *wargs, **kwargs):
        if isinstance(self.warning, Exception):
            raise self.warning
        else:
            raise AttributeError(self.warning)

    # All list mutation functions complain.
    __delitem__ = complain
    __delslice__ = complain
    __iadd__ = complain
    __imul__ = complain
    __setitem__ = complain
    __setslice__ = complain
    append = complain
    extend = complain
    insert = complain
    pop = complain
    remove = complain
    sort = complain
    reverse = complain


class DictWrapper(dict):
    """
    Wraps accesses to a dictionary so that certain values (those starting with
    the specified prefix) are passed through a function before being returned.
    The prefix is removed before looking up the real value.

    Used by the SQL construction code to ensure that values are correctly
    quoted before being used.
    """
    def __init__(self, data, func, prefix):
        super(DictWrapper, self).__init__(data)
        self.func = func
        self.prefix = prefix

    def __getitem__(self, key):
        """
        Retrieves the real value after stripping the prefix string (if
        present). If the prefix is present, pass the value through self.func
        before returning, otherwise return the raw value.
        """
        if key.startswith(self.prefix):
            use_func = True
            key = key[len(self.prefix):]
        else:
            use_func = False
        value = super(DictWrapper, self).__getitem__(key)
        if use_func:
            return self.func(value)
        return value
