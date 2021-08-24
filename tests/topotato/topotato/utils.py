import re, json, difflib, os
from typing import Dict

wsp_re = re.compile(r'^[ \t]+')
def deindent(text):
    text = text.lstrip('\n')
    m = wsp_re.match(text)
    if m is not None:
        indent = m.group(0)
        out = []
        for line in text.splitlines():
            if line.strip() == '':
                out.append('')
            else:
                assert line.startswith(indent)
                out.append(line[len(indent):])
        text = '\n'.join(out)
    return text

def get_textdiff(text1, text2, title1="", title2="", **opts):
    "Returns empty string if same or formatted diff"

    diff = '\n'.join(difflib.unified_diff(text1, text2,
           fromfile=title1, tofile=title2, **opts))
    # Clean up line endings
    diff = os.linesep.join([s for s in diff.splitlines() if s])
    return diff

def difflines(text1, text2, title1='', title2='', **opts):
    "Wrapper for get_textdiff to avoid string transformations."
    text1 = ('\n'.join(text1.rstrip().splitlines()) + '\n').splitlines(1)
    text2 = ('\n'.join(text2.rstrip().splitlines()) + '\n').splitlines(1)
    return get_textdiff(text1, text2, title1, title2, **opts)

class json_cmp_result(object):
    "json_cmp result class for better assertion messages"

    def __init__(self):
        self.errors = []

    def add_error(self, error):
        "Append error message to the result"
        for line in error.splitlines():
            self.errors.append(line)

    def has_errors(self):
        "Returns True if there were errors, otherwise False."
        return len(self.errors) > 0

    def __str__(self):
        return '\n'.join(self.errors)

# used with an "is" comparison
class JSONCompareDirective(dict):
    pass
class JSONCompareIgnoreContent(JSONCompareDirective):
    pass
class JSONCompareIgnoreExtraListitems(JSONCompareDirective):
    pass
class JSONCompareListKeyedDict(JSONCompareDirective):
    def __init__(self, *keys):
        self.keys = keys

json_ignore_content: Dict[None, None] = JSONCompareIgnoreContent()
json_ignore_extra_listitems = JSONCompareIgnoreExtraListitems()

def json_diff(d1, d2):
    """
    Returns a string with the difference between JSON data.
    """
    json_format_opts = {
        'indent': 4,
        'sort_keys': True,
    }
    dstr1 = json.dumps(d1, **json_format_opts)
    dstr2 = json.dumps(d2, **json_format_opts)
    return difflines(dstr2, dstr1, title1='Expected value', title2='Current value', n=0)


def _json_list_cmp(list1, list2, parent, result):
    "Handles list type entries."
    if isinstance(list1, JSONCompareIgnoreContent) or isinstance(list2, JSONCompareIgnoreContent):
        return

    # Check second list2 type
    if not isinstance(list1, type([])) or not isinstance(list2, type([])):
        result.add_error(
            '{} has different type than expected '.format(parent) +
            '(have {}, expected {}):\n{}'.format(
                type(list1), type(list2), json_diff(list1, list2)))
        return

    flags = [{}, {}]
    for i, l in [(0, list1), (1, list2)]:
        while l and isinstance(l[0], JSONCompareDirective):
            item = l.pop(0)
            flags[i][type(item)] = item

    # flags should only be in list2 for the time being
    assert not flags[0]

    # Check list size
    if len(list2) > len(list1):
        # and JSONCompareIgnoreExtraListitems not in flags[0]:
        result.add_error(
            '{} too few items '.format(parent) +
            '(have {}, expected {}:\n {})'.format(
                len(list1), len(list2),
                json_diff(list1, list2)))
        return

    # List all unmatched items errors
    if JSONCompareListKeyedDict in flags[1]:
        keys = flags[1][JSONCompareListKeyedDict].keys
        for expected in list2:
            assert isinstance(expected, dict)

            keymatch = []
            for value in list1:
                if not isinstance(value, dict):
                    continue
                for key in keys:
                    if key not in expected:
                        continue
                    if json_cmp({ "_": value.get(key) }, { "_": expected[key] }) is not None:
                        break
                else:
                    keymatch.append(value)

            keylabel = ','.join(['%s=%r' % (key, expected.get(key)) for key in keys])
            if not keymatch:
                result.add_error("no item found for %s" % (keylabel))
            elif len(keymatch) > 1:
                result.add_error("multiple items found for %s" % (keylabel))
            else:
                res = json_cmp(keymatch[0], expected)
                if res is not None:
                    result.add_error(
                        '{} value for key {} is different (\n  {})'.format(
                            parent, keylabel, str(res).replace('\n', '\n  ')))
    else:
        #unmatched = []
        for expected in list2:
            best_err = None
            for value in list1:
                res = json_cmp({'json': value}, {'json': expected})
                if res is None:
                    break
                if best_err is None or len(str(res)) < len(str(best_err)):
                    best_err = res
            else:
                result.add_error(
                    '{} list value is different (\n  {})'.format(
                        parent, str(best_err).replace('\n', '\n  ')))

        # If there are unmatched items, error out.
        #if unmatched:
        #    result.add_error(
        #        '{} list value is different (\n{})'.format(
        #            parent, json_diff(list1, list2)))


def json_cmp(d1, d2):
    """
    JSON compare function. Receives two parameters:
    * `d1`: json value
    * `d2`: json subset which we expect

    Returns `None` when all keys that `d1` has matches `d2`,
    otherwise a string containing what failed.

    Note: key absence can be tested by adding a key with value `None`.
    """
    squeue = [(d1, d2, 'json')]
    result = json_cmp_result()

    for s in squeue:
        nd1, nd2, parent = s

        # Handle JSON beginning with lists.
        if isinstance(nd1, type([])) or isinstance(nd2, type([])):
            _json_list_cmp(nd1, nd2, parent, result)
            if result.has_errors():
                return result
            else:
                return None

        # Expect all required fields to exist.
        s1, s2 = set(nd1), set(nd2)
        s2_req = set([key for key in nd2 if nd2[key] is not None])
        diff = s2_req - s1
        if diff != set({}):
            result.add_error('expected key(s) {} in {} (have {}):\n{}'.format(
                str(list(diff)), parent, str(list(s1)), json_diff(nd1, nd2)))

        for key in s2.intersection(s1):
            # Test for non existence of key in d2
            if nd2[key] is None:
                result.add_error('"{}" should not exist in {} (have {}):\n{}'.format(
                    key, parent, str(s1), json_diff(nd1[key], nd2[key])))
                continue

            if nd2[key] is json_ignore_content or nd1[key] is json_ignore_content:
                continue

             # If nd1 key is a dict, we have to recurse in it later.
            if isinstance(nd2[key], type({})):
                if not isinstance(nd1[key], type({})):
                    result.add_error(
                        '{}["{}"] has different type than expected '.format(parent, key) +
                        '(have {}, expected {}):\n{}'.format(
                            type(nd1[key]), type(nd2[key]), json_diff(nd1[key], nd2[key])))
                    continue
                nparent = '{}["{}"]'.format(parent, key)
                squeue.append((nd1[key], nd2[key], nparent))
                continue

            # Check list items
            if isinstance(nd2[key], type([])):
                _json_list_cmp(nd1[key], nd2[key], parent, result)
                continue

            # Compare JSON values
            if nd1[key] != nd2[key]:
                result.add_error(
                    '{}["{}"] dict value is different (\n{})'.format(
                        parent, key, json_diff(nd1[key], nd2[key])))
                continue

    if result.has_errors():
        return result

    return None
