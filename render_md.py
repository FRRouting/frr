#!/usr/bin/env python
# written 2016 by David Lamparter, placed in Public Domain.
import sys, markdown

template = '''<html><head><meta charset="UTF-8"><style type="text/css">
body { max-width: 45em; margin: auto; margin-top: 2em; margin-bottom: 2em;
    font-family:Fira Sans,sans-serif; text-align: justify;
    counter-reset: ch2; }
pre, code { font-family:Fira Mono,monospace; }
pre > code { display: block; padding:0.5em; border:1px solid black;
    background-color:#eee; color:#000; }
h2:before { content: counter(ch2) ". "; counter-increment: ch2; }
h2 { clear: both; margin-top: 3em; text-decoration: underline; counter-reset: ch3; }
h3:before { content: counter(ch2) "." counter(ch3) ". "; counter-increment: ch3; }
h3 { clear: both; margin-top: 2em; font-weight: normal; font-style: italic; }
h4 { font-weight: normal; font-style: italic; }
img[alt~="float-right"] { float:right; margin-left:2em; margin-bottom:2em; }
</style></head><body>
%s
</body></html>
'''

md = markdown.Markdown(extensions=['extra', 'toc'])

for fn in sys.argv[1:]:
    with open(fn, 'r') as ifd:
        with open('%s.html' % (fn), 'w') as ofd:
            ofd.write((template % (md.convert(ifd.read().decode('UTF-8')))).encode('UTF-8'))
