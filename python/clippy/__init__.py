
import _clippy
from _clippy import parse, Graph, GraphNode

def graph_iterate(graph):
    '''iterator yielding all nodes of a graph

    nodes arrive in input/definition order, graph circles are avoided.
    '''

    queue = [(graph.first(), frozenset(), 0)]
    while len(queue) > 0:
        node, stop, depth = queue.pop(0)
        yield node, depth

        join = node.join()
        if join is not None:
            queue.insert(0, (join, stop.union(frozenset([node])), depth))
            join = frozenset([join])

        stop = join or stop
        nnext = node.next()
        for n in reversed(nnext):
            if n not in stop and n is not node:
                queue.insert(0, (n, stop, depth + 1))

def dump(graph):
    '''print out clippy.Graph'''

    for i, depth in graph_iterate(graph):
        print('\t%s%s %r' % ('  ' * (depth * 2), i.type, i.text))

def wrdiff(filename, buf):
    '''write buffer to file if contents changed'''

    expl = ''
    if hasattr(buf, 'getvalue'):
        buf = buf.getvalue()
    old = None
    try:    old = open(filename, 'r').read()
    except: pass
    if old == buf:
        # sys.stderr.write('%s unchanged, not written\n' % (filename))
        return
    with open('.new.' + filename, 'w') as out:
        out.write(buf)
    os.rename('.new.' + filename, filename)
