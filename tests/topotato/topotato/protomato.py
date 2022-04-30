import sys
import subprocess
import pprint
import time
from lxml import etree
from py.xml import html
from collections import OrderedDict
from .base import TimedElement

class fmt(html):
    """custom styling"""

    class _cssclass:
        def __init__(self, *args, **kwargs):
            if getattr(self, 'class_', None) is not None:
                kwargs.setdefault('class_', self.class_)
            super().__init__(*args, **kwargs)

    class packets(_cssclass, html.div):
        class_ = 'packets'

    class packet(_cssclass, html.div):
        class_ = 'pkt'

    class tstamp(_cssclass, html.span):
        class_ = 'pktcol tstamp'
    class iface(_cssclass, html.span):
        class_ = 'pktcol ifname'

    class raw_line(_cssclass, html.div):
        class_ = 'r_line'
    class raw_line_cont(_cssclass, html.span):
        class_ = 'r_cont e_cont'
    class raw_sub(_cssclass, html.span):
        class_ = 'r_sub e_hide'

    class span_detail(_cssclass, html.div):
        class_ = 'e_raw e_hide'
        def __init__(self):
            super().__init__()
            self.attr.ondblclick = 'expandall(this, event);'
            self.attr.onclick = 'event.stopPropagation();'

    class span_expand(_cssclass, html.span):
        class_ = 'e_exp'

        def __init__(self):
            super().__init__()
            self.attr.onclick = 'raw_expand(this, event);'

    class span_proto(html.span):
        def make_repr(self, data, indent=''):
            for keyidx, item in data.items():
                key, idx = keyidx
                if idx or key == '' or (key, 1) in data:
                    itm = '%s#%d' % (key, idx)
                else:
                    itm = key

                if not len(item):
                    yield fmt.raw_line(('%s%s: %s' % (
                        indent, itm, item.val)).rstrip(),
                            title=item.desc)
                else:
                    rc = fmt.raw_line_cont()
                    rl = fmt.raw_line(('%s%s: %s' % (
                        indent, itm, item.val)).rstrip(),
                            title=item.desc, onclick='raw_expand(this, event);')
                    rsub = fmt.raw_sub()

                    for sub in self.make_repr(item, indent+'  '):
                        rsub.append(sub)
                    rc.append(rl)
                    rc.append(rsub)
                    yield rc

        def add_raw(self, raw):
            # disabled
            return

            self.append(fmt.span_expand())
            #text = []
            #for keyidx, item in raw.items():
            #    key, idx = keyidx
            #    if idx or (key, 1) in raw:
            #        itm = '%s#%d' % (key, idx)
            #    else:
            #        itm = key
            #
            #    text.append('%s: %s' % (itm, item.val))
            #    if len(item):
            #        text.append(' + %d' % (len(item)))
            #self.append(fmt.span_detail('\n'.join(text)))
            detail = fmt.span_detail()
            detail.extend(self.make_repr(raw))
            self.append(detail)
            self.attr.class_ = self.attr.class_ + ' e_cont'

    class unknown(_cssclass, span_proto):
        class_ = 'pktcol p-unkn'

    class eth(_cssclass, span_proto):
        class_ = 'pktcol p-eth'
    class eth_src(_cssclass, html.span):
        class_ = 'pktsub p-eth-src'
    class eth_arr(_cssclass, html.span):
        class_ = 'pktsub p-eth-arr'
    class eth_dst(_cssclass, html.span):
        class_ = 'pktsub p-eth-dst'

    class ipv4(_cssclass, span_proto):
        class_ = 'pktcol l-3 p-ipv4'

    class ipv6(_cssclass, span_proto):
        class_ = 'pktcol l-3 p-ipv6'

    class arp(_cssclass, span_proto):
        class_ = 'pktcol l-3 p-arp'

    class tcp(_cssclass, span_proto):
        class_ = 'pktcol l-4 p-tcp'
    class udp(_cssclass, span_proto):
        class_ = 'pktcol l-4 p-udp'
    class icmp(_cssclass, span_proto):
        class_ = 'pktcol l-4 p-icmp'
    class icmpv6(_cssclass, span_proto):
        class_ = 'pktcol l-4 p-icmpv6'
    class l4detail(_cssclass, span_proto):
        class_ = 'pktcol l-5 detail'

    class pim(_cssclass, span_proto):
        class_ = 'pktcol l-4 p-pim'
    class ldp(_cssclass, span_proto):
        class_ = 'pktcol l-5 p-ldp'
    class bgp(_cssclass, span_proto):
        class_ = 'pktcol l-5 p-bgp'
    class bfd(_cssclass, span_proto):
        class_ = 'pktcol l-5 p-bfd'
    class ospf(_cssclass, span_proto):
        class_ = 'pktcol l-4 p-ospf'

    class assertmatchitem(_cssclass, html.div):
        class_ = 'assert-match-item'


class ProtomatoPacket(TimedElement, fmt.packet):
    def __init__(self, packets, pdmlpkt):
        super().__init__()

        self.packets = packets
        self.pdmlpkt = pdmlpkt
        self._ts = pdmlpkt.ts

        self.attr.pdml_frame = pdmlpkt['frame']['frame.number'].val

        for key, items in pdmlpkt.items():
            proto, i = key
            if proto in ['geninfo', 'fake-field-wrapper']:
                continue

            handler = getattr(self, 'handle_%s' % proto, None)

            if handler is None:
                if proto in ['tls', 'data', 'ssh']:
                    continue

                obj = fmt.unknown(proto)
                obj.add_raw(items)
                self.append(obj)
                continue

            curlen = len(self)
            handler(proto, items, pdmlpkt, self)
            for obj in self[curlen:]:
                if isinstance(obj, fmt.span_proto):
                    obj.add_raw(items)
                    break

    def __repr__(self):
        return '<%s @%f %s %s>' % (self.__class__.__name__, self._ts,
                self.pdmlpkt["frame/.interface_id/frame.interface_name"].val,
                ':'.join([i for i, _ in self.pdmlpkt.keys()]))

    def ts(self):
        return (self._ts, 0)

    def handle_frame(self, key, items, packet, out):
        iface = items['frame.interface_id/frame.interface_name'].val
        tstamp = float(items['frame.time_epoch'].val)

        out.append(fmt.tstamp('%6.3f' % (tstamp - self.packets.start_ts,)))
        out.append(fmt.iface(iface))

    def handle_vlan(self, key, items, packet, out):
        out[1][0] = out[1][0] + '.%s' % (items['vlan.id'].val)

    def handle_eth(self, key, items, packet, out):
        src = self.packets.macmap.get(items['eth.src'].val, items['eth.src'].val)
        dst = items['eth.dst'].val
        if dst.startswith('01:00:5e:'):
            dst = 'v4mcast'
        elif dst.startswith('33:33:'):
            dst = 'v6mcast'
        else:
            dst = self.packets.macmap.get(dst, dst)

        out.append(fmt.eth(fmt.eth_src(src), fmt.eth_arr('→'), fmt.eth_dst(dst)))

    def handle_ip(self, key, items, packet, out):
        out.append(fmt.ipv4('IPv4'))

    def handle_ipv6(self, key, items, packet, out):
        out.append(fmt.ipv6('IPv6'))

    def handle_arp(self, key, items, packet, out):
        out.append(fmt.arp('ARP'))

    def handle_tcp(self, key, items, packet, out):
        out.append(fmt.tcp('TCP %s → %s' % (items['tcp.srcport'].val, items['tcp.dstport'].val)))

    def handle_udp(self, key, items, packet, out):
        out.append(fmt.udp('UDP %s → %s' % (items['udp.srcport'].val, items['udp.dstport'].val)))

    def handle_icmp(self, key, items, packet, out):
        out.append(fmt.icmp('ICMP'))
        out.append(fmt.l4detail(items['icmp.type'].desc.split(': ', 1)[-1]))

    def handle_igmp(self, key, items, packet, out):
        out.append(fmt.icmp('IGMP'))
        out.append(fmt.l4detail(items['igmp.type'].desc.split(': ', 1)[-1]))

    def handle_icmpv6(self, key, items, packet, out):
        out.append(fmt.icmpv6('ICMPv6'))
        out.append(fmt.l4detail(items['icmpv6.type'].desc.split(': ', 1)[-1]))

    def handle_ospf(self, key, items, packet, out):
        l4title = 'OSPFv%s' % items['ospf.header/ospf.version'].val

        nexthdr = items[list(items.keys())[1]]
        l4title += (nexthdr.desc or nexthdr.val or '').replace('OSPF', '').replace(' Packet','')
        out.append(fmt.ospf(l4title))

        l4detail = []
        for k, item in items.items():
            typ, idx = k
            if typ == 'ospf.header':
                continue
            # add more info...

        out.append(fmt.l4detail(', '.join(l4detail)))

    def handle_ldp(self, key, items, packet, out):
        for key, sub in items.items():
            if key[0] != '':
                continue

            out.append(fmt.ldp('LDP: %s' % sub.val))

    def handle_bgp(self, key, items, packet, out):
        text = 'BGP %s' % (items['bgp.type'].desc.split(': ', 1)[-1])

        for key, sub in items.items():
            if key[0] == 'bgp.update.nlri' and len(sub):
                text += ' %s' % sub['', 0].val

        out.append(fmt.bgp(text))

    def handle_pim(self, key, items, packet, out):
        text = 'PIM %s' % (items['pim.type'].desc.split(': ', 1)[-1])
        out.append(fmt.pim(text))

    def handle_bfd(self, key, items, packet, out):
        text = 'BFD %s → %s' % (
                items.get(('bfd.my_discriminator', 0, 'val'), '?'),
                items.get(('bfd.your_discriminator', 0, 'val'), '?'),
            )
        if ('bfd.sta', 0) in items:
            text += ' %s' % (items['bfd.sta'].desc.split(': ', 1)[-1])
        out.append(fmt.bfd(text))

        #print('-' * 80)
        #pprint.pprint(items)

    def html(self, id_, ts_rel):
        if self.pdmlpkt.match_for:
            self.attr.class_ += ' assert-match'
            for node in self.pdmlpkt.match_for:
                self.append(fmt.assertmatchitem(node.nodeid))
        return [self]

class ProtomatoDumper(list):
    def __init__(self, macmap={}, start_ts=None):
        super().__init__()
        self.start_ts = start_ts or time.time()

        self.macmap = {
            'ff:ff:ff:ff:ff:ff': 'bcast',
            '01:80:c2:00:00:0e': 'eth-link',
        }
        self.macmap.update(macmap)

    def submit(self, pdmlpkt):
        self.append(ProtomatoPacket(self, pdmlpkt))

    @classmethod
    def load_file(cls, filename):
        from .liveshark import LiveShark

        tsharkproc = subprocess.Popen(['tshark', '-r', filename, '-T', 'pdml'], stdout=subprocess.PIPE)
        instance = cls()

        ls = LiveShark(tsharkproc.stdout)
        ls.subscribe(instance.submit)
        for pkt in ls.run(expect_eof=True):
            pass
        return instance

if __name__ == '__main__':
    packets = ProtomatoDumper.load_file(sys.argv[1])

    doc = html.html(
        html.head(
            html.title('packet dump'),
            html.meta(name="Content-Type", value="text/html; charset=utf-8"),
            html.link(rel="stylesheet", href="topotato/protomato.css", type="text/css"),
            html.script(src='topotato/protomato.js', type='text/javascript'),
        ),
        html.body(
            fmt.packets(
                packets,
            ),
            onmousedown="bmdown(event);",
            onclick="hideall(event);",
        ),
    )
    with open('test.html', 'w') as fd:
        fd.write(doc.unicode(indent=2))
