import sys
import optparse
import socket
import select
import errno
import pytun

class TunnelServer(object):

    def __init__(self, taddr, tdstaddr, tmask, tmtu, laddr, lport, raddr, rport):
        self._tun = pytun.TunTapDevice(flags=pytun.IFF_TUN|pytun.IFF_NO_PI)
        self._tun.addr = taddr
        self._tun.dstaddr = tdstaddr
        self._tun.netmask = tmask
        self._tun.mtu = tmtu
        self._tun.up()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((laddr, lport))
        self._raddr = raddr
        self._rport = rport

    def run(self):
        mtu = self._tun.mtu
        r = [self._tun, self._sock]; w = []; x = []
        to_tun = ''
        to_sock = ''
        while True:
            try:
                r, w, x = select.select(r, w, x)
                if self._tun in r:
                    to_sock = self._tun.read(mtu)
                if self._sock in r:
                    to_tun, addr = self._sock.recvfrom(65535)
                    if addr[0] != self._raddr or addr[1] != self._rport:
                        to_tun = '' # drop packet
                if self._tun in w:
                    self._tun.write(to_tun)
                    to_tun = ''
                if self._sock in w:
                    self._sock.sendto(to_sock, (self._raddr, self._rport))
                    to_sock = ''
                r = []; w = []
                if to_tun:
                    w.append(self._tun)
                else:
                    r.append(self._sock)
                if to_sock:
                    w.append(self._sock)
                else:
                    r.append(self._tun)
            except (select.error, socket.error, pytun.Error), e:
                if e[0] == errno.EINTR:
                    continue
                print >> sys.stderr, str(e)
                break

def main():
    parser = optparse.OptionParser()
    parser.add_option('--tun-addr', dest='taddr',
            help='set tunnel local address')
    parser.add_option('--tun-dstaddr', dest='tdstaddr',
            help='set tunnel destination address')
    parser.add_option('--tun-netmask', default='255.255.255.0',dest='tmask',
            help='set tunnel netmask')
    parser.add_option('--tun-mtu', type='int', default=1500,dest='tmtu',
            help='set tunnel MTU')
    parser.add_option('--local-addr', default='0.0.0.0', dest='laddr',
            help='set local address [%default]')
    parser.add_option('--local-port', type='int', default=12000, dest='lport',
            help='set local port [%default]')
    parser.add_option('--remote-addr', dest='raddr',
            help='set remote address')
    parser.add_option('--remote-port', type='int', dest='rport',
            help='set remote port')
    opt, args = parser.parse_args()
    if not (opt.taddr and opt.tdstaddr and opt.raddr and opt.rport):
        parser.print_help()
        return 1
    try:
        server = TunnelServer(opt.taddr, opt.tdstaddr, opt.tmask, opt.tmtu,
                opt.laddr, opt.lport, opt.raddr, opt.rport)
    except (pytun.Error, socket.error), e:
        print >> sys.stderr, str(e)
        return 1
    server.run()
    return 0

if __name__ == '__main__':
    sys.exit(main())

