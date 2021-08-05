# sudo mn --custom Topo.py --topo mytopo
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import irange, dumpNodeConnections
from mininet.log import setLogLevel
from mininet.link import TCLink
from mininet.node import RemoteController, Switch
from mininet.cli import CLI



# 1 switch, k hosts
class TP(Topo):
    def __init__(self, **opts):
        super(TP, self).__init__(**opts)
        k = int(input('set number of hosts: '))
        switch = 1
        host = k
        Sw = []     # switch
        Hs = []     # hosts

        # generate switch
        for i in irange(1, switch):
            dpid='{}{:02x}'.format((7*'00'), i)
            Sw.append(self.addSwitch('Sw{}'.format(i - 1), dpid=dpid))

        # generate the hosts and assign the ip address
        for i in irange(1, host):
            ID = i + 1
            ip = '10.0.0.{}'.format(ID)     # 10 : pod : switch : ID
            Hs.append(self.addHost('h{}'.format(i - 1), ip=ip))

        # connect the host with corresponding edge switch
        counter = 0
        port = 1
        for i in irange(1, host):
            self.addLink(Sw[0], Hs[counter], port, 1)
            port += 1
            counter += 1


# run the mininet test
def simpleTest():
    topo = TP()
    net = Mininet(topo=topo, link=TCLink, controller=None, autoSetMacs=True, autoStaticArp=True)
    net.addController('controller', controller=RemoteController, ip="127.0.0.1", port=6633, protocols="OpenFlow13")
    net.start()
    CLI(net)
    net.stop()

topos = {'mytopo': (lambda: simpleTest())}