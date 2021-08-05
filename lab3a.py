from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.link import TCLink
from mininet.node import RemoteController
from mininet.node import Node
from mininet.cli import CLI


class SimpleTopo(Topo):
    
    def __init__(self,k,**opts):
        self.k = k
        super(SimpleTopo,self).__init__(**opts)

        sw = self.addSwitch('s1', dpid = '00:00:00:00:00:00:00:01')

        host = [self.addHost('h%d'%(i+1), ip = '10.00.00.%x'%(i+1)) for i in range(k)]
        for i in range(k):
            self.addLink(sw, host[i])

def simple():
    k = 6
    topo = SimpleTopo(k)
    net = Mininet(topo, link = TCLink, controller = None, autoSetMacs = True, autoStaticArp = True)
    net.addController('controller', controller = RemoteController, ip = "127.0.0.1", port = 6633, protocols = "OpenFlow13")
    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    simple()