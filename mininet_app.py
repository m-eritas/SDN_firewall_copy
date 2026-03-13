from mininet.clean import cleanup
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import RemoteController, OVSSwitch

class SimpleTopo(Topo):
    def build(self):
        # add switches
        s1 = self.addSwitch('s1')

        # add hosts with static IPs
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')

        # add links
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)

def mininet_main(stop_event):
    topo = SimpleTopo()
    net  = Mininet(
        topo=topo,
        switch=OVSSwitch,
        controller=RemoteController('c0', ip='127.0.0.1', port=6633),
        autoSetMacs=True,
        waitConnected=True,
    )
    net.start()

    stop_event.wait()       # block here until shutdown is signaled

    net.stop()
    cleanup()               # cleans up OVS, namespaces, interfaces