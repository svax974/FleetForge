import os
from VPN import VPN

vpn = VPN()

servers = {{ servers }}

for elem in servers:
    vpn.add_subnet(elem, 32)
