# topology.py
#
# Copyright 2014 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`topology` --- SCION AD topologies
===========================================

Module docstring here.

.. note::
    Fill in the docstring.

"""

from collections import defaultdict
from enum import Enum, unique
import logging

from lib.packet.host_addr import *
import xml.etree.ElementTree as ET


class ElementType(object):
    """
    Defines constants to represent element types in the topology file.
    """
    BEACON_SERVER = 0
    CERTIFICATE_SERVER = 1
    PATH_SERVER = 2
    CONTENT_CACHE = 3
    BORDER_ROUTER = 4
    GATEWAY = 5
    SERVER_TYPES = [BEACON_SERVER, CERTIFICATE_SERVER, PATH_SERVER,
                    CONTENT_CACHE]


@unique
class NeighborType(Enum):
    """
    Defines constants for the possible types of neighbor ADs.
    """
    PARENT = 0
    CHILD = 1
    PEER = 2
    ROUTING = 3  # Inter-ISD Link


class Element(object):
    """
    Base class for elements specified in the topology file.

    :param aid: the AD identifier of the element.
    :type aid: int
    :param addr: the address of the element.
    """

    def __init__(self, aid=0, addr=None):
        """
        Constructor.

        :param aid: the AD identifier of the new element.
        :type aid: int
        :param addr: the address of the new element.
        """
        self.aid = aid
        self.addr = addr


class ServerElement(Element):
    """
    Represents one of the core servers in SCION.

    :ivar aid: the AD identifier of the server (inherited from ``Element``).
    :vartype aid: int
    :ivar addr: the server's address (inherited from ``Element``).
    :vartype addr: TODO
    :ivar type: the server's type (i.e., beacon, certificate, path, etc).
    :vartype type: :class:`ElementType`
    """

    def __init__(self, aid=0, addr=None, server_type=0):
        """
        Constructor.

        Creates a new ServerElement object.

        :param aid: the identifier of the AD in which the server is located.
        :type aid: int
        :param addr: the server address.
        :param type: the type of server (possible values and their meanings are
            listed in :class:`ElementType`)
        :type type: int
        """
        super().__init__(self, aid, addr)
        assert server_type in ElementType.SERVER_TYPES
        self.type = server_type


class InterfaceElement(Element):
    """
    An interface between two ADs.

    An InterfaceElement represents an interface for an inter-AD connection. An
    InterfaceElement instance belongs to a RouterElement and stores relevant
    information to the interface, such as the neighbor AD and type, the local
    UDP port number, and the remote address and UDP port number.

    :ivar if_id: the interface ID.
    :vartype if_id: int
    :ivar neighbor: the AD or TD identifier of the neighbor AD.
    :vartype neighbor: int
    :ivar neighbor_type: the type of the neighbor relative to the AD to which
       this interface belongs.
    :vartype neighbor_type: :class:`NeighborType`
    :ivar to_addr: the address of the router in the neighboring AD to which the
       interface is connected.
    :vartype to_addr: :class:`HostAddr`
    :ivar udp_port: the port number of the interface's router used to send UDP
       traffic.
    :vartype udp_port: int
    :ivar to_udp_port: the port number receiving UDP traffic to which the
       interface is connected.
    :vartype to_udp_port: int

    """

    def __init__(self, aid=0, addr=None, if_id=0, neighbor=0,
                 neighbor_type=0, to_addr=None, udp_port=0, to_udp_port=0):
        """
        Constructor.

        :param aid: the AD identifier.
        :type aid: int
        :param addr: the address of the router in the neighboring AD to which
           the interface is connected.
        :type addr: :class:`HostAddr`
        :param if_id: the interface ID.
        :type if_id: int
        :param neighbor: the AD or TD identifier of the neighbor AD.
        :type neighbor: int
        :param neighbor_type: the type of the neighbor relative to the AD to
           which the interface belongs.
        :type neighbor_type: :class:`NeighborType`
        :param to_addr: the address of the router in the neighboring AD to
           which the interface is connected.
        :type to_addr: :class:`HostAddr`
        :param udp_port: the port number used to send UDP traffic.
        :type udp_port: int
        :param to_udp_port: the port number receiving UDP traffic on the other
           end of the interface.
        :type to_udp_port: int
        :returns: the newly-created :class:`InterfaceElement` instance.
        :rtype: :class:`InterfaceElement`

        """
        super().__init__(self, aid, addr)
        self.if_id = if_id
        self.neighbor = neighbor
        assert neighbor_type in map(lambda x: x.value, NeighborType)
        self.neighbor_type = neighbor_type
        self.to_addr = to_addr
        self.udp_port = udp_port
        self.to_udp_port = to_udp_port


class RouterElement(Element):
    """
    Represents a router.

    :ivar interface: the router's interface to a different AD.
    :vartype interface: :class:`InterfaceElement`
    """

    def __init__(self, aid=0, addr=None, interface=None):
        """
        Constructor.

        :param aid: the AD identifier of the new router.
        :type aid: int
        :param addr: the address of the new router.
        """
        super().__init__(self, aid, addr)
        self.interface = interface


class GatewayElement(Element):
    """
    Represents a gateway.

    :ivar ptype: TODO
    :vartype ptype: TODO
    """

    def __init__(self, aid=0, addr=None, ptype=0):
        """
        Constructor.

        :param aid: the AD identifier of the new gateway.
        :type aid: int
        :param addr: the address of the new gateway.
        """
        super().__init__(self, aid, addr)
        self.ptype = ptype


class ClientElement(Element):
    """
    Represents a client.
    """
    def __init__(self, aid=0, addr=None):
        super().__init__(self, aid, addr)


class Topology(object):
    """
    Handle parsing a SCION topology XML file.

    .. note::
        There can only be one server of each type in the topology.

    :ivar routers: a mapping from neighbor types to lists of border routers
       whose interface connects to a neighbor AD of that type.
    :vartype routers: :class:`collections.defaultdict`
    :ivar servers: a mapping of server types
       (:class:`ElementType.SERVER_TYPES`\ ) to :class:`ServerElement`
       instances of that type in the topology.
    :vartype servers: dict
    :ivar gateways: TODO
    :vartype gateways: TODO
    :ivar clients: the clients in the AD.
    :vartype clients: list

    """

    def __init__(self, filename=None):
        """
        Constructor.

        Construct a new Topology instance. If a topology file is specified,
        load the file and parse it to populate the lists of routers, servers,
        gateways, and clients.

        :param filename: the topology file name.
        :type filename: str
        """
        self.routers = defaultdict(list)
        self.servers = {}
        self.gateways = {}
        self.clients = []

        if filename is not None:
            self.load_file(filename)
        else:
            self._filename = None
            self._topo = None

    def load_file(self, filename):
        """
        Load an XML file and creates an element tree for further parsing.

        Load and parse an XML file to create an element tree. Store the
        resulting ElementTree object internally.

        :param filename: the name of the XML file to load.
        :type filename: str
        """
        assert isinstance(filename, str)
        self._filename = filename
        self._topo = ET.parse(filename)

    def parse(self):
        """
        Parse the topology ElementTree.

        Parse the internally-stored ElementTree object in order to populate the
        lists of servers, routers, clients, and gateways of the AD.
        """
        assert self._topo is not None, "Must load file first"
        self._parse_servers()
        self._parse_routers()
        self._parse_clients()
        self._parse_gateways()

    def _parse_servers(self):
        """
        Parse the servers in the topology file.
        """
        servers = self._topo.getroot().find("Servers")
        if servers is None:
            logging.info("No servers found in %s", self._filename)
            return
        for server in servers:
            element = ServerElement()
            self._parse_aid(server, element)
            self._parse_address(server, element)
            if server.tag == "BeaconServer":
                element.type = ElementType.BEACON_SERVER
            elif server.tag == "CertificateServer":
                element.type = ElementType.CERTIFICATE_SERVER
            elif server.tag == "PathServer":
                element.type = ElementType.PATH_SERVER
            elif server.tag == "ContentCache":
                element.type = ElementType.CONTENT_CACHE
            else:
                logging.warning("Encountered unknown server tag '%s'",
                                server.tag)
                continue
            self.servers[element.type] = element

    def _parse_routers(self):
        """
        Parse the list of border routers in the topology file.

        Parse the list of border routers. Find all border router elements in
        the topology file, and add a mapping between the neighbor type of the
        border router's interface and the router itself.
        """
        routers = self._topo.getroot().find("BorderRouters")
        if routers is None:
            logging.info("No routers found in %s", self._filename)
            return
        for router in routers:
            element = RouterElement()
            self._parse_aid(router, element)
            self._parse_address(router, element)
            interfaces = router.findall("Interface")
            # SM: the following two lines imply that each router must have
            # EXACTLY one interface. If so, we should change the code below.
            assert len(interfaces) <= 1, "Router can only have one interface"
            for interface in interfaces:
                self._parse_interface(interface, element)
            self.routers[element.interface.neighbor_type].append(element)

    def _parse_clients(self):
        """
        Parse the clients in the topology file.

        Parse the clients in the topology file and populate the list of
        clients in the topology.
        """
        clients = self._topo.getroot().find("Clients")
        if clients is None:
            logging.info("No clients found in %s", self._filename)
            return
        for client in clients:
            element = ClientElement()
            self._parse_aid(client, element)
            self.clients.append(element)

    def _parse_gateways(self):
        """
        Parse the gateways in the topology file.

        Parse the gateways from the topology file and add them to the AD
        topology.

        .. warning::
            This method has not been implemented yet. Unless overridden in a
            subclass, calling this method will have no effect.
        """
        pass

    def _parse_aid(self, et_element, element):
        """
        Parse the AID in an element.

        Parse the AID of the XML element et_element and store the found AID in
        element.

        :param et_element: the XML element to parse.
        :type et_element: :class:`xml.etree.ElementTree.Element`
        :param element: the SCION element in which to set the parsed AID.
        :type element: :class:`Element`
        """
        assert ET.iselement(et_element)
        aid_el = et_element.find("AID")
        if aid_el is not None:
            element.aid = int(aid_el.text)

    def _parse_address(self, et_element, element):
        """
        Parse the address in an element.

        Parse the address of the XML element et_element and store the found
        address in element.

        :param et_element: the XML element to parse.
        :type et_element: :class:`xml.etree.ElementTree.Element`
        :param element: the SCION element in which to set the parsed address.
        :type element: :class:`Element`
        """
        assert ET.iselement(et_element)
        addr_type = et_element.find("AddrType").text
        addr = et_element.find("Addr").text
        to_addr = et_element.find("ToAddr")
        if addr_type.lower() == "ipv4":
            if to_addr is not None:
                element.to_addr = IPv4HostAddr(to_addr.text)
            else:
                element.addr = IPv4HostAddr(addr)
        elif addr_type.lower() == "ipv6":
            if to_addr is not None:
                element.to_addr = IPv6HostAddr(to_addr.text)
            else:
                element.addr = IPv6HostAddr(addr)
        elif addr_type.lower() == "scion":
            if to_addr is not None:
                element.to_addr = SCIONHostAddr(to_addr.text)
            else:
                element.addr = SCIONHostAddr(int(addr))
        else:
            logging.info("Unknown address type: %s", addr_type)

    def _parse_interface(self, et_element, router):
        """
        Parse an Interface element.

        Parse an Interface element from the local topology parse tree and add
        its relevant information to an InterfaceElement object associated with
        a border router in the AD.

        :param et_element: the XML element to parse.
        :type et_element: :class:`xml.etree.ElementTree.Element`
        :param router: the router with which to associate the parsed interface.
        :type router: :class:`RouterElement`

        """
        assert ET.iselement(et_element)
        if_el = InterfaceElement()
        if et_element.find("AddrType") is not None:
            self._parse_address(et_element, if_el)
        if_el.if_id = int(et_element.find("IFID").text)
        neighbor = et_element.find("NeighborAD")
        if neighbor is None:
            neighbor = et_element.find("NeighborTD")
        assert neighbor is not None
        if_el.neighbor = int(neighbor.text)

        neighbor_type = et_element.find("NeighborType").text
        if neighbor_type == "PARENT":
            if_el.neighbor_type = NeighborType.PARENT
        elif neighbor_type == "CHILD":
            if_el.neighbor_type = NeighborType.CHILD
        elif neighbor_type == "PEER":
            if_el.neighbor_type = NeighborType.PEER
        elif neighbor_type == "ROUTING":
            if_el.neighbor_type = NeighborType.ROUTING
        else:
            logging.warning("Encountered unknown neighbor type")

        if et_element.find("UdpPort") is not None:
            if_el.udp_port = int(et_element.find("UdpPort").text)
        if et_element.find("ToUdpPort") is not None:
            if_el.to_udp_port = int(et_element.find("ToUdpPort").text)

        router.interface = if_el

# For testing purposes
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: %s <topofile>" % sys.argv[0])
        sys.exit()
    parser = Topology(sys.argv[1])
    parser.parse()
