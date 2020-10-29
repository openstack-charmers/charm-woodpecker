#!/usr/bin/env python3

import logging

from ops.framework import (
    StoredState,
    EventBase,
    ObjectEvents,
    EventSource,
    Object)


class HasPeersEvent(EventBase):
    """Has Peers Event."""
    pass


class ReadyPeersEvent(EventBase):
    pass


class CephBenchmarkingPeerEvents(ObjectEvents):
    has_peers = EventSource(HasPeersEvent)
    ready_peers = EventSource(ReadyPeersEvent)


class CephBenchmarkingPeers(Object):

    on = CephBenchmarkingPeerEvents()
    state = StoredState()
    SWIFT_KEY = "swift_key"
    SWIFT_USER_CREATED = "swift_user_created"

    def __init__(self, charm, relation_name):
        super().__init__(charm, relation_name)
        self.relation_name = relation_name
        self.this_unit = self.framework.model.unit
        self.framework.observe(
            charm.on[relation_name].relation_changed,
            self.on_changed)

    def on_changed(self, event):
        """On changed.

        Set context from action parameters for rendering files.

        :param event: Event
        :type event: Operator framework event object
        :returns: This method is called for its side effects
        :rtype: None
        """

        logging.info("CephBenchmarkingPeers on_changed")
        self.on.has_peers.emit()
        if self.ready_peer_details:
            self.on.ready_peers.emit()

    def set_swift_key(self, password):
        logging.info("Setting swift key")
        self.peers_rel.data[self.peers_rel.app][self.SWIFT_KEY] = password

    def set_swift_user_created(self, user):
        logging.info("Setting swift user created")
        self.peers_rel.data[self.peers_rel.app][self.SWIFT_USER_CREATED] = user

    @property
    def ready_peer_details(self):
        peers = {
            self.framework.model.unit.name: {
                'ip': self.peers_bind_address}}
        for u in self.peers_rel.units:
            peers[u.name] = {
                'ip': self.peers_rel.data[u]['ingress-address']}
        return peers

    @property
    def is_joined(self):
        return self.peers_rel is not None

    @property
    def peers_rel(self):
        return self.framework.model.get_relation(self.relation_name)

    @property
    def peers_binding(self):
        return self.framework.model.get_binding(self.peers_rel)

    @property
    def peers_bind_address(self):
        return str(self.peers_binding.network.bind_address)

    @property
    def swift_key(self):
        if not self.peers_rel:
            return None
        return self.peers_rel.data[self.peers_rel.app].get(self.SWIFT_KEY)

    @property
    def swift_user_created(self):
        if not self.peers_rel:
            return None
        return self.peers_rel.data[
            self.peers_rel.app].get(self.SWIFT_USER_CREATED)

    @property
    def peer_addresses(self):
        addresses = [self.peers_bind_address]
        for u in self.peers_rel.units:
            addresses.append(self.peers_rel.data[u]['ingress-address'])
        return sorted(addresses)

    @property
    def peers_count(self):
        if self.peers_rel:
            return len(self.peers_rel.units)
        else:
            return 0

    @property
    def unit_count(self):
        return self.peers_count + 1
