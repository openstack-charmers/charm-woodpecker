#!/usr/bin/env python3

import socket
import logging
import os
import subprocess
import sys
from pathlib import Path

sys.path.append("lib")

from ops.framework import (
    StoredState,
)
from ops.main import main
import ops.model
import charmhelpers.core.host as ch_host
import charmhelpers.core.templating as ch_templating
import interface_ceph_client.ceph_client as ceph_client
import interface_tls_certificates.ca_client as ca_client
import interface_ceph_benchmarking_peers

import bench_tools

import ops_openstack.adapters
import ops_openstack.core
import cryptography.hazmat.primitives.serialization as serialization
logger = logging.getLogger(__name__)


class CephClientAdapter(ops_openstack.adapters.OpenStackOperRelationAdapter):
    """Ceph Client Adapter."""

    def __init__(self, relation):
        super(CephClientAdapter, self).__init__(relation)

    @property
    def mon_hosts(self):
        hosts = self.relation.get_relation_data()["mon_hosts"]
        return " ".join(sorted(hosts))

    @property
    def auth_supported(self):
        return self.relation.get_relation_data()["auth"]

    @property
    def key(self):
        return self.relation.get_relation_data()["key"]


class PeerAdapter(ops_openstack.adapters.OpenStackOperRelationAdapter):
    """Peer Adapter."""

    def __init__(self, relation):
        super(PeerAdapter, self).__init__(relation)


class CephBenchmarkingPeerAdapter(PeerAdapter):
    """Ceph Benchmarking Peer Adapter."""

    def __init__(self, relation):
        super(CephBenchmarkingPeerAdapter, self).__init__(relation)

    @property
    def hosts(self):
        """Ceph-benchmarking unit addresses."""
        hosts = self.relation.peers_addresses
        return " ".join(sorted(hosts))


class TLSCertificatesAdapter(
        ops_openstack.adapters.OpenStackOperRelationAdapter):
    """TLS Certificates Adapter."""

    def __init__(self, relation):
        super(TLSCertificatesAdapter, self).__init__(relation)

    @property
    def enable_tls(self):
        try:
            return bool(self.relation.application_certificate)
        except ca_client.CAClientError:
            return False


class CephBenchmarkingAdapters(
        ops_openstack.adapters.OpenStackRelationAdapters):
    """Ceph Benchmarking Adapters."""

    relation_adapters = {
        "ceph-client": CephClientAdapter,
        "peers": CephBenchmarkingPeerAdapter,
        "certificates": TLSCertificatesAdapter,
    }


class CephBenchmarkingCharmBase(ops_openstack.core.OSBaseCharm):
    """Ceph Benchmarking Charm Base."""

    state = StoredState()
    PACKAGES = ["ceph-common", "fio", "swift-bench"]
    CEPH_CAPABILITIES = [
        "osd", "allow *",
        "mon", "allow *",
        "mgr", "allow *"]
    CLIENT_NAME = "ceph-benchmarking"
    CEPH_CLIENT_NAME = "client.{}".format(CLIENT_NAME)
    SWIFT_USER = "{}:swift".format(CLIENT_NAME)

    RBD_MOUNT = Path("/mnt/ceph-block-device")
    RBD_IMAGE = "rbdimage01"
    RBD_DEV = Path("/dev/rbd")

    REQUIRED_RELATIONS = ["ceph-client"]

    CEPH_CONFIG_PATH = Path("/etc/ceph")
    RBD_FIO_CONF = CEPH_CONFIG_PATH / "rbd.fio"
    DISK_FIO_CONF = CEPH_CONFIG_PATH / "disk.fio"
    CEPH_CONF = CEPH_CONFIG_PATH / "ceph.conf"
    SWIFT_BENCH_CONF = Path("/etc/swift/swift-bench.conf")
    BENCHMARK_KEYRING = (
        CEPH_CONFIG_PATH / "ceph.client.ceph-benchmarking.keyring")
    TLS_KEY_PATH = CEPH_CONFIG_PATH / "ceph-benchmarking.key"
    TLS_PUB_KEY_PATH = CEPH_CONFIG_PATH / "ceph-benchmarking-pub.key"
    TLS_CERT_PATH = CEPH_CONFIG_PATH / "ceph-benchmarking.crt"
    TLS_KEY_AND_CERT_PATH = CEPH_CONFIG_PATH / "ceph-benchmarking.pem"
    TLS_CA_CERT_PATH = Path(
        "/usr/local/share/ca-certificates/vault_ca_cert.crt")
    # We have no services to restart so using configs_for_rendering.
    configs_for_rendering = [
        str(CEPH_CONF),
        str(BENCHMARK_KEYRING)]
    release = "default"
    bindings = ["cluster", "peers", "public"]
    action_output_key = "test-results"

    def __init__(self, framework):
        """Init Ceph Benchmarking Charm Base."""
        super().__init__(framework)
        super().register_status_check(self.custom_status_check)
        logging.info("Using {} class".format(self.release))
        self._stored.set_default(
            target_created=False,
            enable_tls=False)
        self.ceph_client = ceph_client.CephClientRequires(
            self,
            "ceph-client")
        self.peers = interface_ceph_benchmarking_peers.CephBenchmarkingPeers(
            self,
            "peers")
        self.ca_client = ca_client.CAClient(
            self,
            "certificates")
        self.adapters = CephBenchmarkingAdapters(
            (self.ceph_client, self.peers, self.ca_client),
            self)
        self.framework.observe(
            self.ceph_client.on.broker_available,
            self.request_ceph_pool)
        self.framework.observe(
            self.ceph_client.on.pools_available,
            self.render_config)
        self.framework.observe(
            self.peers.on.has_peers,
            self.on_has_peers)
        self.framework.observe(
            self.ca_client.on.tls_app_config_ready,
            self.on_tls_app_config_ready)
        self.framework.observe(
            self.ca_client.on.ca_available,
            self.on_ca_available)
        self.framework.observe(
            self.on.config_changed,
            self.render_config)
        self.framework.observe(
            self.on.upgrade_charm,
            self.render_config)
        self.framework.observe(
            self.on.rados_bench_action,
            self.on_rados_bench_action)
        self.framework.observe(
            self.on.rbd_bench_action,
            self.on_rbd_bench_action)
        self.framework.observe(
            self.on.swift_bench_action,
            self.on_swift_bench_action)
        self.framework.observe(
            self.on.fio_action,
            self.on_fio_action)
        self.framework.observe(
            self.on.rbd_map_image_action,
            self.on_rbd_map_image_action)

    def on_install(self, event):
        """Event handler on install.

        :param event: Event
        :type event: Operator framework event object
        :returns: This method is called for its side effects
        :rtype: None
        """
        if ch_host.is_container():
            logging.warning("Some charm actions cannot be performed while "
                            "deployed in a container.")
        self.install_pkgs()

    def on_has_peers(self, event):
        """Event handler on has peers.

        Currently a noop. Multiple units will allow for simultaneous stress
        tests against ceph.

        :param event: Event
        :type event: Operator framework event object
        :returns: This method is called for its side effects
        :rtype: None
        """
        logging.info("Unit has peers")

    def request_ceph_pool(self, event):
        """Request pool from ceph cluster.

        :param event: Event
        :type event: Operator framework event object
        :returns: This method is called for its side effects
        :rtype: None
        """
        logging.info("Requesting replicated pool")
        self.ceph_client.create_replicated_pool(
            self.model.config["pool-name"])
        logging.info("Requesting permissions")
        self.ceph_client.request_ceph_permissions(
            self.CEPH_CLIENT_NAME,
            self.CEPH_CAPABILITIES)
        self.ceph_client.request_osd_settings({
            "osd heartbeat grace": 20,
            "osd heartbeat interval": 5})

    def refresh_request(self, event):
        """Refresh request for pool from ceph cluster.

        :param event: Event
        :type event: Operator framework event object
        :returns: This method is called for its side effects
        :rtype: None
        """
        self.render_config(event)
        self.request_ceph_pool(event)

    def get_pool_name(self, event):
        """Get pool name.

        Return either the action parameter or the configuration option pool
        name setting.

        :param event: Event
        :type event: Operator framework event object
        :returns: pool name
        :rtype: string
        """
        return (
            event.params.get("pool-name") or
            self.model.config["pool-name"])

    def set_action_params(self, event):
        """Set action parameters.

        Set context from action parameters for rendering files.

        :param event: Event
        :type event: Operator framework event object
        :returns: This method is called for its side effects
        :rtype: None
        """
        _action_parameters = {"protocol": "http"}
        for k, v in event.params.items():
            _action_parameters[k.replace("-", "_")] = v
        _action_parameters["pool_name"] = self.get_pool_name(event)
        _action_parameters["rbd_image"] = self.RBD_IMAGE
        _action_parameters["rbd_dev"] = str(self.RBD_DEV)
        _action_parameters["rbd_mount"] = str(self.RBD_MOUNT)
        _action_parameters["swift_user"] = self.SWIFT_USER
        _action_parameters["swift_key"] = self.get_swift_key()
        if self._stored.enable_tls:
            _action_parameters["protocol"] = "https"
        self.adapters.action_params = _action_parameters
        self.adapters._relations.add("action_params")

    def render_config(self, event):
        """Render configuration files.

        Render self.configs_for_rendering.

        :param event: Event
        :type event: Operator framework event object
        :returns: This method is called for its side effects
        :rtype: None
        """
        if not self.ceph_client.pools_available:
            print("Defering setup pools")
            logging.info("Defering setup")
            event.defer()
            return

        self.CEPH_CONFIG_PATH.mkdir(
            exist_ok=True,
            mode=0o750)

        def _render_configs():
            for config_file in self.configs_for_rendering:
                ch_templating.render(
                    os.path.basename(config_file),
                    config_file,
                    self.adapters)
        logging.info("Rendering config")
        _render_configs()
        logging.info("Setting started state")
        self._stored.is_started = True
        self.update_status()
        logging.info("on_pools_available: status updated")

    def on_ca_available(self, event):
        """Event handler on Certificate Authority available.

        :param event: Event
        :type event: Operator framework event object
        :returns: This method is called for its side effects
        :rtype: None
        """
        addresses = set()
        for binding_name in self.bingings:
            binding = self.model.get_binding(binding_name)
            addresses.add(binding.network.ingress_address)
            addresses.add(binding.network.bind_address)
        sans = [str(s) for s in addresses]
        sans.append(socket.gethostname())
        self.ca_client.request_application_certificate(socket.getfqdn(), sans)

    def on_tls_app_config_ready(self, event):
        """Event handler on TLS application configuration ready.

        :param event: Event
        :type event: Operator framework event object
        :returns: This method is called for its side effects
        :rtype: None
        """
        self.TLS_KEY_PATH.write_bytes(
            self.ca_client.application_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()))
        self.TLS_CERT_PATH.write_bytes(
            self.ca_client.application_certificate.public_bytes(
                encoding=serialization.Encoding.PEM))
        self.TLS_CA_CERT_PATH.write_bytes(
            self.ca_client.ca_certificate.public_bytes(
                encoding=serialization.Encoding.PEM))
        self.TLS_KEY_AND_CERT_PATH.write_bytes(
            self.ca_client.application_certificate.public_bytes(
                encoding=serialization.Encoding.PEM) +
            b"\n" +
            self.ca_client.application_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption())
        )
        self.TLS_PUB_KEY_PATH.write_bytes(
            self.ca_client.application_key.public_key().public_bytes(
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
                encoding=serialization.Encoding.PEM))
        subprocess.check_call(["update-ca-certificates"])
        self._stored.enable_tls = True
        self.render_config(event)

    def custom_status_check(self):
        """Custom status check.

        Inform the operator if the charm has been deployed in a container.

        :returns: This method is called for its side effects
        :rtype: None
        """
        if ch_host.is_container():
            return ops.model.ActiveStatus(
                "Some charm actions cannot be performed when deployed in a "
                "container")
        else:
            return ops.model.ActiveStatus()

    # Actions
    def on_rbd_map_image_action(self, event):
        """Event handler on rbd map image action.

        Create and map rbd image

        :param event: Event
        :type event: Operator framework event object
        :returns: This method is called for its side effect of setting event
                  results.
        :rtype: None
        """
        # Prepare the rbd image
        self.rbd_create_image(event)
        self.rbd_map_image(event)

    def on_rados_bench_action(self, event):
        """Event handler on RADOS bench action.

        Run the rados-bench test.

        :param event: Event
        :type event: Operator framework event object
        :returns: This method is called for its side effect of setting event
                  results.
        :rtype: None
        """
        _bench = bench_tools.BenchTools(self)
        logging.info(
            "Running rados bench {}".format(event.params["operation"]))
        try:
            _result = _bench.rados_bench(
                self.get_pool_name(event),
                event.params["seconds"],
                event.params["operation"],
                switches=event.params.get("switches"))
            event.set_results({self.action_output_key: _result})
        except subprocess.CalledProcessError as e:
            _msg = ("rados bench failed: {}"
                    .format(e.stderr.decode("UTF-8")))
            logging.error(_msg)
            event.fail(_msg)
            event.set_results({
                "stderr": _msg,
                "code": "1"})

    def rbd_create_image(self, event):
        """Create map and mount rbd block device.

        Create RBD image. Map RBD Image. Prepare and mount RBD block device.

        :param event: Event
        :type event: Operator framework event object
        :returns: This method is called for its side effects.
        :rtype: None
        """
        _bench = bench_tools.BenchTools(self)

        # Create the image
        logging.info("Create the rbd image")
        try:
            _result = _bench.rbd_create_image(
                self.get_pool_name(event),
                event.params["image-size"])
            # XXX We actually don't care about this output unless we fail on
            # subsequent steps
            event.set_results({self.action_output_key: _result})
        except subprocess.CalledProcessError as e:
            if "already exists" in e.stderr.decode("UTF-8"):
                logging.warning(e.stderr.decode("UTF-8"))
            else:
                _msg = ("rbd create image failed: {}"
                        .format(e.stderr.decode("UTF-8")))
                logging.error(_msg)
                event.fail(_msg)
                event.set_results({
                    "stderr": _msg,
                    "code": "1"})
                raise

    def rbd_map_image(self, event):
        """Create map and mount rbd block device.

        Create RBD image. Map RBD Image. Prepare and mount RBD block device.

        :param event: Event
        :type event: Operator framework event object
        :returns: This method is called for its side effects.
        :rtype: None
        """
        _bench = bench_tools.BenchTools(self)

        # Map the image
        logging.info("rbd map image")
        try:
            _result = _bench.rbd_map_image(
                self.get_pool_name(event))
            # XXX We actually don't care about this output unless we fail on
            # subsequent steps
            event.set_results({self.action_output_key: _result})
        except subprocess.CalledProcessError as e:
            _msg = ("rbd map image failed: {}"
                    .format(e.stderr.decode("UTF-8")))
            logging.error(_msg)
            event.fail(_msg)
            event.set_results({
                "stderr": _msg,
                "code": "1"})
            raise

    def mount_rbd(self, event):
        """Mount rbd block device.

        Create RBD image. Map RBD Image. Prepare and mount RBD block device.

        :param event: Event
        :type event: Operator framework event object
        :returns: This method is called for its side effects.
        :rtype: None
        """
        _bench = bench_tools.BenchTools(self)

        # Make and mount fs
        logging.info("Setup filestem for rbd")
        try:
            _bench.make_rbd_fs(self.get_pool_name(event))
            _bench.make_rbd_mount()
            _bench.mount_rbd_mount(self.get_pool_name(event))
        except subprocess.CalledProcessError as e:
            _msg = ("Making or mounting fs failed: {}"
                    .format(e.stderr.decode("UTF-8")))
            logging.error(_msg)
            event.fail(_msg)
            event.set_results({
                "stderr": _msg,
                "code": "1"})
            raise

    def on_rbd_bench_action(self, event):
        """Event handler on RBD bench action.

        Run the rbd-bench test.

        :param event: Event
        :type event: Operator framework event object
        :returns: This method is called for its side effect of setting event
                  results.
        :rtype: None
        """
        # Prepare the rbd image
        self.rbd_create_image(event)
        self.rbd_map_image(event)
        self.mount_rbd(event)

        _bench = bench_tools.BenchTools(self)

        # Run bench
        logging.info("Running rbd bench")
        try:
            _result = _bench.rbd_bench(
                self.get_pool_name(event),
                event.params["operation"])
            event.set_results({self.action_output_key: _result})
        except subprocess.CalledProcessError as e:
            _msg = ("rbd bench failed: {}"
                    .format(e.stderr.decode("UTF-8")))
            logging.error(_msg)
            event.fail(_msg)
            event.set_results({
                "stderr": _msg,
                "code": "1"})
            raise

    def get_swift_key(self):
        """Get Swift Key.

        Generate or get existing swift key

        :returns: Key for authenticating against swift
        :rtype: String
        """
        if not self.peers.swift_key:
            # If the leader create and set the swift key
            if self.unit.is_leader():
                self.peers.set_swift_key(ch_host.pwgen())
        return self.peers.swift_key

    def on_swift_bench_action(self, event):
        """Event handler on Swift bench action.

        Run the swift-bench test.

        :param event: Event
        :type event: Operator framework event object
        :returns: This method is called for its side effect of setting event
                  results.
        :rtype: None
        """
        _bench = bench_tools.BenchTools(self)

        if not self.get_swift_key():
            _msg = ("Unable to set sift key. Please run the action on the "
                    "leader.")
            event.fail(_msg)
            raise Exception(_msg)

        # Add action_parms to adapters
        self.set_action_params(event)
        # Add swift-bench.conf for rendering
        self.configs_for_rendering.append(str(self.SWIFT_BENCH_CONF))
        # Render swift-bench.conf with action_params
        self.render_config(event)

        logging.info("Create radosgw user and key")
        if not self.peers.swift_user_created:
            try:
                _result = _bench.radosgw_user_create(
                    self.CLIENT_NAME,
                    "swift",
                    self.get_swift_key())
                # XXX We actually don't care about this output unless we fail
                # on subsequent steps
                event.set_results({self.action_output_key: _result})
            except subprocess.CalledProcessError as e:
                _msg = ("Rados GW user and key creation failed: {}"
                        .format(e.stderr.decode("UTF-8")))
                logging.error(_msg)
                event.fail(_msg)
                event.set_results({
                    "stderr": _msg,
                    "code": "1"})
                raise
            self.peers.set_swift_user_created(self.SWIFT_USER)

        # Run bench
        logging.info("Running swift bench")
        try:
            _result = _bench.swift_bench()
            event.set_results({self.action_output_key: _result})
        except subprocess.CalledProcessError as e:
            # For some reason swift-bench sends outpout to stderr
            # So stderr is also on stdout
            _msg = ("swift bench failed: {}"
                    .format(e.stdout.decode("UTF-8")))
            logging.error(_msg)
            event.fail(_msg)
            event.set_results({
                "stderr": _msg,
                "code": "1"})
            raise

    def on_fio_action(self, event):
        """Event handler on FIO action.

        Run the FIO test.

        :param event: Event
        :type event: Operator framework event object
        :returns: This method is called for its side effect of setting event
                  results.
        :rtype: None
        """
        # If not disk specified use RBD mount
        if not event.params.get("disk-devices"):
            # Prepare the rbd image
            self.rbd_create_image(event)
            if not ch_host.is_container():
                self.rbd_map_image(event)

            # Add context for the render of rbd.fio
            event.params["client"] = self.CLIENT_NAME
            event.params["rbd_image"] = self.RBD_IMAGE
            event.params["pool_name"] = self.get_pool_name(event)
            _fio_conf = str(self.RBD_FIO_CONF)
        else:
            event.params["disk_devices"] = event.params["disk-devices"].split()
            _fio_conf = str(self.DISK_FIO_CONF)

        # Add action_parms to adapters
        self.set_action_params(event)
        # Render fio config file
        self.configs_for_rendering.append(_fio_conf)
        self.render_config(event)

        _bench = bench_tools.BenchTools(self)

        logging.info(
            "Running fio {}".format(event.params["operation"]))
        try:
            _result = _bench.fio(_fio_conf)
            event.set_results({self.action_output_key: _result})
        except subprocess.CalledProcessError as e:
            _msg = ("fio failed: {}"
                    .format(e.stderr.decode("UTF-8")))
            logging.error(_msg)
            event.fail(_msg)
            event.set_results({
                "stderr": _msg,
                "code": "1"})


@ops_openstack.core.charm_class
class CephBenchmarkingCharmJewel(CephBenchmarkingCharmBase):
    """Ceph Benchmarking Charm at Jewel."""

    state = StoredState()
    release = "jewel"


@ops_openstack.core.charm_class
class CephBenchmarkingCharmOcto(CephBenchmarkingCharmBase):
    """Ceph Benchmarking Charm at Octopus."""

    state = StoredState()
    release = "octopus"


if __name__ == "__main__":
    """Main."""
    main(ops_openstack.core.get_charm_class_for_release())
