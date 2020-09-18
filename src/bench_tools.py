import logging
import subprocess

import charmhelpers.core.host as ch_host

logger = logging.getLogger()


class BenchTools():

    def __init__(self, charm_instance):
        self.charm_instance = charm_instance

    def rados_bench(
            self, pool_name, seconds, operation, switches=None):
        _cmd = ["rados", "bench", "-n",
                self.charm_instance.CEPH_CLIENT_NAME,
                "-p", pool_name, str(seconds), operation]
        if switches:
            _cmd += switches.split()
        _output = subprocess.check_output(_cmd, stderr=subprocess.PIPE)
        return _output.decode("UTF-8")

    def rbd_create_image(self, pool_name, image_size):
        _cmd = ["rbd", "create", self.charm_instance.RBD_IMAGE,
                "--size", str(image_size), "-p", pool_name,
                "-n", self.charm_instance.CEPH_CLIENT_NAME]
        _output = subprocess.check_output(_cmd, stderr=subprocess.PIPE)
        return _output.decode("UTF-8")

    def rbd_map_image(self, pool_name):
        _cmd = ["rbd", "map", self.charm_instance.RBD_IMAGE,
                "-p", pool_name, "-n", self.charm_instance.CEPH_CLIENT_NAME]
        _output = subprocess.check_output(_cmd, stderr=subprocess.PIPE)
        return _output.decode("UTF-8")

    def make_rbd_fs(self, pool_name, file_system_type="ext4"):
        _image_dev = "{}/{}/{}".format(
            str(self.charm_instance.RBD_DEV), pool_name,
            self.charm_instance.RBD_IMAGE)
        _cmd = ["mkfs.{}".format(file_system_type), "-m0", _image_dev]
        _output = subprocess.check_output(_cmd, stderr=subprocess.PIPE)
        return _output.decode("UTF-8")

    def make_rbd_mount(self):
        ch_host.mkdir(str(self.charm_instance.RBD_MOUNT))

    def mount_rbd_mount(self, pool_name):
        _image_dev = "{}/{}/{}".format(
            str(self.charm_instance.RBD_DEV), pool_name,
            self.charm_instance.RBD_IMAGE)
        _cmd = ["mount", _image_dev, str(self.charm_instance.RBD_MOUNT)]
        _output = subprocess.check_output(_cmd, stderr=subprocess.PIPE)
        return _output.decode("UTF-8")

    def rbd_bench(
            self, pool_name, operation):
        _cmd = ["rbd", "bench", "--io-type", operation,
                self.charm_instance.RBD_IMAGE,
                "-n", self.charm_instance.CEPH_CLIENT_NAME,
                "-p", pool_name]
        _output = subprocess.check_output(_cmd, stderr=subprocess.PIPE)
        return _output.decode("UTF-8")

    def swift_bench(self):
        _cmd = ["swift-bench", str(self.charm_instance.SWIFT_BENCH_CONF)]
        _output = subprocess.check_output(_cmd, stderr=subprocess.PIPE)
        return _output.decode("UTF-8")

    def fio(self):
        _cmd = ["fio", str(self.charm_instance.RBD_FIO_CONF)]
        _output = subprocess.check_output(_cmd, stderr=subprocess.PIPE)
        return _output.decode("UTF-8")

    def radosgw_user_create(self, user, subuser, secret):
        """
        radosgw-admin user create -n client.ceph-benchmarking
          --uid="benchmark" --display-name="benchmark"
        radosgw-admin subuser create -n client.ceph-benchmarking
          --uid=benchmark --subuser=benchmark:swift --access=full
        radosgw-admin key create -n client.ceph-benchmarking
          --subuser=benchmark:swift --key-type=swift --secret=guessme
        radosgw-admin user modify -n client.ceph-benchmarking
          --uid=benchmark --max-buckets=0
        """
        _output = ""
        _cmd = ["radosgw-admin", "user", "create",
                "-n", self.charm_instance.CEPH_CLIENT_NAME,
                "--uid={}".format(user), "--display-name={}".format(user)]
        _output += (
            subprocess.check_output(
                _cmd, stderr=subprocess.PIPE).decode("UTF-8"))

        _cmd = ["radosgw-admin", "subuser", "create",
                "-n", self.charm_instance.CEPH_CLIENT_NAME,
                "--uid={}".format(user),
                "--subuser={}:{}".format(user, subuser), "--access=full"]
        _output += (
            subprocess.check_output(
                _cmd, stderr=subprocess.PIPE).decode("UTF-8"))

        _cmd = ["radosgw-admin", "key", "create",
                "-n", self.charm_instance.CEPH_CLIENT_NAME,
                "--subuser={}:{}".format(user, subuser),
                "--key-type=swift", "--secret={}".format(secret)]
        _output += (
            subprocess.check_output(
                _cmd, stderr=subprocess.PIPE).decode("UTF-8"))

        _cmd = ["radosgw-admin", "user", "modify",
                "-n", self.charm_instance.CEPH_CLIENT_NAME,
                "--uid={}".format(user), "--max-buckets=0"]
        _output += (
            subprocess.check_output(
                _cmd, stderr=subprocess.PIPE).decode("UTF-8"))

        return _output
