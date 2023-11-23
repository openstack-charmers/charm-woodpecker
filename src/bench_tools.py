import logging
import subprocess
import os.path

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

    def rbd_remove_image(self, pool_name):
        # first unmap the image otherwise removing the image will fail
        _rbd_name = f"/dev/rbd/{ pool_name }/{ self.charm_instance.RBD_IMAGE }"
        if os.path.exists(_rbd_name):
            _cmd = ["rbd", "unmap", _rbd_name]
            _output = subprocess.check_output(_cmd, stderr=subprocess.PIPE)

        _cmd = ["rbd", "remove", self.charm_instance.RBD_IMAGE,
                "-p", pool_name, "-n", self.charm_instance.CEPH_CLIENT_NAME]
        _output = subprocess.check_output(_cmd, stderr=subprocess.PIPE)
        return _output.decode("UTF-8")

    def rbd_create_image(self, pool_name, image_size, extra_args=[]):
        _cmd = ["rbd", "create", self.charm_instance.RBD_IMAGE,
                "--size", str(image_size), "-p", pool_name,
                "--thick-provision",
                "-n", self.charm_instance.CEPH_CLIENT_NAME] + extra_args
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

    def swift_bench(self, delete=True):
        _cmd = ["swift-bench"]
        if not delete:
            _cmd.append("-x")
        _cmd.append(str(self.charm_instance.SWIFT_BENCH_CONF))
        # For some reason swift-bench sends outpout to stderr
        _output = subprocess.check_output(_cmd, stderr=subprocess.STDOUT)
        return _output.decode("UTF-8")

    def fio(self, fio_conf):
        _cmd = ["fio", "--output-format=json", fio_conf]
        _output = subprocess.check_output(_cmd, stderr=subprocess.PIPE)
        return _output.decode("UTF-8")

    def radosgw_user_create(self, user, subuser, secret):
        """
        radosgw-admin user create -n client.woodpecker
          --uid="benchmark" --display-name="benchmark"
        radosgw-admin subuser create -n client.woodpecker
          --uid=benchmark --subuser=benchmark:swift --access=full
        radosgw-admin key create -n client.woodpecker
          --subuser=benchmark:swift --key-type=swift --secret=guessme
        radosgw-admin user modify -n client.woodpecker
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
