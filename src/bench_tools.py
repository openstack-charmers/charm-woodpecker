import logging
import subprocess

import charmhelpers.core.host as ch_host

logger = logging.getLogger()


class BenchTools():

    RBD_MOUNT = "/mnt/ceph-block-device"
    RBD_IMAGE = "rbdimage01"
    RBD_DEV = "/dev/rbd"
    RBD_FIO_CONF = "/etc/ceph/rbd.fio"

    def rados_bench(
            self, pool_name, seconds, operation, client=None, switches=None):
        _cmd = ["rados", "bench"]
        if client:
            _cmd += ["-n", client]
        _cmd += ["-p", pool_name, str(seconds), operation]
        if switches:
            _cmd += switches.split()
        _output = subprocess.check_output(_cmd, stderr=subprocess.PIPE)
        return _output.decode("UTF-8")

    def rbd_create_image(self, pool_name, image_size, client=None):
        _cmd = ["rbd", "create", self.RBD_IMAGE, "--size", str(image_size),
                "-p", pool_name]
        if client:
            _cmd += ["-n", client]
        _output = subprocess.check_output(_cmd, stderr=subprocess.PIPE)
        return _output.decode("UTF-8")

    def rbd_map_image(self, pool_name, client=None):
        _cmd = ["rbd", "map", self.RBD_IMAGE, "-p", pool_name]
        if client:
            _cmd += ["-n", client]
        _output = subprocess.check_output(_cmd, stderr=subprocess.PIPE)
        return _output.decode("UTF-8")

    def make_rbd_fs(self, pool_name, file_system_type="ext4"):
        _image_dev = "{}/{}/{}".format(
            self.RBD_DEV, pool_name, self.RBD_IMAGE)
        _cmd = ["mkfs.{}".format(file_system_type), "-m0", _image_dev]
        _output = subprocess.check_output(_cmd, stderr=subprocess.PIPE)
        return _output.decode("UTF-8")

    def make_rbd_mount(self):
        ch_host.mkdir(self.RBD_MOUNT)

    def mount_rbd_mount(self, pool_name):
        _image_dev = "{}/{}/{}".format(
            self.RBD_DEV, pool_name, self.RBD_IMAGE)
        _cmd = ["mount", _image_dev, self.RBD_MOUNT]
        _output = subprocess.check_output(_cmd, stderr=subprocess.PIPE)
        return _output.decode("UTF-8")

    def rbd_bench(
            self, pool_name, operation, client=None):
        _cmd = ["rbd", "bench", "--io-type", operation, self.RBD_IMAGE]
        if client:
            _cmd += ["-n", client]
        _cmd += ["-p", pool_name]
        _output = subprocess.check_output(_cmd, stderr=subprocess.PIPE)
        return _output.decode("UTF-8")

    def fio(self):
        _cmd = ["fio", self.RBD_FIO_CONF]
        _output = subprocess.check_output(_cmd, stderr=subprocess.PIPE)
        return _output.decode("UTF-8")
