import logging
import subprocess

logger = logging.getLogger()


class BenchTools():

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
