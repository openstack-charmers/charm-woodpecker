# Copyright 2023 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from unittest import TestCase
import unittest.mock as mock

import src.charm as charm

from ops.testing import Harness
from .test_utils import MockActionEvent


class TestActions(TestCase):
    def setUp(self):
        self.harness = Harness(charm.WoodpeckerCharmBase)

    def _start(self):
        self.harness.begin()
        self.harness.charm.install_pkgs = lambda *_: None

    @mock.patch.object(charm.ch_host, 'is_container')
    @mock.patch.object(charm.snap, 'snap_install')
    def test_on_install(self, snap_install, is_container):
        is_container.return_value = False
        self._start()
        self.harness.model.resources.fetch =\
            ({self.harness.charm.SNAP_NAME: 1}).__getitem__
        self.harness.charm.on_install(MockActionEvent())
        snap_install.assert_called_with('1', '--dangerous', '--classic')
        self.assertTrue(self.harness.charm._stored.swift_bench_snap_installed)
        self.assertTrue(self.harness.charm.state.installed)

    @mock.patch.object(charm.bench_tools.subprocess, 'check_output')
    def test_on_rbd_map_image(self, check_output):
        event = MockActionEvent({'pool-name': 'test-pool',
                                 'image-size': 2048})
        self._start()
        self.harness.charm.on_rbd_map_image_action(event)
        rbd_img = self.harness.charm.RBD_IMAGE
        client = self.harness.charm.CEPH_CLIENT_NAME

        check_output.assert_any_call(['rbd', 'map', rbd_img, '-p',
                                      'test-pool', '-n', client],
                                     stderr=mock.ANY)
        check_output.assert_any_call(['rbd', 'remove', rbd_img, '-p',
                                      'test-pool', '-n', client],
                                     stderr=mock.ANY)
        check_output.assert_any_call(['rbd', 'create', rbd_img, '--size',
                                      '2048', '-p', 'test-pool',
                                      '-n', client],
                                     stderr=mock.ANY)
        check_output.assert_any_call(['rbd', 'map', rbd_img, '-p',
                                      'test-pool', '-n', client],
                                     stderr=mock.ANY)

    @mock.patch.object(charm.bench_tools.subprocess, 'check_output')
    def test_on_rados_bench(self, check_output):
        event = MockActionEvent({'seconds': 1, 'operation': 'read',
                                 'pool-name': 'ceph-benchmarking',
                                 'switches': 'a b'})
        self._start()
        self.harness.charm.on_rados_bench_action(event)

        check_output.assert_called_with(['rados', 'bench', '-n',
                                         self.harness.charm.CEPH_CLIENT_NAME,
                                         '-p', 'ceph-benchmarking', '1',
                                         'read', 'a', 'b'], stderr=mock.ANY)

    @mock.patch.object(charm.bench_tools.subprocess, 'check_output')
    @mock.patch.object(charm.bench_tools.ch_host, 'mkdir')
    def test_on_rbd_bench(self, mkdir, check_output):
        event = MockActionEvent({'pool-name': 'test', 'operation': 'read',
                                 'image-size': '1'})
        self._start()
        self.harness.charm.on_rbd_bench_action(event)

        mount = str(self.harness.charm.RBD_MOUNT)
        path = (str(self.harness.charm.RBD_DEV) + '/test/' +
                self.harness.charm.RBD_IMAGE)
        mkdir.assert_any_call(mount)
        check_output.assert_any_call(['mount', path, mount], stderr=mock.ANY)
