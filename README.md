# Overview

The woodpecker charm deploy a testing tool that enables various action
based performance tests to be performed.

# Usage

## Configuration

See file `config.yaml` for the full list of options, along with their
descriptions and default values. The option, `pool-name`, may be provided as a
default pool name for the bench tests.

* `pool-name`

## Deployment

We are assuming a pre-existing Ceph cluster.

To provide the testing host:

    juju deploy cs:~openstack-charmers-next/woodpecker

Then add a relation to the ceph-mon application:

    juju add-relation woodpecker:ceph-client ceph-mon:client

## Snap on Ubuntu 20.04 (Focal)

Due to [LP Bug #1902951][swift-bench-bug] it is necessary to use the [Swift
Bench Snap][swift-bench-snap] when deploying woodpecker on Ubuntu 20.04
(Focal).

In the bundle:

... code-block:: console

  woodpecker:
    num_units: 1
    series: focal
    resources:
      swift-bench: /path/to/swift-bench.snap


From command line:

:command:`juju attach-resource woodpecker swift-bench=/path/to/swift-bench.snap

## Actions

This section covers Juju [actions][juju-docs-actions] supported by the charm.
Actions allow specific operations to be performed on a per-unit basis.

* `rados-bench`
* `rbd-bench`
* `swift-bench`
* `fio`

To display action descriptions run `juju actions woodpecker`. If the charm is
not deployed then see file `actions.yaml`.


<!--

# Bugs

Please report bugs on [Launchpad][lp-bugs-charm-woodpecker].

For general charm questions refer to the [OpenStack Charm Guide][cg].

-->

<!-- LINKS -->

[ceph-mon-charm]: https://jaas.ai/ceph-mon
[ceph-osd-charm]: https://jaas.ai/ceph-osd
[cg]: https://docs.openstack.org/charm-guide
[cg-preview-charms]: https://docs.openstack.org/charm-guide/latest/openstack-charms.html#tech-preview-charms-beta
[cdg]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide
[juju-docs-actions]: https://jaas.ai/docs/actions
[lp-bugs-charm-woodpecker]: https://bugs.launchpad.net/charm-woodpecker/+filebug
[swift-bench-bug]: https://bugs.launchpad.net/ubuntu/+source/swift-bench/+bug/1902951
[swift-bench-snap]: https://github.com/openstack-charmers/snap-swift-bench
