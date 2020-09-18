# Overview

The ceph-benchmarking charm deploy a testing tool that enables various action
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

    juju deploy cs:~openstack-charmers-next/ceph-benchmarking

Then add a relation to the ceph-mon application:

    juju add-relation ceph-benchmarking:ceph-client ceph-mon:client

## Actions

This section covers Juju [actions][juju-docs-actions] supported by the charm.
Actions allow specific operations to be performed on a per-unit basis.

* `rados-bench`
* `rbd-bench`
* `swift-bench`
* `fio`

To display action descriptions run `juju actions ceph-benchmarking`. If the charm is
not deployed then see file `actions.yaml`.


<!--

# Bugs

Please report bugs on [Launchpad][lp-bugs-charm-ceph-benchmarking].

For general charm questions refer to the [OpenStack Charm Guide][cg].

-->

<!-- LINKS -->

[ceph-mon-charm]: https://jaas.ai/ceph-mon
[ceph-osd-charm]: https://jaas.ai/ceph-osd
[cg]: https://docs.openstack.org/charm-guide
[cg-preview-charms]: https://docs.openstack.org/charm-guide/latest/openstack-charms.html#tech-preview-charms-beta
[cdg]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide
[juju-docs-actions]: https://jaas.ai/docs/actions
[lp-bugs-charm-ceph-benchmarking]: https://bugs.launchpad.net/charm-ceph-benchmarking/+filebug
