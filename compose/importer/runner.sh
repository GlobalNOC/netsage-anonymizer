#!/usr/bin/env bash

#/tmp/docker_init.sh
echo "Data expected to be initialized by data volume"

netsage-netflow-importer-daemon --nofork --config /etc/grnoc/netsage/deidentifier/netsage_netflow_importer.xml
