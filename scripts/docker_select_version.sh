#!/usr//bin/env bash

function displayVersions() {
  echo "Current Released Tags"
  git tag -l
}

function selectVersion() {
  displayVersions
  echo -n "Which version would you like to use?  "
  read version
  updateDocker $version

}


## Will update images generated by netsage pipeline to selected version
function updateFile()  {
    sed -i -e "s/pipeline_importer:.*/pipeline_importer:$version/" $1
    sed -i -e "s/pipeline_logstash:.*/pipeline_logstash:$version/" $1
}

function updateDocker() {
  version=$1
  echo "Selecting $version, updating docker configuration"
  updateFile docker-compose.build.yml
  updateFile docker-compose.yml
  if test -f "docker-compose.override.yml"; then
    updateFile docker-compose.override.yml
  fi

}

if [ $# -gt 0 ]; then
  updateDocker $1
else
  selectVersion
fi
