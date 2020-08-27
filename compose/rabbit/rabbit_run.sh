#!/usr/bin/env bash
set -em

/usr/local/bin/docker-entrypoint.sh rabbitmq-server &

until nc -z -v -w30 localhost 15672; do
    echo "Waiting 5 second until rabbit is coming up..."
    sleep 5
done

## Ensure the queues are created on start
rabbitmqadmin declare queue name=${rabbitmq_input_key} durable=true
rabbitmqadmin declare binding source=amq.direct destination=${rabbitmq_input_key} routing_key=${rabbitmq_input_key}

fg %1
