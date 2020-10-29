require 'json'
require 'socket'
require 'resolv'

NETFLOW = "netflow"

def is_debug
  if ENV["DEBUG"] == "true"
    return true
  end
  false
end

def clear_event(event)
  #Remove all keys in event except the ones listed below
  event.to_hash.each { |k, v|
    unless ["@timestamp", "@version", "host", "message"].include?(k)
      event.remove(k)
    end
  }
end


def process_netflow_data(event)
  if is_debug
    puts "Event type is %s" % event.class
  end
  puts "Identified as netflow"
  data = event.to_hash
  clear_event(event)

  if is_debug
    event.set('raw_message', data.to_json)
  end

  event.set("type", "flow")
  event.set("interval", 600)

  values = Hash.new
  meta = Hash.new

  meta["sensor_id"] = data["meta"]["sensor_id"]
  meta["instance_id"] = data["meta"]["instance_id"]
  meta["flow_type"] = NETFLOW

  meta["src_ip"] = data["ip_src"]
  meta["dst_ip"] = data["ip_dst"]
  meta["src_port"] = data["port_src"]
  meta["dst_port"] = data["port_dst"]
  ## If regex matching on IP is needed
  # if data["ip_src"] =~  Resolv::IPv4::Regex
  meta["protocol"] = data["ip_proto"]
  meta["dst_asn"] = data["as_dst"]
  meta["src_asn"] = data["as_src"]
  meta["src_ifindex"] = data["iface_in"]
  meta["dst_ifindex"] = data["iface_out"]

  event.set("start", data["timestamp_start"])
  event.set("end", data["timestamp_end"])
  values["duration"] = Float(event.get("end")) - Float(event.get("start"))

  values["num_packets"] = data["packets"]
  values["num_bits"] = data["bytes"] * 8
  if values["duration"] > 0
    values["packets_per_second"] = Integer(values["num_packets"] / values["duration"])
    values["bits_per_second"] = Integer(values["num_bits"] / values["duration"])
  else
    values["packets_per_second"] = 0
    values["bits_per_second"] = 0
  end

  event.set("values", values)
  event.set("meta", meta)

  return [event]
end

def filter(event)
  if event.get("[meta][flow_type]") == NETFLOW
    return process_netflow_data(event)
    # else
    #   return [event]
  end
  [event]
end
