require 'optparse'
require 'logger'
require 'capdissector'

opts = {
    :cap_file => nil,
    :list_wireless_aps => false,
    :benchmarks => false,
    :wireshark_prefs => [],
    :display_filter => nil
}

log = Logger.new(STDOUT)
log.level = Logger::INFO

opt_parser = OptionParser.new
# Define 'WiresharkPref' as an option type, consisting of a name=value pair
class WiresharkPref
    attr_reader :name
    attr_reader :value

    def initialize(name, value)
        @name = name
        @value = value
    end
end

opt_parser.accept(WiresharkPref, /([[:alnum:]\._]+)\=(.+)/) do |nvp, name, value|
    WiresharkPref.new(name, value)
end

opt_parser.on("-w", 
    "--wireless", 
    "Collects and displays information about wireless networks in the capture") {|val| 
        opts[:list_wireless_aps] = true
    }

opt_parser.on("-b", 
    "--benchmarks", 
    "Collects and displays information about the time spent processing the capture") {|val| 
        opts[:benchmarks] = true
    }

opt_parser.on("-p NVP", 
    "--preference NVP", 
    WiresharkPref, 
    "Sets a named Wireshark preference of the form name=value") {|val| 
        opts[:wireshark_prefs] << val
    }

opt_parser.on("-v", 
    "--verbose", 
    "Turns on verbose logging") {|val| 
        log.level  = Logger::DEBUG
    }

opt_parser.on("-f ARG", 
    "--ilter ARG", 
    "Sets a display filter in Wireshark syntax to apply to the file") {|val| 
        opts[:display_filter] = val
    }

remaining_args = opt_parser.parse(*ARGV)

if remaining_args.length != 1
    opts.to_s
    exit(-1)
end

opts[:cap_file] = remaining_args[0]

# APply the preferences
opts[:wireshark_prefs].each do |nvp|
    log.debug "Setting #{nvp.name} to #{nvp.value}"
    CapDissector::CapFile.set_preference(nvp.name, nvp.value)
end

log.info "Dumping capture file #{opts[:cap_file]}"

dissector = CapDissector::CapFile.new(opts[:cap_file])
if opts[:display_filter]
    log.debug "Setting display filter '#{opts[:display_filter]}'"
    dissector.set_display_filter opts[:display_filter]
end

packet_count = 0
wlan_aps = {}
benchmarks = {}

if opts[:benchmarks]
    log.debug "Initializing benchmarks"
    benchmarks[:best_packet_time] = 0
    benchmarks[:worst_packet_time] = 0
    benchmarks[:total_packet_time] = 0
    benchmarks[:end_time] = nil
    benchmarks[:start_time] = Time.now
end

dissector.each_packet do |packet|    
    if packet_count % 100 == 0
        if (log.level >= Logger::INFO) 
            printf "Processed #{packet_count} packets\r"
        end
    end
    packet_count += 1

    if opts[:benchmarks]
        packet_start_time = Time.now
    end

    if opts[:list_wireless_aps]
        # Look for a WLAN tag containing the SSID
        ssid_tag = packet.find_first_field_match(Proc.new {|query|
            query.name_is?("wlan_mgt.tag.interpretation") &&
            query.sibling_matches?(Proc.new {|sib_query|
                sib_query.name_is?("wlan_mgt.tag.number") &&
                sib_query.value_is?([0])
            })
        })
    
        if ssid_tag != nil
            wlan_aps[ssid_tag.display_value] = 0 if wlan_aps[ssid_tag.display_value] == nil
            wlan_aps[ssid_tag.display_value] += 1
        end
    end

    if opts[:benchmarks]
        packet_end_time = Time.now
        packet_processing_time = (packet_end_time - packet_start_time)

        benchmarks[:total_packet_time] += packet_processing_time

        if benchmarks[:best_packet_time] == 0 ||
           benchmarks[:best_packet_time] > packet_processing_time
            benchmarks[:best_packet_time] = packet_processing_time
        end

        if benchmarks[:worst_packet_time] == 0 ||
           benchmarks[:worst_packet_time] < packet_processing_time
            benchmarks[:worst_packet_time] = packet_processing_time
        end
    end
end

if opts[:benchmarks]
    benchmarks[:end_time] = Time.now
end

#puts

log.info "Packet Count: #{packet_count}"
if opts[:list_wireless_aps]
    log.info "#{wlan_aps.length} WLAN APs detected."
    wlan_aps.each_pair do |ap_name, ap_packet_count|
        log.info "\tWLAN AP: #{ap_name} (#{ap_packet_count} packets)"
    end
end

if opts[:benchmarks]
    total_packet_processing_time = benchmarks[:end_time] - benchmarks[:start_time]

    log.info "#{packet_count} packet(s) processed in #{total_packet_processing_time} seconds (#{packet_count/total_packet_processing_time} packets/sec)"
    log.info "Total time spent executing each_packet block: #{benchmarks[:total_packet_time]} seconds"
    log.info "Fastest each_packet block run time: #{benchmarks[:best_packet_time]} seconds"
    log.info "Slowest each_packet block run time: #{benchmarks[:worst_packet_time]} seconds"
    log.info "Mean each_packet block run time: #{benchmarks[:total_packet_time] / packet_count} seconds"
end

