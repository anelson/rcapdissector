require 'optparse'
require 'capdissector'

opts = {
    :cap_file => nil,
    :list_wireless_aps => false,
    :benchmarks => false
}

opt_parser = OptionParser.new
opt_parser.on("-w") {|val| opts[:list_wireless_aps] = true}
opt_parser.on("-b") {|val| opts[:benchmarks] = true}

remaining_args = opt_parser.parse(*ARGV)

if remaining_args.length != 1
    opts.to_s
    exit(-1)
end

opts[:cap_file] = remaining_args[0]

puts "Dumping capture file #{opts[:cap_file]}"

dissector = CapDissector::CapFile.new(opts[:cap_file])

packet_count = 0
wlan_aps = {}
benchmarks = {}

if opts[:benchmarks]
    benchmarks[:best_packet_time] = 0
    benchmarks[:worst_packet_time] = 0
    benchmarks[:total_packet_time] = 0
    benchmarks[:end_time] = nil
    benchmarks[:start_time] = Time.now
end

dissector.each_packet do |packet|    
    if packet_count % 100 == 0
        printf "\rProcessed #{packet_count} packets"
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

puts

puts "Packet Count: #{packet_count}"
if opts[:list_wireless_aps]
    puts "#{wlan_aps.length} WLAN APs detected."
    wlan_aps.each_pair do |ap_name, ap_packet_count|
        puts "\tWLAN AP: #{ap_name} (#{ap_packet_count} packets)"
    end
end

if opts[:benchmarks]
    total_packet_processing_time = benchmarks[:end_time] - benchmarks[:start_time]

    puts "#{packet_count} packet(s) processed in #{total_packet_processing_time} seconds (#{packet_count/total_packet_processing_time} packets/sec)"
    puts "Total time spent executing each_packet block: #{benchmarks[:total_packet_time]} seconds"
    puts "Fastest each_packet block run time: #{benchmarks[:best_packet_time]} seconds"
    puts "Slowest each_packet block run time: #{benchmarks[:worst_packet_time]} seconds"
    puts "Mean each_packet block run time: #{benchmarks[:total_packet_time] / packet_count} seconds"
end

