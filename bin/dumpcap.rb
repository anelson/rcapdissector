require 'optparse'
require 'capdissector'

cap_file = nil
list_wireless_aps = false

opts = OptionParser.new
opts.on("-w") {|val| list_wireless_aps = true}

remaining_args = opts.parse(*ARGV)

if remaining_args.length != 1
    opts.to_s
    exit -1
end

cap_file = remaining_args[0]

puts "Dumping capture file #{cap_file}"

dissector = CapDissector::CapFile.new(cap_file)

packet_counts = 0
wlan_aps = {}

dissector.each_packet do |packet|
    if packet_counts % 100 == 0
        printf "\rProcessed #{packet_counts} packets"
    end
    packet_counts += 1

    if list_wireless_aps
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
end

puts

puts "Packet Count: #{packet_counts}"
if list_wireless_aps
    puts "#{wlan_aps.length} WLAN APs detected."
    wlan_aps.each_pair do |ap_name, packet_count|
        puts "\tWLAN AP: #{ap_name} (#{packet_count} packets)"
    end
end

