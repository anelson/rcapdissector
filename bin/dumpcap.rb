require 'optparse'
require 'logger'
require 'rcapdissector'
require 'pp'

# Define 'WiresharkPref' as an option type, consisting of a name=value pair
class WiresharkPref
    attr_reader :name
    attr_reader :value

    def initialize(name, value)
        @name = name
        @value = value
    end
end

def main(*args)
    opts = {
        :cap_file => nil,
        :list_wireless_aps => false,
        :benchmarks => false,
        :wireshark_prefs => [],
        :display_filter => nil,
        :show_packets => false,
        :show_packets_as_yaml => false,
        :wlan_keys => [],
        :traffic_analysis => nil,
        :dump_field_contents => [],
        :run_test_code => false
    }
    
    log = Logger.new(STDOUT)
    log.level = Logger::INFO
    
    opt_parser = OptionParser.new
    
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
        "--filter ARG", 
        "Sets a display filter in Wireshark syntax to apply to the file") {|val| 
            opts[:display_filter] = val
        }
    
    opt_parser.on("-s", 
        "--show-packets", 
        "Outputs the fields within each packet") {|val| 
            opts[:show_packets] = true
        }
    
    opt_parser.on("-y", 
        "--yaml", 
        "When combined with --show-packets, outputs packets in YAML") {|val| 
            opts[:show_packets_as_yaml] = true
        }
    
    opt_parser.on("-k ARG", 
        "--wlan-key ARG", 
        "Specifies a WEP or WPA/WPA2 decryption key for decrypting encrypted WLAN packets") {|val| 
            opts[:wlan_keys] << val
        }
    
    opt_parser.on("-t", 
        "--traffic", 
        "Analyze and display traffic information by host and protocol") {|val| 
            opts[:traffic_analysis] = {
                :hosts => {},
                :http => 0
            }
            opts[:traffic_analysis][:hosts].default = 0
        }
    
    opt_parser.on("-d FIELDNAME", 
        "--dump-field-contents FIELDNAME", 
        "Dump the raw contents of each field called FIELDNAME to a separate file") {|val| 
            opts[:dump_field_contents] << val
        }
    
    opt_parser.on("-x", 
        "--test", 
        "Run the per-packet test code") {|val|
            opts[:run_test_code] = true
        }
    
    remaining_args = opt_parser.parse(*args)
    
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

    # Set the decrypt keys
    log.debug "Using WLAN decryption key(s) #{opts[:wlan_keys].join(',')}"
    CapDissector::CapFile.set_wlan_decryption_keys(opts[:wlan_keys])
    
    log.info "Dumping capture file #{opts[:cap_file]}"
    
    dissector = CapDissector::CapFile.new(opts[:cap_file])
    if opts[:display_filter]
        log.debug "Setting display filter '#{opts[:display_filter]}'"
        dissector.set_display_filter opts[:display_filter]
    end
    
    packet_count = 0
    wlan_aps = {}
    benchmarks = {}

    if !opts[:dump_field_contents].empty?
        #Initialize a hash to keep track of the counts of each dumped field
        dumped_field_count = {}
        dumped_field_count.default = 0
    end
    
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
            if (log.level <= Logger::INFO) 
                printf "Processed #{packet_count} packets\r"
            end
        end
        packet_count += 1
    
        if opts[:benchmarks]
            packet_start_time = Time.now
        end

        if opts[:run_test_code]
            per_packet_test(packet)
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

        if opts[:traffic_analysis]
            #Try to extract a hostname from this packet
            hostname = packet.find_first_field('http.host')
            if hostname != nil
                opts[:traffic_analysis][:hosts][hostname.display_value] += 1
            end

            hostname = packet.each_field('dns.resp.name') do |field|
                opts[:traffic_analysis][:hosts][field.display_value] += 1
            end

            opts[:traffic_analysis][:http] += 1 unless packet.find_first_field('http') == nil
        end
    
        if opts[:show_packets]
            output_packet packet, opts[:show_packets_as_yaml]
        end

        opts[:dump_field_contents].each do |fieldname|
            #For each field to dump, attempt to locate it in the 
            #packet.  Could use Packet.each_field_match and provide a block
            #to check for the field name in the dump_field_contents array,
            #but that's much more expensive.  Packet.each_field is a high-speed
            #operation that doesn't require excessive Ruby object creation overhead
            packet.each_field(fieldname) do |field|
                if field.value.empty?
                    log.debug "Field #{fieldname} in packet #{packet_count} has zero-length value; skipping dump"
                    return
                end

                dumped_field_count[fieldname] += 1

                filename = "#{fieldname}-#{dumped_field_count[fieldname]}.dump"

                log.debug "Writing #{field.value.length} data bytes in field #{fieldname} to file #{filename}"

                File.open(filename, "w") do |f| 
                    f.binmode 
                    f.write field.value
                end
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
    
    # Start a new line after the 'Processed n packets' line
    if (log.level <= Logger::INFO) 
        puts
    end
    
    log.info "Packet Count: #{packet_count}"
    if opts[:list_wireless_aps]
        log.info "#{wlan_aps.length} WLAN APs detected."
        wlan_aps.each_pair do |ap_name, ap_packet_count|
            log.info "\tWLAN AP: #{ap_name} (#{ap_packet_count} packets)"
        end
    end

    if opts[:traffic_analysis]
        log.info "Host traffic counts: "

        opts[:traffic_analysis][:hosts].each_pair do |hostname, count|
            log.info "\t#{hostname} (#{count} packets)"
        end

        log.info "#{opts[:traffic_analysis][:http]} HTTP packet(s)"
    end
    
    if opts[:benchmarks]
        total_packet_processing_time = benchmarks[:end_time] - benchmarks[:start_time]
    
        log.info "#{packet_count} packet(s) processed in #{total_packet_processing_time} seconds (#{packet_count/total_packet_processing_time} packets/sec)"
        log.info "Total time spent executing each_packet block: #{benchmarks[:total_packet_time]} seconds"
        log.info "Fastest each_packet block run time: #{benchmarks[:best_packet_time]} seconds"
        log.info "Slowest each_packet block run time: #{benchmarks[:worst_packet_time]} seconds"
        log.info "Mean each_packet block run time: #{benchmarks[:total_packet_time] / packet_count} seconds"
    end
end

def per_packet_test(packet)
    #Put experimental code here before integrating into the dumpcap app

    #Experiment: Does the position/length values for each field, when applied to the
    #raw data for the entire packet, return the same value as the value property?
    frame = packet.find_first_field('frame')
    raise 'Unexpectedly missing frame field' unless frame != nil

    entire_packet_value = frame.value

    # Find a small obscure field deep in the packet
    compare_field = packet.find_first_field('image-jfif')
    if compare_field == nil
        compare_field = packet.find_first_field('http.host')
        if compare_field == nil
            compare_field = packet.find_first_field('tcp.flags')
            if compare_field == nil
                compare_field = packet.find_first_field('wlan.flags')
                return unless compare_field != nil
            end
        end
    end

    #Does this offset and length fit in the frame's value buffer?
    if compare_field.position >= entire_packet_value.length
        raise "Position of field #{compare_field.name} within packet is #{compare_field.position}, but length of frame.value is only #{entire_packet_value.length}"
    end

    if compare_field.position + compare_field.length >= entire_packet_value.length
        raise "Position of end of field #{compare_field.name} within packet is #{compare_field.position + compare_field.length}, but length of frame.value is only #{entire_packet_value.length}"
    end

    if compare_field.value != entire_packet_value[compare_field.position, compare_field.length]
        raise "Field #{compare_field.name} reports value [#{compare_field.value}], which doesn't match data at frame's value buffer, at byte offset #{compare_field.position}, #{compare_field.length} bytes long: [#{entire_packet_value[compare_field.position, compare_field.length]}]"
    end
end

def output_packet(packet, as_yaml)
    output_packet_as_text(packet) unless as_yaml == true
    output_packet_as_yaml(packet) unless as_yaml != true
end

def output_packet_as_text(packet)
    packet.each_root_field do |field|
        output_field field, 0
    end
end

def output_packet_as_yaml(packet)
    puts packet.to_yaml
    #yaml = packet.ruby_to_yaml

    #fields_array = []

    #packet.each_root_field do |field|
        #add_field_to_array(field, fields_array)
    #end

    #p fields_array
    #YAML.dump(fields_array, STDOUT)
end

def add_field_to_array(field, fields_array)
    # Each field is represented by a hash
    field_hash = {}
    fields_array << field_hash

    if field.name != nil && field.name != ""
        #Top-level key of this field's hash will be the field's name
        field_hash[field.name] = {}
        field_hash = field_hash[field.name]
    else
        field_hash["<no name>"] = {}
        field_hash = field_hash["<no name>"]
    end

    if field.display_name != nil && field.display_name != ""
        field_hash['display_name'] = field.display_name
    end

    # The top-level 'protocol' fields shouldn't have values as they're just containers
    if field.is_protocol_node? == false && field.value != nil && field.value.length > 0
        value_string = ""
        field_hash['value'] = field.value
    end

    if field.display_value != nil && field.display_value != ""
        field_hash['display_value'] = field.display_value
    end

    field_hash['children'] = []

    field.each_child do |child_field|
        add_field_to_array(child_field, field_hash['children'])
    end

    field_hash.delete('children') unless field_hash['children'].length > 0
end

def output_field(field, indent_level) 
    #indent the field name by two spaces
    indent = ""
    indent_level.times { indent += "  "}

    if field.name != nil && field.name != ""
        puts indent + "#{field.name}:"
    else
        puts indent + "[no-name]:"
    end

    #indent the other field information by two more spaces
    indent += "  "

    if field.display_name != nil && field.display_name != ""
        puts indent + "Display Name: #{field.display_name}"
    end

    # The top-level 'protocol' fields shouldn't have values as they're just containers
    if field.is_protocol_node? == false && field.value != nil && field.value.length > 0
        value_string = ""
        field.value.each_byte do |byte|
            value_string << sprintf(" %02x", byte)
            #value_string << sprintf(" %02x", 0)
        end
        puts indent + "value:#{value_string}"
    end
    if field.display_value != nil && field.display_value != ""
        puts indent + "Display Value: #{field.display_value}"
    end

    field.each_child do |child_field|
        output_field child_field, indent_level + 2
    end
end

main(*ARGV)
