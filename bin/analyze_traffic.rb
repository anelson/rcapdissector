require 'optparse'
require 'logger'
require 'rcapdissector'

def main(*args)
    opts = {
        :cap_files => [],
        :wlan_keys => [],
    }
    
    $log = Logger.new(STDOUT)
    $log.level = Logger::INFO
    
    opt_parser = OptionParser.new
    
    opt_parser.on("-v", 
        "--verbose", 
        "Turns on verbose logging") {|val| 
            $log.level  = Logger::DEBUG
        }
    
    opt_parser.on("-k ARG", 
        "--wlan-key ARG", 
        "Specifies a WEP or WPA/WPA2 decryption key for decrypting encrypted WLAN packets") {|val| 
            opts[:wlan_keys] << val
        }
    
    remaining_args = opt_parser.parse(*args)
    
    if remaining_args.length == 0
        puts opts.to_s
        exit(-1)
    end
    
    opts[:cap_files] = remaining_args
    
    # Set the decrypt keys
    $log.debug "Using WLAN decryption key(s) #{opts[:wlan_keys].join(',')}"
    CapDissector::CapFile.set_wlan_decryption_keys(opts[:wlan_keys])

    stats = {
        :capture_files => 0,
        :packets => 0,
        :hosts => {},
        :ports => {},
        :protocols => {}
    }

    stats[:hosts].default = 0
    stats[:ports].default = 0
    stats[:protocols].default = 0

    opts[:cap_files].each do |file|
        analyze_file file, stats
        dump_stats stats
    end

    dump_stats stats
end

def dump_stats(stats)
    $log.info "Captured traffic stats: "
    $log.info "  #{stats[:capture_files]} capture file(s) processed"
    $log.info "  #{stats[:packets]} packet(s) processed"
    $log.info "  Hosts:"
    dump_sorted_packet_count(stats[:hosts])
    $log.info "  TCP Ports:"
    dump_sorted_packet_count(stats[:ports])

    $log.info "  Wireshark Protocols:"
    dump_sorted_packet_count(stats[:protocols])

end

# Dumps a hash where the key is some packet attribute and the value is the number of packets
# with that attribute.  Sorts by packet count (largest first) and outputs
def dump_sorted_packet_count(packet_counts)
    packet_counts.sort { |a,b| b[1] <=> a[1]}.each do |nvp|
        $log.info "    #{nvp[0]} (#{nvp[1]} packets)"
    end
end

def get_serv_by_port(port)
    #TODO: Someday Ruby will expose the getservbyport system call; on that day, start using that instead of this hack
    port = port.to_i(10)

    case port
        when 80: "http"
        when 21: "ftp"
        when 22: "ssh"
        when 25: "smtp"
        when 110: "pop"
        when 53: "dns"
        when 443: "https"
        else
            if port < 1024
                port.to_s
            else
                "Unrecognized or ephemeral port"
            end
    end
end

def simplify_hostname(hostname)
    #Strips a DNS name to the TLD only
    components = hostname.split(".").reverse

    if ["com", "net", "org", "edu", "mil", "gov"].include?(components[0].downcase)
        components[1].downcase + "." + components[0].downcase
    else
        hostname.downcase
    end
end

def analyze_file(file, stats)
    $log.info "Analyzing capture file #{file}"
        
    packet_count = 0

    dissector = CapDissector::CapFile.new(file)

    begin
        dissector.each_packet do |packet|  
            if packet_count % 100 == 0
                if ($log.level <= Logger::INFO) 
                    printf "Processed #{packet_count} packets\r"
                end
            end
            packet_count += 1
    
            #Try to extract a hostname from this packet
            hostname = packet.find_first_field('http.host')
            if hostname != nil
                stats[:hosts][simplify_hostname(hostname.display_value)] += 1
                hostname = nil
            end
    
            packet.each_field('dns.resp.name') do |field|
                stats[:hosts][simplify_hostname(field.display_value)] += 1
            end
    
            packet.each_field('tcp.port') do |field|
                port = get_serv_by_port(field.display_value)
                stats[:ports][port] += 1
            end
    
            packet.each_root_field do |field|
                stats[:protocols][field.name] += 1
            end
        end
    rescue CapDissector::WtapCapFileError
        if $!.error_code == CapDissector::WtapCapFileError.WTAP_ERR_SHORT_READ
            # The packet file was truncated, perhaps by a crash on the node doing the capturing
            # Don't worry about it
            $log.warn "Capture file #{file} was truncated prematurely, possibly due to a crash on the capturing node"
        else
            $log.error "Wireshark error while processing #{file}: #{$!}"
        end
        dissector.close
        raise
    rescue CapDissector::CapFileError
        $log.error "CapDissector error while processing #{file}: #{$!}"
        dissector.close
        raise
    end

    dissector.close
    
    # Start a new line after the 'Processed n packets' line
    if ($log.level <= Logger::INFO) 
        puts
    end
    
    $log.info "Packet Count: #{packet_count}"
    stats[:packets] += packet_count
    stats[:capture_files] += 1
end

main(*ARGV)
