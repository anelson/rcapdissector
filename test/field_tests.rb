require 'test/unit'

require 'rcapdissector'
require File.dirname(__FILE__) + '\testdata'

include TestData

class FieldTests < Test::Unit::TestCase
    def test_each_field_name
        capfile = CapDissector::CapFile.new(HUGE_CAP)

        capfile.each_packet() do |packet|
            packet.each_field do |field|
                assert_not_equal(nil, field.name)
            end
        end
    end

    def test_null_value
        capfile = CapDissector::CapFile.new(SINGLE_HTTP_REQ_CAP)
        capfile.each_packet() do |packet|
            field = packet.find_first_field('http.request')

            # field has no value; make sure it comes out that way
            assert_equal(nil, field.value)
        end
    end

    def test_known_field_count
        capfile = CapDissector::CapFile.new(SINGLE_HTTP_REQ_CAP)

        field_count = 0
        packet_count = 0

        capfile.each_packet() do |packet|
            packet_count += 1

            packet.each_field do |field|
                field_count += 1

                # puts "Field: #{field}"
            end
        end

        assert_equal(1, packet_count)
        assert_equal(90, field_count)
    end

    def test_known_field_contents
        capfile = CapDissector::CapFile.new(SINGLE_HTTP_REQ_CAP)

        capfile.each_packet() do |packet|
            frame = packet.find_first_field('frame.pkt_len')
            assert_not_equal(nil, frame)
            assert_equal('frame.pkt_len', frame.name)
            assert_equal('Packet Length: 1422 bytes', frame.display_name)
            assert_equal('1422', frame.display_value)
            assert_equal(nil, frame.value)

            ip_version = packet.find_first_field('ip.version')
            assert_not_equal(nil, ip_version)
            assert_equal('ip.version', ip_version.name)
            assert_equal('Version: 4', ip_version.display_name)
            assert_equal('4', ip_version.display_value)
            assert_equal("\x45", ip_version.value)

            # Find the nameless child field of 'http' that contains the http GET request
            # Make sure it's parsed out right
            http = packet.find_first_field('http')
            assert_not_equal(nil, http)
            http_get = packet.find_first_descendant_field(http, '')
            assert_not_equal(nil, http_get)
            assert_equal('', http_get.name)
            assert_equal(nil, http_get.display_name)
            assert_equal('GET /public/page/0_0018_Refresh.html HTTP/1.1\\r\\n', http_get.display_value)

            assert_equal("\x47\x45\x54\x20\x2f\x70\x75\x62\x6c\x69\x63\x2f\x70\x61\x67\x65\x2f\x30\x5f\x30\x30\x31\x38\x5f\x52\x65\x66\x72\x65\x73\x68\x2e\x68\x74\x6d\x6c\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a", http_get.value)
        end
    end

    def test_hierarchy
        capfile = CapDissector::CapFile.new(SINGLE_HTTP_REQ_CAP)

        capfile.each_packet() do |packet|
            #Verify the hierarchy methods are working
            eth = packet.find_first_field('eth')
            assert_equal(nil, eth.parent)
            assert_equal('ip', eth.next_sibling.name)
            child_count = 0
            eth.each_child do |field|
                assert_equal(eth, field.parent)
                child_count += 1
            end
            assert_equal(3, child_count)

            # Make sure the each_field iterator returns the same number
            # of fields as a tree traversal
            iter_fields = {}
            hier_fields = {}
            packet.each_root_field do |field|   
                add_field_to_hash field, hier_fields
            end

            packet.each_field do |field|
                if iter_fields[field.name] == nil
                    iter_fields[field.name] = []
                end
                iter_fields[field.name] << field
            end

            # Look for fields in iter not in hier
            iter_fields.each_pair do |key, value|
                if hier_fields[key] == nil
                    fail("Iter fields contains #{key} but hier fields does not")
                elsif hier_fields[key].length != iter_fields[key].length
                    fail("Iter fields contains #{iter_fields[key].length} instances of #{key}")
                end
            end

            #Look for fields in hier not in iter
            #(Don't need to compare field counts, since that's done above
            hier_fields.each_pair do |key, value|
                if hier_fields[key] == nil
                    fail("Hier fields contains #{key} but iter fields does not")
                end
            end
        end
    end

    def add_field_to_hash(field, hash)
        if hash[field.name] == nil
            hash[field.name] = []
        end
        hash[field.name] << field

        field.each_child do |child|
            add_field_to_hash child, hash
        end
    end
end
