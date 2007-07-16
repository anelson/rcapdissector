require 'test/unit'

require 'capdissector'
require File.dirname(__FILE__) + '\testdata'

include TestData

class PacketTests < Test::Unit::TestCase
    def test_each_packet
        capfile = CapDissector::CapFile.new(TEST_CAP)
        count = 0

        capfile.each_packet() do |packet|
            count += 1
            assert_equal(packet.capfile.capture_file, capfile.capture_file)
        end

        assert_not_equal(0, count)
    end

    def test_load_time
        capfile = CapDissector::CapFile.new(TEST_CAP)
        count = 0

        capfile.each_packet() do |packet|
            count += 1
        end

        puts "Read #{count} packets"
    end

    def test_field_exists
        capfile = CapDissector::CapFile.new(TEST_CAP)
        ip_count = 0
        bogus_count = 0

        capfile.each_packet() do |packet|
            if packet.field_exists?("ip")
                ip_count += 1
            end
            if packet.field_exists?("fuckoffanddie")
                bogus_count += 1
            end
        end

        assert_not_equal(0, ip_count)
        assert_equal(0, bogus_count)
    end

    def test_find_first_field
        capfile = CapDissector::CapFile.new(TEST_CAP)

        capfile.each_packet() do |packet|
            eth = packet.find_first_field("eth")
            assert(eth != nil)

            bogus = packet.find_first_field("nofuckingway")
            assert(bogus == nil)
        end
    end

    def test_descendant_field_exists
        capfile = CapDissector::CapFile.new(TEST_CAP)

        capfile.each_packet() do |packet|
            eth = packet.find_first_field("eth")

            # The descenant field 'eth.type' should exist, but
            # the field 'frame' (which is present in all packets)
            # isn't a child of 'eth' and thus shouldn't exist
            assert_equal(true, packet.descendant_field_exists?(eth, "eth.type"))
            assert_equal(true, packet.descendant_field_exists?(eth, "eth.ig"))
            assert_equal(false, packet.descendant_field_exists?(eth, "frame"))
            assert_equal(false, packet.descendant_field_exists?(eth, "bogus"))
        end
    end

    def test_each_field
        capfile = CapDissector::CapFile.new(TEST_CAP)

        capfile.each_packet() do |packet|
            field_count = 0
            packet.each_field do |field|
                field_count += 1
            end
            assert_not_equal(0, field_count)
        end
    end

    def test_find_first_descendant_field
        capfile = CapDissector::CapFile.new(TEST_CAP)

        capfile.each_packet() do |packet|
            eth = packet.find_first_field("eth")

            # There should be two 'eth.addr' fields under 'eth'
            addr = packet.find_first_descendant_field(eth, 'eth.addr')
            assert_not_equal(nil, addr)

            # No 'ip' fields under 'eth
            ip = packet.find_first_descendant_field(eth, 'ip')
            assert_equal(nil, ip)
        end
    end

    def test_each_descendant_field
        capfile = CapDissector::CapFile.new(TEST_CAP)

        capfile.each_packet() do |packet|
            eth = packet.find_first_field("eth")
            descendantCount = 0
            packet.each_descendant_field(eth) do |field|
                descendantCount += 1
                # Try to find this field.  It should exist
                desc = packet.find_first_descendant_field(eth, field.name)
                assert_not_equal(nil, desc)
            end

            assert_not_equal(0, descendantCount)
        end
    end

    def test_each_root_field
        capfile = CapDissector::CapFile.new(SINGLE_HTTP_REQ_CAP)

        capfile.each_packet() do |packet|
            num_root_fields = 0

            #This packet is known to have six 'root' fields, each one corresponding
            #to a protocol
            packet.each_root_field do |field|
                num_root_fields += 1
            end

            assert_equal(5, num_root_fields)
        end
    end

    def test_field_matches
        capfile = CapDissector::CapFile.new(TEST_CAP)

        capfile.each_packet() do |packet|
            assert_equal(true, packet.field_matches?(Proc.new {|query| query.name_is? 'eth.dst'}))
            assert_equal(false, packet.field_matches?(Proc.new {|query| query.name_is? 'quidgibo'}))
        end
    end

    def test_decendant_field_matches
        capfile = CapDissector::CapFile.new(TEST_CAP)

        capfile.each_packet() do |packet|
            eth = packet.find_first_field("eth")
            assert_not_equal(nil, eth)
            assert_equal(true, packet.descendant_field_matches?(eth, Proc.new {|query| query.name_is? 'eth.ig'}))
            assert_equal(false, packet.descendant_field_matches?(eth, Proc.new {|query| query.name_is? 'ip'}))
        end
    end

    def test_find_first_field_match
        capfile = CapDissector::CapFile.new(TEST_CAP)

        capfile.each_packet() do |packet|
            eth_addr = packet.find_first_field_match(Proc.new {|query| query.name_is? 'eth.addr'})
            assert_not_equal(nil, eth_addr)

            quidgibo = packet.find_first_field_match(Proc.new {|query| query.name_is? 'quidgibo'})
            assert_equal(nil, quidgibo)
        end
    end

    def test_each_field_match
        capfile = CapDissector::CapFile.new(TEST_CAP)

        capfile.each_packet() do |packet|
            eth_count = 0
            ip_version_count = 0
            bogus_count = 0
            packet.each_field_match(Proc.new {|query| query.name_is? 'eth'}) do |field| 
                eth_count += 1
            end
            packet.each_field_match(Proc.new {|query| query.name_is? 'ip.version'}) do |field| 
                ip_version_count += 1
            end
            packet.each_field_match(Proc.new {|query| query.name_is? 'bogus'}) do |field| 
                bogus_count += 1
            end

            assert_equal(true, eth_count > 0)
            assert_equal(true, ip_version_count > 0)
            assert_equal(true, bogus_count == 0)
        end
    end

    def test_find_first_descendant_field_match
        capfile = CapDissector::CapFile.new(TEST_CAP)

        capfile.each_packet() do |packet|
            eth = packet.find_first_field_match(Proc.new {|query| query.name_is? 'eth'})
            assert_not_equal(nil, eth)

            eth_addr = packet.find_first_descendant_field_match(eth, Proc.new {|query| query.name_is? 'eth.addr'})
            assert_not_equal(nil, eth_addr)

            quidgibo = packet.find_first_descendant_field_match(eth, Proc.new {|query| query.name_is? 'frame'})
            assert_equal(nil, quidgibo)
        end
    end

    def test_each_descendant_field_match
        capfile = CapDissector::CapFile.new(TEST_CAP)

        capfile.each_packet() do |packet|
            eth = packet.find_first_field_match(Proc.new {|query| query.name_is? 'eth'})
            assert_not_equal(nil, eth)

            eth_addr_count = 0
            ip_version_count = 0
            bogus_count = 0
            packet.each_descendant_field_match(eth, Proc.new {|query| query.name_is? 'eth.addr'}) do |field| 
                eth_addr_count += 1
            end
            packet.each_descendant_field_match(eth, Proc.new {|query| query.name_is? 'ip.version'}) do |field| 
                ip_version_count += 1
            end
            packet.each_descendant_field_match(eth, Proc.new {|query| query.name_is? 'bogus'}) do |field| 
                bogus_count += 1
            end

            assert_equal(true, eth_addr_count > 0)
            assert_equal(true, ip_version_count == 0)
            assert_equal(true, bogus_count == 0)
        end
    end
end
