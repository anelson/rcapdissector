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
end
