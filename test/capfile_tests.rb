require 'test/unit'

require 'capdissector'
require File.dirname(__FILE__) + '\testdata'

include TestData

class CapfileTests < Test::Unit::TestCase

    def test_instance
        capfile = CapDissector::CapFile.new(TEST_CAP)
    end

    def test_capture_file_property
        capfile = CapDissector::CapFile.new(TEST_CAP)

        assert_equal(TEST_CAP, capfile.capture_file)
    end

    def test_bogus_capture_file
        exception_thrown = false

        begin
            capfile = CapDissector::CapFile.new(BOGUS_CAP)

            fail("CapFile.new succeeded for a non-existent cap file path")
        rescue CapDissector::CapFileError
            exception_thrown = true
        end

        assert_equal(true, exception_thrown)
    end

    def test_corrupted_capture_file
        exception_thrown = false

        begin
            capfile = CapDissector::CapFile.new(CORRUPTED_CAP)

            fail("CapFile.new succeeded for a corrupted cap file path")
        rescue CapDissector::CapFileError
            exception_thrown = true
        end

        assert_equal(true, exception_thrown)
    end

    def test_set_bogus_preference
        exception_thrown = false

        begin
            CapDissector::CapFile.set_preference("tcp.fuckyou", "whatever")
            fail("CapFile.set_preference succeeded for a bogus preference value")
        rescue CapDissector::CapFileError
            exception_thrown = true
        end

        assert_equal(true, exception_thrown)
    end

    def test_set_valid_preference
        exception_thrown = false

        CapDissector::CapFile.set_preference(CapDissector::CapFile::PREF_TCP_CHECK_CHECKSUM, 
            'true')
    end

    def test_set_bogus_filter
        exception_thrown = false

        begin
            capfile = CapDissector::CapFile.new(TEST_CAP)
            capfile.set_display_filter("wtf does this do?")
            fail("CapFile.set_display_filter succeeded for a bogus filter")
        rescue CapDissector::CapFileError
            exception_thrown = true
        end

        assert_equal(true, exception_thrown)
    end

    def test_set_valid_filter
        capfile = CapDissector::CapFile.new(HUGE_CAP)

        num_ip_packets = 0
        capfile.each_packet do |packet|
            ip = packet.find_first_field('ip')
            num_ip_packets += 1 unless ip == nil
        end
        assert_equal(true, num_ip_packets > 0)

        capfile = CapDissector::CapFile.new(HUGE_CAP)
        capfile.set_display_filter('ip')

        num_filtered_packets = 0
        capfile.each_packet do |packet|
            num_filtered_packets += 1
        end

        assert_equal(num_ip_packets, num_filtered_packets)
    end
end
