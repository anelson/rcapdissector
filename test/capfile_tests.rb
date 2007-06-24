require 'test/unit'

require 'capdissector'

class CapfileTests < Test::Unit::TestCase
    TEST_CAP = File.dirname(__FILE__) + '\testdata\test.cap'
    HUGE_CAP = File.dirname(__FILE__) + '\testdata\huge_dump.cap'

    def test_instance
        capfile = CapDissector::CapFile.new(TEST_CAP)
    end

    def test_capture_file_property
        capfile = CapDissector::CapFile.new(TEST_CAP)

        assert_equal(TEST_CAP, capfile.capture_file)
    end

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
        capfile = CapDissector::CapFile.new(HUGE_CAP)
        count = 0

        capfile.each_packet() do |packet|
            count += 1
        end

        puts "Read #{count} packets"
    end

    def test_field_exists
        capfile = CapDissector::CapFile.new(HUGE_CAP)
        ip_count = 0

        capfile.each_packet() do |packet|
            if packet.field_exists?("ip")
                ip_count += 1
            end
        end

        assert_not_equal(0, ip_count)
    end

    def test_each_field
        capfile = CapDissector::CapFile.new(HUGE_CAP)

        capfile.each_packet() do |packet|
            field_count = 0
            packet.each_field do |field|
                field_count += 1
            end
            assert_not_equal(0, field_count)
        end
    end

    def test_each_field_name
        capfile = CapDissector::CapFile.new(HUGE_CAP)

        capfile.each_packet() do |packet|
            packet.each_field do |field|
                assert_not_equal(nil, field.name)
            end
        end
    end
end
