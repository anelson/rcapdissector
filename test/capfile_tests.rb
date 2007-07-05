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
end
