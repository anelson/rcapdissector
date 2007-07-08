require 'test/unit'

require 'capdissector'

module TestData
    TEST_DATA_DIR = File.dirname(__FILE__) + "\\testdata\\"

    BOGUS_CAP = TEST_DATA_DIR + 'nonexistantcapturefile'
    CORRUPTED_CAP = TEST_DATA_DIR + 'corrupted.cap'
    TEST_CAP = TEST_DATA_DIR + 'test.cap'
    HUGE_CAP = TEST_DATA_DIR + 'huge_dump.cap'
    SINGLE_HTTP_REQ_CAP = TEST_DATA_DIR + 'single_http_request.cap'
end

