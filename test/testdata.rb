require 'test/unit'

require 'capdissector'

module TestData
    TEST_DATA_DIR = File.dirname(__FILE__) + "\\testdata\\"

    BOGUS_CAP = TEST_DATA_DIR + 'nonexistantcapturefile'
    CORRUPTED_CAP = TEST_DATA_DIR + 'corrupted.cap'
    TEST_CAP = TEST_DATA_DIR + 'test.cap'
    HUGE_CAP = TEST_DATA_DIR + 'huge_dump.cap'
    SINGLE_HTTP_REQ_CAP = TEST_DATA_DIR + 'single_http_request.cap'
    WEP_ENCRYPTED_CAP = TEST_DATA_DIR + 'bradenton_wep.pcap'

    WEP_ENCRYPTED_CAP_KEY = "6D0F9AD408"
    WEP_ENCRYPTED_CAP_INCORRECT_KEY = "5BB99DA271"
end

