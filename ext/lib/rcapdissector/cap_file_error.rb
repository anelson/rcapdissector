#!/usr/bin/ruby -w
require 'rcapdissector'

module CapDissector
    class CapFileError < Exception
        
        def initialize(message, error_code = 0)
            super(message)
        end
    end

    class WtapCapFileError < CapFileError
        WTAP_ERR_NOT_REGULAR_FILE = -1
        WTAP_ERR_RANDOM_OPEN_PIPE = -2
        WTAP_ERR_FILE_UNKNOWN_FORMAT = -3
        WTAP_ERR_UNSUPPORTED = -4
        WTAP_ERR_CANT_WRITE_TO_PIPE = -5
        WTAP_ERR_CANT_OPEN = -6
        WTAP_ERR_UNSUPPORTED_FILE_TYPE = -7
        WTAP_ERR_UNSUPPORTED_ENCAP = -8
        WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED = -9
        WTAP_ERR_CANT_CLOSE = -10
        WTAP_ERR_CANT_READ = -11
        WTAP_ERR_SHORT_READ = -12
        WTAP_ERR_BAD_RECORD = -13
        WTAP_ERR_SHORT_WRITE = -14
        WTAP_ERR_UNC_TRUNCATED = -15
        WTAP_ERR_UNC_OVERFLOW = -16
        WTAP_ERR_UNC_BAD_OFFSET = -17
        WTAP_ERR_RANDOM_OPEN_STDIN = -18
        WTAP_ERR_COMPRESSION_NOT_SUPPORTED = -19

        attr_reader :error_code

        def initialize(message, error_code = 0)
            super(message)
            @error_code = error_code
        end
    end
end


