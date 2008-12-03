require 'test/unit'

require 'rcapdissector'
require File.dirname(__FILE__) + '/testdata'

include TestData

class FieldQueryTests < Test::Unit::TestCase
    def test_name_is_negative
        capfile = CapDissector::CapFile.new(SINGLE_HTTP_REQ_CAP)

        capfile.each_packet() do |packet|
            match = packet.field_matches? Proc.new { |query| 
                query.name_is?('quidgiebo')
            }
            assert_equal(false, match)
        end
    end

    def test_name_is_positive
        capfile = CapDissector::CapFile.new(SINGLE_HTTP_REQ_CAP)

        capfile.each_packet() do |packet|
            match = packet.field_matches? Proc.new { |query| 
                query.name_is?('tcp.flags.push')
            }
            assert_equal(true, match)
        end
    end

    def test_value_is_negative
        capfile = CapDissector::CapFile.new(SINGLE_HTTP_REQ_CAP)

        capfile.each_packet() do |packet|
            match = packet.field_matches? Proc.new { |query| 
                query.value_is? [0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89]
            }
            assert_equal(false, match)
        end
    end

    def test_value_is_positive
        capfile = CapDissector::CapFile.new(SINGLE_HTTP_REQ_CAP)

        capfile.each_packet() do |packet|
            match = packet.field_matches? Proc.new { |query| 
                query.value_is? [0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x6f, 0x6e, 0x6c, 0x69, 0x6e, 0x65, 0x2e, 0x77, 0x73, 0x6a, 0x2e, 0x63, 0x6f, 0x6d, 0x0d, 0x0a]
            }
            assert_equal(true, match)
        end
    end

    def test_display_value_is_negative
        capfile = CapDissector::CapFile.new(SINGLE_HTTP_REQ_CAP)

        capfile.each_packet() do |packet|
            match = packet.field_matches? Proc.new { |query| 
                query.display_value_is? "Fuck you and your little dog too"
            }
            assert_equal(false, match)
        end
    end

    def test_display_value_is_positive
        capfile = CapDissector::CapFile.new(SINGLE_HTTP_REQ_CAP)

        capfile.each_packet() do |packet|
            match = packet.field_matches? Proc.new { |query| 
                query.display_value_is? '/public/page/0_0018_Refresh.html'
            }
            assert_equal(true, match)
        end
    end

    def test_display_name_is_negative
        capfile = CapDissector::CapFile.new(SINGLE_HTTP_REQ_CAP)

        capfile.each_packet() do |packet|
            match = packet.field_matches? Proc.new { |query| 
                query.display_name_is? 'Shit for brains'
            }
            assert_equal(false, match)
        end
    end

    def test_display_name_is_positive
        capfile = CapDissector::CapFile.new(SINGLE_HTTP_REQ_CAP)

        capfile.each_packet() do |packet|
            match = packet.field_matches? Proc.new { |query| 
                query.display_name_is? "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.3) Gecko/20070309 Firefox/2.0.0.3\\r\\n"
            }
            assert_equal(true, match)
        end
    end

    def test_sibling_name_is_negative
        capfile = CapDissector::CapFile.new(SINGLE_HTTP_REQ_CAP)

        capfile.each_packet() do |packet|
            match = packet.field_matches? Proc.new { |query| 
                query.sibling_name_is? 'dickbob'
            }
            assert_equal(false, match)
        end
    end

    def test_sibling_name_is_positive
        capfile = CapDissector::CapFile.new(SINGLE_HTTP_REQ_CAP)

        capfile.each_packet() do |packet|
            match = packet.field_matches? Proc.new { |query| 
                query.sibling_name_is? 'http.request.method'
            }
            assert_equal(true, match)
        end
    end

    def test_sibling_matches_negative
        capfile = CapDissector::CapFile.new(SINGLE_HTTP_REQ_CAP)

        capfile.each_packet() do |packet|
            match = packet.field_matches? Proc.new { |query| 
                query.sibling_matches? Proc.new { |sib_query| 
                    sib_query.name_is? 'fuck.tard'
                }
            }
            assert_equal(false, match)
        end
    end

    def test_sibling_matches_positive
        capfile = CapDissector::CapFile.new(SINGLE_HTTP_REQ_CAP)

        capfile.each_packet() do |packet|
            match = packet.field_matches? Proc.new { |query| 
                query.sibling_matches? Proc.new { |sib_query| 
                    sib_query.name_is? 'http.request.method'
                }
            }
            assert_equal(true, match)
        end
    end

    def test_has_display_name
        capfile = CapDissector::CapFile.new(SINGLE_HTTP_REQ_CAP)

        capfile.each_packet() do |packet|
            # In each packet, some fields will have a display name
            # and some won't
            match = packet.field_matches? Proc.new { |query| 
                query.has_display_name?
            }
            assert_equal(true, match)

            match = packet.field_matches? Proc.new { |query| 
                !query.has_display_name?
            }
            assert_equal(true, match)
        end
    end

    def test_has_display_value
        capfile = CapDissector::CapFile.new(SINGLE_HTTP_REQ_CAP)

        capfile.each_packet() do |packet|
            # In each packet, some fields will have a display value
            # and some won't
            match = packet.field_matches? Proc.new { |query| 
                query.has_display_value?
            }
            assert_equal(true, match)

            match = packet.field_matches? Proc.new { |query| 
                !query.has_display_value?
            }
            assert_equal(true, match)
        end
    end

    def test_has_value
        capfile = CapDissector::CapFile.new(SINGLE_HTTP_REQ_CAP)

        capfile.each_packet() do |packet|
            # In each packet, some fields will have a display value
            # and some won't
            match = packet.field_matches? Proc.new { |query| 
                query.has_value?
            }
            assert_equal(true, match)

            match = packet.field_matches? Proc.new { |query| 
                !query.has_value?
            }
            assert_equal(true, match)
        end
    end

    def test_get_field
        capfile = CapDissector::CapFile.new(SINGLE_HTTP_REQ_CAP)

        capfile.each_packet() do |packet|
            match = packet.field_matches? Proc.new { |query| 
                query.name_is?('http.request.method') &&
                query.get_field.name == 'http.request.method'
            }
            assert_equal(true, match)
        end
    end
end

