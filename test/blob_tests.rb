require 'test/unit'
require 'yaml'

require 'capdissector'
require File.dirname(__FILE__) + '\testdata'

include TestData

class BlobTests < Test::Unit::TestCase
    def test_frame_blob
        SMALLISH_CAPS.each do |file|
            capfile = CapDissector::CapFile.new(file)
    
            capfile.each_packet() do |packet|
                has_frame_blob = false
    
                #The contents of the frame captured from the wire are exposed in
                #a blob called 'Frame (n bytes)'
                #Every packet should have at least that blob
                packet.blobs.each do |key, value|
                    if key.include?("Frame")
                        has_frame_blob = true
                        break
                    end
                end
    
                assert_equal(true, has_frame_blob)
            end
        end
    end

    def test_field_blob_value_equals_field_value
        SMALLISH_CAPS.each do |file|
            capfile = CapDissector::CapFile.new(file)
    
            capfile.each_packet() do |packet|
                packet.each_field do |field|
                    return unless field.value != nil
    
                    assert_not_equal(nil, field.value_blob,
                        "The field #{field.name} has no value blob!")
    
                    assert_equal(field.value,
                        field.value_blob.value[field.value_blob_offset, field.value_blob_length],
                        "The Field.value property for #{field.name} doesn't match the value from the blob #{field.value_blob.name} at [#{field.value_blob_offset}, #{field.value_blob_length}]")
                end
            end
        end
    end
end
