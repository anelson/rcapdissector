require 'yaml'

# HACK
# YAML detects binary data in Ruby strings using a very simplistic heuristic that is sometimes
# wrong.  When I have a blob consisting of the hex value 0x0a, that serializes as a newline 
# then deserializes as an empty string.  Not helpful.  This special BinaryString class overrides
# YAML's binary detection logic with an always-binary
class BinaryString < String
    def is_binary_data?
        true
    end
end

# Mixin that adds a Ruby implementation of the to_yaml method, mostly for testing
# the C++ implementation of that method against a reference impl
module CapDissector
    class Packet
        def ruby_to_yaml
            fields_array = []

            each_root_field do |field|
                add_field_to_array(field, fields_array)
            end

            YAML.dump(fields_array)
        end

        def add_field_to_array(field, fields_array)
            # Each field is represented by a hash
            field_hash = {}
            fields_array << field_hash

            if field.name != nil && field.name != ""
                #Top-level key of this field's hash will be the field's name
                field_hash[field.name] = {}
                field_hash = field_hash[field.name]
            else
                key = "<Field##{field.ordinal}>"
                field_hash[key] = {}
                field_hash = field_hash[key]
            end

            if field.display_name != nil && field.display_name != ""
                field_hash['display_name'] = field.display_name
            end

            # The top-level 'protocol' fields shouldn't have values as they're just containers
            if field.is_protocol_node? == false && field.length > 0
                #Output the literal value if it's short enough, otherwise output a reference
                #to the blob containing the value
                if field.length <= CapDissector::Packet::MAX_INLINE_VALUE_LENGTH
                    field_hash['value'] = BinaryString.new(field.value)
                else
                    field_hash['value_blob_name'] = field.value_blob.name
                    field_hash['value_blob_offset'] = field.value_blob_offset
                    field_hash['value_blob_length'] = field.value_blob_length
                end
            end

            if field.display_value != nil && field.display_value != ""
                field_hash['display_value'] = field.display_value
            end

            field_hash['children'] = []

            field.each_child do |child_field|
                add_field_to_array(child_field, field_hash['children'])
            end

            field_hash.delete('children') unless field_hash['children'].length > 0
        end

    end
end
