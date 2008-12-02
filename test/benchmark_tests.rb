require 'test/unit'
require 'benchmark'
require 'yaml'

require 'rcapdissector'
require File.dirname(__FILE__) + '\testdata'

include TestData
include Benchmark

class PacketTests < Test::Unit::TestCase
    def test_to_yaml_performance
        #Compare the native to_yaml with the Ruby impl ruby_to_yaml
        bm(20) do |x|
            capfile = CapDissector::CapFile.new(TEST_CAP)

            capfile.each_packet() do |packet|
                x.report("to_yaml") do
                    yaml = packet.to_yaml
                end
            end

            capfile.close

            capfile = CapDissector::CapFile.new(TEST_CAP)

            capfile.each_packet() do |packet|
                x.report("ruby_to_yaml") do
                    yaml = packet.ruby_to_yaml
                end
            end

            capfile.close
            capfile = nil
        end
    end
end

