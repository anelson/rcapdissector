#!/usr/bin/ruby -w
require 'capdissector'

module CapDissector
    class CapFileError < Exception
        def initialize(message)
            super(message)
        end
    end
end

