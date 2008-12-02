#!/usr/bin/ruby -w
require 'capdissector'

module CapDissector
    # Internal exception thrown by the native FieldQuery object when a query predicate is found to not
    # match the current field.  This error should never propagate to callers of this extension
    class FieldDoesNotMatchQueryError < Exception
        def initialize(dontCare)
        end
    end
end

