#!/usr/bin/env ruby

# Runs all the tests
Dir['**/*_tests.rb'].each { |test_case| require test_case unless test_case == __FILE__ }

