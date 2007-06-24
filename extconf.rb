require 'mkmf'

is_windows = (RUBY_PLATFORM =~ /mswin32|mingw/)


create_makefile("capdissector")

