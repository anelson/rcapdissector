require 'mkmf-gnome2'

PACKAGE_NAME="rcapdissector"

def move_ruby_includes_to_end(flags)
    puts "Moving ruby includes in #{flags}"

    dirs = flags.split(" ")
    non_ruby_dirs = []
    ruby_dirs = []
    dirs.each do |dir|
        if dir =~ /ruby/
            ruby_dirs << dir
        else
            non_ruby_dirs << dir
        end
    end

    dirs = non_ruby_dirs + ruby_dirs
    puts "Came up with" + dirs.join(" ")
    dirs.join(" ")
end



dir_config("wireshark")
dir_config("wiretap")

unless PKGConfig.have_package('gtk+-2.0')
    warn("Unable to locate GTK+ version 2.0 or later")
    exit
end

unless have_header("glib.h")
    warn("Unable to locate glib.h; check the glib include directory and try again")
    exit
end

has_stdarg = have_header("stdarg.h")
unless has_stdarg
    warn("Unable to locate stdarg.h; varargs.h will be used instead, which may not work with later GCC versions")
end

# wireshark expects HAVE_STDARG_H to be defined if stdarg.h is available, but
# despite the check above Ruby won't define this until it writes the makefile, so
# I have to do it myself
if has_stdarg
    $CFLAGS += " -DHAVE_STDARG_H"
    $CPPFLAGS += " -DHAVE_STDARG_H"
end

unless have_header("config.h" )
    warn("Unable to locate wireshark's config.h header; check the wireshark include directory")
    exit
end

# The ruby build environment has a config.h in the include path, which contains Ruby's build-time
# configuration.  Great, except wireshark has a config.h too, and that's the one I want
# Since the Ruby include directory is specified in $INCFLAGS, which are passed to the compiler
# before $CPPFLAGS, add the wireshark include directory to $INCFLAGS.  This sucks in a number of ways,
# but it's all I can come up with.  Say what you will about Windows, but the Microsoft toolchain
# doesn't require anywhere near this level of contortion.
# TODO: There has GOT to be a more elegant way to do this
wireshark_include_dir=with_config("wireshark-include", "")
if wireshark_include_dir.empty?
    warn("No wireshark include directory has been specified.")
    exit
end

$INCFLAGS = "-I#{wireshark_include_dir} " + $INCFLAGS

unless have_macro("WS_VAR_IMPORT", ["config.h"])
    warn("WS_VAR_IMPORT macro not defined in config.h.  Probably the include path contains something else with a config.h before Wireshark's include directory")
    exit
end

unless have_header("epan/epan.h")
    warn("Unable to locate epan.h; check the wireshark include directory and try again")
    exit
end

unless find_library("wiretap", "wtap_pcap_encap_to_wtap_encap") 
    warn("Unable to locate libwiretap; check wiretap link directory and try again")
    exit
end

unless find_library("wireshark", "tvb_reported_length") 
    warn("Unable to locate libwireshark; check wireshark link directory and try again")
    exit
end

create_makefile(PACKAGE_NAME)


