require 'mkmf-gnome2'

PACKAGE_NAME="rcapdissector"

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


