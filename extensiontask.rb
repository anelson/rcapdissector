require 'rake'
require 'rake/clean'
require 'rake/tasklib'
require 'rbconfig'

# Rake tasks to build Ruby extensions

module Rake

  # Create a build task that will generate a Ruby extension (e.g. .so) from one or more
  # C (.c) or C++ (.cc, .cpp, .cxx) files, and is intended as a replcaement for mkmf.
  # It determines platform-specific settings (e.g. file extensions, compiler flags, etc.)
  # from rbconfig (note: examples assume *nix file extensions).
  #
  # *Note*: Strings vs Symbols
  # In places where filenames are expected (e.g. lib_name and objs), Strings are used
  # as verbatim filenames, while, Symbols have the platform-dependant extension
  # appended (e.g. '.so' for libraries and '.o' for objects).  Also, only Symbols
  # have #dir prepended to them.
  #
  # Example:
  #   desc "build sample extension"
  #   # build sample.so (from foo.{c,cc,cxx,cpp}, through foo.o)
  #   Rake::ExtensionTask.new :sample => :foo do |t|
  #     # all extension files under this directory
  #     t.dir = 'ext'
  #     # link libraries (libbar.so)
  #     t.link_libs << 'bar'
  #   end
  #
  # Author::    Steve Sloan (mailto:steve@finagle.org)
  # Copyright:: Copyright (c) 2006 Steve Sloan
  # License::   GPL

  class ExtensionTask < Rake::TaskLib
    # The name of the extension
    attr_accessor :name

    # The filename of the extension library file (e.g. 'extension.so')
    attr_accessor :lib_name

    # Object files to build and link into the extension.
    attr_accessor :objs

    # The directory where the extension files (source, output, and
    # intermediate) are stored.
    attr_accessor :dir

    # Environment configuration -- i.e. CONFIG from rbconfig, with a few other
    # settings, and converted to lowercase-symbols.
    attr_accessor :env

    # Additional link libraries
    attr_accessor :link_libs

    # Same arguments as Rake::define_task
    def initialize( args, &blk )
      @env = @@DefaultEnv.dup
      @name, @objs = resolve_args(args)
      set_defaults
      yield self  if block_given?
      define_tasks
    end

    # Generate default values.  This is called from initialize _before_ the
    # yield block.
    #
    # Defaults:
    # - lib_name: name.so
    # - objs: name.o (<- name.{c,cxx,cpp,cc})
    # - dir: .
    # - link_libs: <none>
    def set_defaults
      @lib_name ||= name.to_sym
      @objs = [name.to_sym]  unless @objs and @objs.any?
      @dir ||= '.'
      @link_libs ||= []
    end

    # Defines the library task.
    def define_tasks
      output_objs = @objs.collect { |obj| filepath obj, :objext }
      output_lib = filepath lib_name, :dlext

      task name => output_lib

      @env[:deffile] = lib_name.to_s + '.def'

      file output_lib => output_objs do |t|
        # ANELSON CHANGE
        # With MSVC, /Fe<name> is how you specify the output file of the linker
        # Also everything after /link is a linker option, so dldflags needs to appear
        # in the right place
        #sh_cmd :ldshared, :dldflags, :ldflags,
        #       {'-L' => :libdirs}, '-o', output_lib,
        #       output_objs.join(' '),
        #       link_libs.join(' '),
        #       :libs, :dldlibs, :librubyarg_shared
        sh_cmd t, :link_so, 
               {'-L' => :libdirs}, 
               output_objs.join(' '),
               link_libs.join(' '),
               :librubyarg_shared
      end

      CLEAN.include output_objs
      CLOBBER.include output_lib
      define_rules
    end

    # Defines C and C++ source-to-object rules, using the source extensions from env.
    def define_rules
      for ext in env[:c_exts]
        Rake::Task.create_rule '.'+env[:objext] => '.'+ext do |r|
          # ANELSON CHANGE
          # Under VC++, output file isn't specified by -o, but by /Fo
          #sh_cmd :cc, :cflags, :cppflags, {'-D' => :defines}, {'-I' => :includedirs}, {'-I' => :topdir},
          #      '-c', '-o', r.name, r.sources

          # TODO: Use the COMPILE_C command instead of using
          # :cc, :cflags, and :cppflags.  Call expand_makefile_variable 
          # on COMPILE_C, passing in 'r' as the task
          sh_cmd r, :compile_c, {'-D' => :defines}, {'-I' => :includedirs}, {'-I' => :topdir}
        end
      end

      for ext in env[:cpp_exts]
        Rake::Task.create_rule '.'+env[:objext] => '.'+ext do |r|
          # ANELSON CHANGE
          # Under VC++, output file isn't specified by -o, but by /Fo
          #sh_cmd :cxx, :cxxflags, :cppflags, {'-D' => :defines}, {'-I' => :includedirs}, {'-I' => :topdir},
          #      '-o', r.name, '-c', r.sources
          sh_cmd r, :compile_cxx, {'-D' => :defines}, {'-I' => :includedirs}, {'-I' => :topdir}
        end
      end
    end

    class << self
      # The default environment for all extensions.
      @@DefaultEnv = {}
      def env
        @@DefaultEnv
      end
      def env=(e)
        @@DefaultEnv = e
      end

      Config::CONFIG.merge(ENV).each { |k, v| @@DefaultEnv[k.downcase.to_sym] = v }
      @@DefaultEnv = {
        :cxx => 'c++',
        :cxxflags => '',
        :c_exts => ['c'],
        :cpp_exts => ['cc', 'cxx', 'cpp'],
        :includedirs => [],
        :libdirs => [],
      }.update(@@DefaultEnv)
    end

  protected

    # Handles convenience filenames:
    # * f (String) => f
    # * f (Symbol) => dir/f.ext
    def filepath( f, ext )
      ext = env[ext]  if Symbol === ext
      Symbol === f ? File.join( dir, "#{f}.#{ext}" ) : f
    end

    # Convenience function for cnstructing command lines for build tools.
    def optify( task, *opts )
      return optify(task, *opts.first)  if opts.size == 1 and opts.first.kind_of? Array
      opts.collect do |opt|
        case opt
          when String then  expand_makefile_placeholders(task, opt)
          when Symbol then  optify task, env[opt]
          when Hash
            opt.collect do |k, v|
              v = env[v]  if v.kind_of? Symbol
              if v.kind_of? Array
                optify task, v.collect { |w| k.to_s + w.to_s }
              elsif v
                expand_makefile_placeholders(task, k.to_s + v.to_s)
              end
            end
          else
            expand_makefile_placeholders(task, opt.to_s)
        end
      end.join(' ').squeeze(' ')
    end

    def sh_cmd( task, cmd, *opts )
      optified_cmd = optify( task, cmd, *opts )
      puts "Invoking [#{optified_cmd}]"
      sh optified_cmd
    end

    # Expands make-esque placeholders like $(ENVVAR) and $(*F) which Ruby 
    # seems all-too-happy to drop into the config variables
    def expand_makefile_placeholders(task, val)
        expanded = val.dup

        expanded.gsub!(/\$\(([^\)]+)\)/) do 
            # The bit between $( and ) is in $1
            variable = $1.dup

            # If it's an environment variable, just expand it
            if @env.has_key?(variable.downcase.to_sym)
                variable = @env[variable.downcase.to_sym] 
            elsif ENV.has_key?(variable)
                variable =  ENV[variable]
            elsif variable =~ /^[[:alpha:]_]+$/
                puts "Couldn't find value for variable #{variable}; defaulting to empty string"
                variable = ''
            end

            # Replace a subset of the GNU make Automatic Variables
            # listed in http://www.gnu.org/software/make/manual/make.html#Automatic-Variables
            target_filename = File.basename(task.name, ".*")

            # *F with an optional : concat operator is replaced with the base
            # file name of the target stem; it's too hard to figure out what the
            # stem equivalent would be in Rake, so just use the base file name
            # of the target
            variable.gsub!(/^\*F\:?/, target_filename)

            # @ with an optional : concat operator is the file name of the target
            # rule, path, extension, and all
            variable.gsub!(/^\@\:?/, task.name)

            # < with an optional : concat operator is replaced with the 
            # name of the first pre-req
            if task.sources.empty?
                variable.gsub!(/^\<\:?/, '')
            else
                variable.gsub!(/^\<\:?/, task.sources.first)
            end

            # Sometimes I see this placeholder: $(<:\=/).  '<' is the first source file, but nfi
            # what \=/ is.  Kill it
            variable.gsub!('\=/', '')

            variable = expand_makefile_placeholders(task, variable)

            variable
        end

        puts "Expanded [#{val}] to [#{expanded}]"

        return expanded
    end

    # For some reason, Rake::TaskManager.resolve_args can't be found, so snarf it.
    def resolve_args(args)
      case args
      when Hash
        fail "Too Many Task Names: #{args.keys.join(' ')}" if args.size > 1
        fail "No Task Name Given" if args.size < 1
        task_name = args.keys[0]
        deps = args[task_name]
        deps = [deps] if (String===deps) || (Regexp===deps) || (Proc===deps)
      else
        task_name = args
        deps = []
      end
      [task_name, deps]
    end

  end

end
