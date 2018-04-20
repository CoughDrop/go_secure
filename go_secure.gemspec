Gem::Specification.new do |s|
  s.name        = 'go_secure'

  s.add_development_dependency 'rspec'
  s.add_development_dependency 'ruby-debug'

  s.version     = '0.3'
  s.date        = '2018-04-20'
  s.summary     = "Go Secure"
  s.extra_rdoc_files = %W(LICENSE)
  s.homepage = %q{http://github.com/CoughDrop/go_secure}
  s.description = "Security helper gem, used by multiple CoughDrop libraries"
  s.authors     = ["Brian Whitmer"]
  s.email       = 'brian.whitmer@gmail.com'

	s.files = Dir["{lib}/**/*"] + ["LICENSE", "README.md"]
  s.require_paths = %W(lib)

  s.homepage    = 'https://github.com/CoughDrop/obf'
  s.license     = 'MIT'
end
