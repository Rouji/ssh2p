project('ssh2p', 'c',
  version : '0.1',
  default_options : ['warning_level=3', 'b_ndebug=if-release', 'strip=true'])

static_link = get_option('static_build')
if static_link
  add_project_link_arguments('-static', language: 'c')
endif

executable(
    'ssh2p',
    'ssh2p.c',
    dependencies: [
        dependency('libcurl', static: static_link),
        dependency('libssh', static: static_link),
        dependency('threads'),
    ],
    install : true
)
