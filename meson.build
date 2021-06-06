project('ssh2p', 'c',
  version : '0.1',
  default_options : ['warning_level=3'])

executable(
    'ssh2p',
    'ssh2p.c',
    dependencies: [
        dependency('libcurl'),
        dependency('libssh'),
        dependency('threads'),
    ],
    install : true
)
