VERSION='0.1'
APPNAME='carepo'

import waflib


def options(opt):
    opt.load('compiler_c')
    opt.load('ndnx', tooldir='.')

    opt.add_option('--optimize',action='store_true',default=False,dest='optimize',help='optimize object code')
    opt.add_option('--markdown',action='store_true',default=False,dest='markdown',help='build Markdown into HTML')


def configure(conf):
    conf.load('compiler_c')
    conf.load('ndnx', tooldir='.')
    conf.check_ndnx(path=conf.options.ndnx_dir)
    
    conf.define('_GNU_SOURCE', 1)
    conf.env.append_unique('CFLAGS', ['-Wall', '-Werror', '-Wpointer-arith', '-fPIC', '-Wstrict-prototypes', '-std=c99'])

    if conf.options.optimize:
        conf.env.append_unique('CFLAGS', ['-O3', '-g1'])
    else:
        conf.env.append_unique('CFLAGS', ['-O0', '-g3'])

    if conf.options.markdown:
        conf.env.MARKDOWN = 1
        conf.find_program('pandoc', var='PANDOC')


def build(bld):
    bld.objects(target='rabin',
        source=bld.path.ant_glob(['rabin/*.c']),
        includes='.',
        export_includes='.',
        )
    
    if bld.env.MARKDOWN:
        waflib.TaskGen.declare_chain(name='markdown2html',
            rule='${PANDOC} -f markdown -t html -o ${TGT} ${SRC}',
            shell=False,
            ext_in='.md',
            ext_out='.htm',
            reentrant=False,
            install_path=None,
            )
        bld(source=bld.path.ant_glob(['**/*.md']))


