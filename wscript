VERSION='0.1'
APPNAME='carepo'

import waflib


def options(opt):
    opt.load('compiler_c')
    opt.load('ndnx', tooldir='.')
    opt.load('cunit', tooldir='.')

    opt.add_option('--optimize',action='store_true',default=False,dest='optimize',help='optimize object code')
    opt.add_option('--unit',action='store_true',default=False,dest='unit',help='build unit tests')
    opt.add_option('--markdown',action='store_true',default=False,dest='markdown',help='build Markdown into HTML')


def configure(conf):
    conf.load('compiler_c')
    conf.load('ndnx', tooldir='.')
    conf.load('cunit', tooldir='.')
    conf.check_ndnx(path=conf.options.ndnx_dir)
    
    conf.define('_GNU_SOURCE', 1)
    conf.env.append_unique('CFLAGS', ['-Wall', '-Werror', '-Wpointer-arith', '-fPIC', '-Wstrict-prototypes', '-std=c99'])

    if conf.options.optimize:
        conf.env.append_unique('CFLAGS', ['-O3', '-g1'])
    else:
        conf.env.append_unique('CFLAGS', ['-O0', '-g3'])
    
    if conf.options.unit:
        conf.env.UNIT = 1
        conf.check_cunit(path=conf.options.cunit_dir)
    
    if conf.options.markdown:
        conf.env.MARKDOWN = 1
        conf.find_program('pandoc', var='PANDOC')


def build(bld):
    source_subdirs = ['rabin','segment']
    bld.objects(target='objs',
        source=bld.path.ant_glob([subdir+'/*.c' for subdir in source_subdirs], excl=['**/*_test*.c']),
        includes='.',
        export_includes='.',
        use='NDNX',
        )

    bld.program(target='rabinseg',
        source=bld.path.ant_glob(['command/rabinseg.c']),
        use='objs CUNIT',
        install_path=None,
        )

    if bld.env.UNIT:
        bld.program(target='unittest',
            source=bld.path.ant_glob([subdir+'/*_test*.c' for subdir in source_subdirs] + ['command/unittest.c']),
            use='objs CUNIT',
            install_path=None,
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


def check(ctx):
    unittest_node=ctx.root.find_node(waflib.Context.out_dir+'/unittest')
    if unittest_node is None:
        ctx.fatal('unittest is not built; configure with --unit and build')
    else:
        import subprocess
        subprocess.call(unittest_node.abspath())

