import sys
import re
from waflib import Utils,Logs,Errors
from waflib.Configure import conf
NDNX_DIR=['/usr','/usr/local','/opt/local','/sw']
NDNX_VERSION_FILE='ndn/ndn.h'
NDNX_VERSION_CODE='''
#include <ndn/ndn.h>
#include <stdio.h>
int main() { printf ("%d.%d.%d", ((NDN_API_VERSION/100000) % 100), ((NDN_API_VERSION/1000) % 100), (NDN_API_VERSION % 1000)); return 0; }
'''

def options(opt):
	opt.add_option('--ndnx',type='string',default='',dest='ndnx_dir',help='''path to where NDNx is installed, e.g. /usr/local''')

@conf
def __ndnx_get_version_file(self,dir):
	try:
		return self.root.find_dir(dir).find_node('%s/%s'%('include',NDNX_VERSION_FILE))
	except:
		return None
@conf
def ndnx_get_version(self,dir):

	val=self.check_cc(fragment=NDNX_VERSION_CODE,includes=['%s/%s'%(dir,'include')],execute=True,define_ret=True,mandatory=True)
	return val

@conf
def ndnx_get_root(self,*k,**kw):
	root=k and k[0]or kw.get('path',None)
	if root and self.__ndnx_get_version_file(root):
		return root
	for dir in NDNX_DIR:
		if self.__ndnx_get_version_file(dir):
			return dir
	if root:
		self.fatal('NDNx not found in %s'%root)
	else:
		self.fatal('NDNx not found, please provide a --ndnx argument (see help)')

@conf
def check_ssl(conf):
    if not conf.check_cfg(package='openssl', args=['--cflags', '--libs'], uselib_store='SSL', mandatory=False):
        libcrypto = conf.check_cc(lib='crypto',
                                  header_name='openssl/crypto.h',
                                  define_name='HAVE_SSL',
                                  uselib_store='SSL')
    else:
        conf.define("HAVE_SSL", 1)
    if not conf.get_define ("HAVE_SSL"):
        conf.fatal("Cannot find SSL libraries")

@conf
def check_ndnx(self,*k,**kw):
	self.check_ssl()
	if not self.env['CC']:
		self.fatal('load a c compiler first, conf.load("compiler_c")')
	var=kw.get('uselib_store','NDNX')
	self.start_msg('Checking NDNx')
	root=self.ndnx_get_root(*k,**kw);
	self.env.NDNX_VERSION=self.ndnx_get_version(root)
	self.env['INCLUDES_%s'%var]='%s/%s'%(root,"include");
	self.env['LIB_%s'%var]=["ccn"]+self.env["LIB_SSL"]
	self.env['LIBPATH_%s'%var]='%s/%s'%(root,"lib")
	self.end_msg(self.env.NDNX_VERSION)
	if Logs.verbose:
		Logs.pprint('CYAN','	ndnx include : %s'%self.env['INCLUDES_%s'%var])
		Logs.pprint('CYAN','	ndnx lib     : %s'%self.env['LIB_%s'%var])
		Logs.pprint('CYAN','	ndnx libpath : %s'%self.env['LIBPATH_%s'%var])

