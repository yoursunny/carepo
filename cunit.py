import sys
import re
from waflib import Utils,Logs,Errors
from waflib.Configure import conf
CUNIT_DIR=['/usr','/usr/local','/opt/local','/sw']
CUNIT_VERSION_FILE='CUnit/CUnit.h'
CUNIT_VERSION_CODE='''
#include <CUnit/CUnit.h>
#include <stdio.h>
int main(void) { printf ("%s", CU_VERSION); return 0; }
'''

def options(opt):
	opt.add_option('--cunit',type='string',default='',dest='cunit_dir',help='''path to where CUnit is installed, e.g. /usr/local''')

@conf
def __cunit_get_version_file(self,dir):
	try:
		return self.root.find_dir(dir).find_node('%s/%s'%('include',CUNIT_VERSION_FILE))
	except:
		return None
@conf
def cunit_get_version(self,dir):

	val=self.check_cc(fragment=CUNIT_VERSION_CODE,includes=['%s/%s'%(dir,'include')],execute=True,define_ret=True,mandatory=True)
	return val

@conf
def cunit_get_root(self,*k,**kw):
	root=k and k[0]or kw.get('path',None)
	if root and self.__cunit_get_version_file(root):
		return root
	for dir in CUNIT_DIR:
		if self.__cunit_get_version_file(dir):
			return dir
	if root:
		self.fatal('CUnit not found in %s'%root)
	else:
		self.fatal('CUnit not found, please provide a --cunit argument (see help)')

@conf
def check_cunit(self,*k,**kw):
	if not self.env['CC']:
		self.fatal('load a c compiler first, conf.load("compiler_c")')
	var=kw.get('uselib_store','CUNIT')
	self.start_msg('Checking CUnit')
	root=self.cunit_get_root(*k,**kw);
	self.env.CUNIT_VERSION=self.cunit_get_version(root)
	self.env['INCLUDES_%s'%var]='%s/%s'%(root,"include");
	self.env['LIB_%s'%var]=["cunit"]+self.env["LIB_SSL"]
	self.env['LIBPATH_%s'%var]='%s/%s'%(root,"lib")
	self.end_msg(self.env.CUNIT_VERSION)
	if Logs.verbose:
		Logs.pprint('CYAN','	cunit include : %s'%self.env['INCLUDES_%s'%var])
		Logs.pprint('CYAN','	cunit lib     : %s'%self.env['LIB_%s'%var])
		Logs.pprint('CYAN','	cunit libpath : %s'%self.env['LIBPATH_%s'%var])

