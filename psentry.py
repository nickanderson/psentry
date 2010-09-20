#!/usr/bin/env python

import os
import sys
import pickle
import inspect
import subprocess

from optparse import OptionParser
from pyinotify import WatchManager, Notifier, ThreadedNotifier, EventsCodes, ProcessEvent

configfile = '/etc/psentry.dat'

class ConfigChange(Exception):
    pass

def whoami():
    return inspect.stack()[1][3]

def errorExit(msg):
    sys.stderr.write(msg)
    sys.exit(1)

class Sentry:
    def checktype(self, value, type):
        if not type(value).__name__ == type:
            caller = whoami()
            errorExit('Expected %s but got %s in %s' %(type, value, caller))
        else:
            pass

    def __init__(self, path):
        #self.checktype(path,'str')
        self.path = path
        self.fileacl = []
        self.diracl = []
        self.defaultacl = []
        self.uid = ''
        self.gid = ''
        self.filechmod = ''
        self.dirchmod = ''


    def setfileacl(self, acl):
        if not type(acl).__name__ == 'list':
            tmp = []
            tmp.append(acl)
            acl = tmp
            sys.exit('non list type passed to setacl')
        self.fileacl = acl

    def setdiracl(self, acl):
        if not type(acl).__name__ == 'list':
            tmp = []
            tmp.append(acl)
            acl = tmp
            sys.exit('non list type passed to setacl')
        self.diracl = acl

    def setdetfaultacl(self, acl):
        if not type(acl).__name__ == 'list':
            tmp = []
            tmp.append(acl)
            acl = tmp
        self.defaultacl = acl

    def setuid(self, uid):
        if not type(uid).__name__ == 'str':
            sys.exit('non string type passed to setuid')
        self.uid = uid

    def setgid(self, gid):
        if not type(gid).__name__ == 'str':
            sys.exit('non string type passed to setgid')
        self.gid = gid

    def setfilechmod(self, chmod):
        if not type(chmod).__name__ == 'str':
            sys.exit('non string type passed to setchmod')
        self.filechmod = chmod

    def setdirchmod(self, chmod):
        if not type(chmod).__name__ == 'str':
            sys.exit('non string type passed to setchmod')
        self.dirchmod = chmod

    def addfileacl(self, acl):
        self.fileacl.extend(acl)

    def adddiracl(self, acl):
        self.diracl.extend(acl)

    def adddefaultacl(self, acl):
        self.defaultacl.extend(acl)


wm = WatchManager()

mask = EventsCodes.IN_CREATE | EventsCodes.IN_MOVED_TO | EventsCodes.IN_MODIFY

from os.path import dirname
def GetParent(path):
    return dirname(path)

def ApplyPermissions(file, permissions, operation):
    if operation == 'move':
        setfacl_cmd = 'setfacl -Rbm'
    else:
        setfacl_cmd = 'setfacl -bm'

    if not os.path.isdir(file):
        # replace any existing permissions with those that are definded
        cmd = setfacl_cmd + ' %s "%s"' %(','.join(permissions.fileacl), file)
        print cmd
        subprocess.call(cmd, shell=True)

        if not len(permissions.filechmod) == 0:
            cmd = 'chmod %s "%s"' %(permissions.filechmod, file)
            print cmd
            subprocess.call(cmd, shell=True)

    else:
        # add watch to newly created directories
        wdd = wm.add_watch(file, mask, rec=True)
        cmd = setfacl_cmd + ' %s "%s"' %(','.join(permissions.diracl), file)
        print cmd
        subprocess.call(cmd, shell=True)

        if not len(permissions.dirchmod) == 0:
            cmd = 'chmod %s "%s"' %(permissions.dirchmod, file)
            print cmd
            subprocess.call(cmd, shell=True)


    if not len(permissions.defaultacl) == 0:
        cmd = 'setfacl -dbm %s "%s"' %(','.join(permissions.defaultacl), file)
        print cmd
        subprocess.call(cmd, shell=True)
    
    if not len(permissions.uid) == 0:
        cmd = 'chown %s "%s"' %(permissions.uid, file)
        print cmd
        subprocess.call(cmd, shell=True)
    
    if not len(permissions.gid) == 0:
        cmd = 'chgrp %s "%s"' %(permissions.gid, file)
        print cmd
        subprocess.call(cmd, shell=True)
    


def FixPerms(permissions):
    for x in sorted(permissions.keys()):
        ApplyPermissions(x, permissions[x], 'move')

class do_event(ProcessEvent):

    def doSet(self, event, operation):
        found_path = False
        path = os.path.join(event.path, event.name)
        if path in sentry_paths:
            print 'found path definition'
            print sentry_paths[path].path
        else:
            print 'searching for path'
            while not found_path:
                print '.'
                path = GetParent(path)
                if path in sentry_paths:
                    print 'found path definition'
                    print sentry_paths[path].path
                    ApplyPermissions(os.path.join(event.path, event.name),
                                     sentry_paths[path], operation)
                    break

    def process_IN_CREATE(self,event):
        print "Create: %s" % os.path.join(event.path, event.name)
        self.doSet(event, 'create')

    def process_IN_MOVED_TO(self,event):
        print "moved to: %s" % os.path.join(event.path, event.name)
        self.doSet(event, 'move')

    def process_IN_MODIFY(self,event):
        if os.path.join(event.path, event.name).rstrip('/') == configfile:
            raise ConfigChange("Config file changed")
        
def startSentry(sentry_paths):
    """
    Sentry Runner
    """
    notifier = Notifier(wm, do_event())
    for path in sentry_paths:
        wdd = wm.add_watch(sentry_paths[path].path, mask, rec=True)
        print 'watching %s ' % sentry_paths[path].path

    #wdd = wm.add_watch('/home/cmdln/sandbox/permissionminder/test', mask, rec=True)
    while True:
        try:
            notifier.process_events()
            if notifier.check_events():
                notifier.read_events()
        except KeyboardInterrupt:
            notifier.stop()
            break
        except ConfigChange:
            notifier.stop()
            raise ConfigChange('Config Changed')
            break
        except:
            #from pdb import set_trace;set_trace()
            pass


def showConfig(sentry_paths, path=None):
    """
    Show configuration for specified path
    if no path is given show entire configuration
    
    """
    if path == None:
        for x in sorted(sentry_paths.keys()):
            print 'path:', sentry_paths[x].path
            print '\tfileacl:', sentry_paths[x].fileacl
            print '\tdiracl:', sentry_paths[x].diracl
            print '\tuid:', sentry_paths[x].uid
            print '\tgid:', sentry_paths[x].gid
            print '\tdefaultacl:', sentry_paths[x].defaultacl
            print '\tfilechmod:', sentry_paths[x].filechmod
            print '\tdirchmod:', sentry_paths[x].dirchmod

    elif not path in sentry_paths:
        sys.exit('%s not in configuration' % path)
    else:
        print 'path:', sentry_paths[path].path
        print '\tfileacl:', sentry_paths[path].fileacl
        print '\tdiracl:', sentry_paths[path].diracl
        print '\tuid:', sentry_paths[path].uid
        print '\tgid:', sentry_paths[path].gid
        print '\tdefaultacl:', sentry_paths[path].defaultacl
        print '\tfilechmod:', sentry_paths[x].filechmod
        print '\tdirchmod:', sentry_paths[x].dirchmod

    sys.exit()

if __name__ == '__main__':
    parser = OptionParser()
    (options, args) = parser.parse_args()
    try:
        t = open(configfile, 'r')
        sentry_paths = pickle.load(t)
        t.close()
    except:
        sentry_paths = {}
        pass
    if configfile not in sentry_paths:
        print "Adding Configfile to watchlist"
        sentry_paths[configfile] = Sentry(configfile)


    #ApplyInitPermissions(sentry_paths)
    #sys.exit()
    actions = ['start', 'addpath', 'fixperms', 'show',
              'setfileacl', 'setdiracl', 'addfileacl', 
              'adddiracl', 'setuid', 'setgid',
              'setfilechmod', 'setdirchmod', 'adddefaultacl', ]
    action = args[0]

    if not action in actions:
        print action + ' not a valid action '
        sys.exit(0)

    import signal

    if action == 'start':
        try:
            print sentry_paths
            startSentry(sentry_paths)
        except ConfigChange:
            #signal.signal(signal.SIGHUP, self.hup)
            pass

    if action == 'show':
        # if no path passed to action show whole config
        if len(args) == 1:
            showConfig(sentry_paths)
        elif os.path.isdir(args[1]):
            showConfig(sentry_paths, args[1])
        else:
            sys.exit('%s is not a valid path to watch' % args[1])

    #if not len(args) > 1:
        #        sys.exit('not enough information to do something')

    if action == 'fixperms':
        FixPerms(sentry_paths)

    if action == 'addpath':
        path = args[1]
        if os.path.isdir(path):
            sentry_paths[path] = Sentry(path)
        else:
            sys.exit('%s does not exist or cannot be watched' % path)

    #if not len(args) > 2:
        #        sys.exit('not enough information to do something')

    if action == 'setdiracl':
        if args[2] not in sentry_paths:
            sys.exit('path not found in configuration please add it first')
        else:
            acl = args[1].split(',')
            sentry_paths[args[2]].setdiracl(acl)

    if action == 'setfileacl':
        if args[2] not in sentry_paths:
            sys.exit('path not found in configuration please add it first')
        else:
            acl = args[1].split(',')
            sentry_paths[args[2]].setfileacl(acl)

    if action == 'adddiracl':
        if args[2] not in sentry_paths:
            sys.exit('path not found in configuration please add it first')
        else:
            acl = args[1].split(',')
            sentry_paths[args[2]].adddiracl(acl)
        print sentry_paths[args[2]].diracl

    if action == 'addfileacl':
        if args[2] not in sentry_paths:
            sys.exit('path not found in configuration please add it first')
        else:
            acl = args[1].split(',')
            sentry_paths[args[2]].addfileacl(acl)
        print sentry_paths[args[2]].fileacl

    if action == 'adddefaultacl':
        if args[2] not in sentry_paths:
            sys.exit('path not found in configuration please add it first')
        else:
            acl = args[1].split(',')
            sentry_paths[args[2]].adddefaultacl(acl)
        print sentry_paths[args[2]].acl

    if action == 'setuid':
        if args[2] not in sentry_paths:
            sys.exit('path not found in configuration please add it')
        else:
            uid = args[1]
            sentry_paths[args[2]].setuid(uid)
        print sentry_paths[args[2]].uid

    if action == 'setgid':
        if args[2] not in sentry_paths:
            sys.exit('path not found in configuration please add it')
        else:
            gid = args[1]
            sentry_paths[args[2]].setgid(gid)
        print sentry_paths[args[2]].gid

    if action == 'setfilechmod':
        if args[2] not in sentry_paths:
            sys.exit('path not found in configuration please add it')
        else:
            chmod = args[1]
            sentry_paths[args[2]].setfilechmod(chmod)
        print sentry_paths[args[2]].filechmod
 
    if action == 'setdirchmod':
        if args[2] not in sentry_paths:
            sys.exit('path not found in configuration please add it')
        else:
            chmod = args[1]
            sentry_paths[args[2]].setdirchmod(chmod)
        print sentry_paths[args[2]].dirchmod
    
    #print sentry_paths
    #for x in sentry_paths:
    #    print sentry_paths[x].path

    pickle.dump(sentry_paths, open(configfile, 'w'))
    # startSentry(sentry_paths)
   
    
