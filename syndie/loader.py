__author__ = 'jeff'
##
#
# loader.py -- message loader
#
##
from syndie import common
from syndie import datastore
import io
import os
import logging

import time
import threading
import traceback

class Loader:

    logger = logging.getLogger("Loader")
    dao = datastore.DAO()

    def __init__(self, directory):
        self.directory = os.path.abspath(directory)
        self._jobs = []
        self._jlock = threading.Lock()
        self._threads = []
        self.run = True

    def _add_job(self,func):
        self._jlock.acquire()
        self.logger.debug("add job %s" % func)
        self._jobs.insert(0,func)
        self._jlock.release()

    def _pump(self):
        if len(self._jobs) > 0:
            self._jlock.acquire()
            job = self._jobs.pop()
            self._jlock.release()
            try:
                self.logger.debug("do job %s" % job)
                job()
            except:
                traceback.print_exc()

    def _run(self):
        while self.run:
            self._pump()
            time.sleep(1)

    def start(self, jobs=4):
        for n in range(jobs):
            t = threading.Thread(target=self._run)
            self._threads.append(t)
        for thread in self._threads:
            thread.start()

    def stop(self):
        self.run = False
        for thread in self._threads:
            thread.join()



    def load_http(self,url,proxy='http://127.0.0.1:4444/'):

        index = common.HttpArchive(url)
        index.get_index(proxy)
        index.download(self.directory, proxy)


    def _load_file(self, fname):
        self.logger.debug("load file %s" % fname)
        msg = common.SyndieFile(fname)

    def load(self):
        self._load(self.directory)

    def _load(self, directory):
        self.logger.info("load directory %s" % directory)
        if not os.path.exists(directory):
            self.logger.fatal("%s does not exist"%directory)
            return
        if not os.path.isdir(directory):
            self.logger.fatal("%s in not a directory" % directory)
            return
        for root, dirs, files in os.walk(directory):
            for d in dirs:
                d = os.path.join(root,d)
                self._load(d)
            for f in files:
                f = os.path.join(root,f)
                self._load_file(f)
