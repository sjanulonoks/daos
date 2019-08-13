#!/usr/bin/python
'''
  (C) Copyright 2018-2019 Intel Corporation.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  GOVERNMENT LICENSE RIGHTS-OPEN SOURCE SOFTWARE
  The Government's rights to use, modify, reproduce, release, perform, display,
  or disclose this software are subject to the terms of the Apache License as
  provided in Contract No. B609815.
  Any reproduction of computer software, computer software documentation, or
  portions thereof marked with this legend must also reproduce the markings.
'''
from __future__ import print_function

import os
import json
from apricot import Test


import agent_utils
import server_utils
import write_host_file
from daos_api import DaosContext, DaosPool, DaosContainer, DaosLog, DaosApiError

class Permission(Test):
    """
    Tests DAOS pool permissions while connect, whether
    modifying file with specific permissions work as expected.

    :avocado: recursive
    """
    def setUp(self):
        self.agent_sessions = None
        # get paths from the build_vars generated by build
        with open('../../../.build_vars.json') as build_file:
            build_paths = json.load(build_file)
        self.basepath = os.path.normpath(build_paths['PREFIX'] + "/../")
        self.server_group = self.params.get("name",
                                            '/server_config/',
                                            'daos_server')

        # setup the DAOS python API
        self.context = DaosContext(build_paths['PREFIX'] + '/lib/')
        self.pool = None
        self.d_log = DaosLog(self.context)

        # getting hostfile
        self.hostfile_servers = None
        self.hostlist_servers = self.params.get("test_machines", '/run/hosts/*')
        self.hostfile_servers = write_host_file.write_host_file(
            self.hostlist_servers, self.workdir)
        print ("Host file is: {}".format(self.hostfile_servers))

        self.container = None

        # starting server
        self.agent_sessions = agent_utils.run_agent(self.basepath,
                                                    self.hostlist_servers)
        server_utils.run_server(self.hostfile_servers, self.server_group,
                                self.basepath)

    def tearDown(self):
        try:
            if self.pool is not None and self.pool.attached:
                self.pool.destroy(1)
        finally:
            # stop servers
            if self.agent_sessions:
                agent_utils.stop_agent(self.agent_sessions)
            server_utils.stop_server(hosts=self.hostlist_servers)

    def test_connectpermission(self):
        """
        Test pool connections with specific permissions.
        :avocado: tags=pool,permission,connectpermission
        """
        # parameters used in pool create
        createmode = self.params.get("mode", '/run/createtests/createmode/*/')
        createuid = os.geteuid()
        creategid = os.getegid()
        createsetid = self.params.get("setname", '/run/createtests/createset/')
        createsize = self.params.get("size", '/run/createtests/createsize/')

        # parameters used for pool connect
        permissions = self.params.get("perm", '/run/createtests/permissions/*')

        if createmode == 73:
            expected_result = 'FAIL'
        if createmode == 511 and permissions == 0:
            expected_result = 'PASS'
        elif createmode in [146, 511] and permissions == 1:
            expected_result = 'PASS'
        elif createmode in [292, 511] and permissions == 2:
            expected_result = 'PASS'
        else:
            expected_result = 'FAIL'

        try:
            # initialize a python pool object then create the underlying
            # daos storage
            self.pool = DaosPool(self.context)
            self.d_log.debug("Pool initialisation successful")

            self.pool.create(createmode, createuid, creategid,
                             createsize, createsetid, None)
            self.d_log.debug("Pool Creation successful")

            self.pool.connect(1 << permissions)
            self.d_log.debug("Pool Connect successful")

            if expected_result in ['FAIL']:
                self.fail("Test was expected to fail but it passed.\n")

        except DaosApiError as excep:
            print(excep)
            if expected_result == 'PASS':
                self.fail("Test was expected to pass but it failed.\n")

    def test_filemodification(self):
        """
        Test whether file modification happens as expected under different
        permission levels.

        :avocado: tags=pool,permission,filemodification
        """
        # parameters used in pool create
        createmode = self.params.get("mode", '/run/createtests/createmode/*/')
        createuid = self.params.get("uid", '/run/createtests/createuid/')
        creategid = self.params.get("gid", '/run/createtests/creategid/')
        createsetid = self.params.get("setname", '/run/createtests/createset/')
        createsize = self.params.get("size", '/run/createtests/createsize/')

        if createmode == 73:
            expected_result = 'FAIL'
        elif createmode in [146, 511]:
            permissions = 1
            expected_result = 'PASS'
        elif createmode == 292:
            permissions = 2
            expected_result = 'PASS'

        try:
            # initialize a python pool object then create the underlying
            # daos storage
            self.pool = DaosPool(self.context)
            self.d_log.debug("Pool initialisation successful")
            self.pool.create(createmode,
                             createuid,
                             creategid,
                             createsize,
                             createsetid,
                             None)
            self.d_log.debug("Pool Creation successful")

            self.pool.connect(1 << permissions)
            self.d_log.debug("Pool Connect successful")

            self.container = DaosContainer(self.context)
            self.d_log.debug("Contianer initialisation successful")

            self.container.create(self.pool.handle)
            self.d_log.debug("Container create successful")

            # now open it
            self.container.open()
            self.d_log.debug("Container open successful")

            thedata = "a string that I want to stuff into an object"
            size = 45
            dkey = "this is the dkey"
            akey = "this is the akey"

            self.container.write_an_obj(thedata, size, dkey, akey)
            self.d_log.debug("Container write successful")
            if expected_result in ['FAIL']:
                self.fail("Test was expected to fail but it passed.\n")

        except DaosApiError as excep:
            print(excep)
            if expected_result == 'PASS':
                self.fail("Test was expected to pass but it failed.\n")
