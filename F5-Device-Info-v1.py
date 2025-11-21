
 # Copyright 2025 Matthew J Wolf
 #
 # This program is free software: you can redistribute it and/or modify
 # it under the terms of the GNU General Public License as published by
 # the Free Software Foundation, either version 2 of the License, or
 # (at your option) any later version.
 #
 # This program is distributed in the hope that it will be useful,
 # but WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 # GNU General Public License for more details.
 #
 # You should have received a copy of the GNU General Public License
 # along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Name:    F5 Device Info
# Author:  Matthew J. Wolf
# Date:    12-JAN-2020
# Version: 1.0
#
# Description:
#
#  !! This program was writen very quickly. It has not been fully tested.     !!
#  !! The program is some what messy due to the speed in which it was writen. !!
#
#   THing to improve:
#   - Input files: allow white space before the "#"
#   - Add output to standout that can be piped into other programs.
#   - Restore interactive mode ?
#   - The "MTO" mode is a program with in the program. Fit this.
#     -= Move the MTO mode device details in the F5Host object.
#     -= Move call of mto logging to the main function.
#

# pylint: disable=C0111
# pylint: disable=C0103
# pylint: disable=W0603
# pylint: disable=R0912
# pylint: disable=R0913
# pylint: disable=R0914
# pylint: disable=R0915
# pylint: disable=R1702

import datetime
import json
import os
import re
import socket
import subprocess
import sys
from typing import TextIO
from optparse import OptionParser
import urllib3


# Imports for secure shell (ssh)
import paramiko

# Linked list Node object class


# class Node(object):
class Node():
    def __init__(self, data=None, next_node=None):
        self.data = data
        self.next_node = next_node

    def get_data(self):
        return self.data

    def get_next(self):
        return self.next_node

    def set_next(self, new_next):
        self.next_node = new_next


# class LinkedList(object):
class LinkedList():
    def __init__(self, head=None):
        self.head = head

# pylint: disable=method-hidden


class F5Host:
    def __init__(self, p_ip_addr='NA', p_ip_ver=0, p_os_ver='NA', p_hostname='NA',
                 p_hw_type=42, p_hw_platform='NA', p_chassis_id='NA', p_mgmt_ip_addr='NA',
                 p_def_mgmt_gw='NA', p_net_failover_state=-1,
                 p_mgmt_routes=None, p_log_hosts=None, p_act_modules=None,
                 p_vcmp_host=False, p_viprion=False, p_vcmp_guests=None,
                 p_viprion_blades=None):
        self._ip_addr = p_ip_addr
        self._ip_ver = p_ip_ver
        self._os_ver = p_os_ver
        self._hostname = p_hostname
        self._hw_type = p_hw_type
        self._hw_platform = p_hw_platform
        self._chassis_id = p_chassis_id
        self._mgmt_ip_addr = p_mgmt_ip_addr
        self._def_mgmt_gw = p_def_mgmt_gw
        self._net_failover_state = p_net_failover_state
        self._mgmt_routes = p_mgmt_routes
        self._log_hosts = p_log_hosts
        self._act_modules = p_act_modules
        self._vcmp_host = p_vcmp_host
        self._viprion = p_viprion
        self._vcmp_guests = p_vcmp_guests
        self._viprion_blades = p_viprion_blades

    @property
    def ip_addr(self):
        return self._ip_addr

    @property
    def ip_ver(self):
        return self._ip_ver

    @property
    def os_ver(self):
        return self._os_ver

    @property
    def hostname(self):
        return self._hostname

    @property
    def hw_type(self):
        return self._hw_type

    @property
    def hw_platform(self):
        return self._hw_platform

    @property
    def chassis_id(self):
        return self._chassis_id

    @property
    def mgmt_ip_addr(self):
        return self._mgmt_ip_addr

    @property
    def def_mgmt_gw(self):
        return self._def_mgmt_gw

    @property
    def net_failover_state(self):
        return self._net_failover_state

    @property
    def mgmt_routes(self):
        return self._mgmt_routes

    @property
    def log_hosts(self):
        return self._log_hosts

    @property
    def act_modules(self):
        return self._act_modules

    @property
    def vcmp_host(self):
        return self._vcmp_host

    @property
    def viprion(self):
        return self._viprion

    @property
    def vcmp_guests(self):
        return self._vcmp_guests

    @property
    def viprion_blades(self):
        return self._viprion_blades

    # This setter also sets ip version of the IP address
    @ip_addr.setter
    def ip_addr(self, new_ip_addr):
        if isinstance(new_ip_addr, str):
            ip_ver_test = test_host_ip_address(new_ip_addr)
            if ip_ver_test > 0:
                self._ip_addr = new_ip_addr
                self._ip_ver = ip_ver_test
            else:
                raise Exception('Invalid value for ip_addr')

    @os_ver.setter
    def os_ver(self, new_os_ver):
        if isinstance(new_os_ver, str):
            self._os_ver = new_os_ver
        else:
            raise Exception('Invalid type for os_ver')

    @hostname.setter
    def hostname(self, new_hostname):
        if isinstance(new_hostname, str):
            self._hostname = new_hostname
        else:
            raise Exception('Invalid type for hostname')

    @hw_type.setter
    def hw_type(self, new_hw_type):
        if isinstance(new_hw_type, int):
            self._hw_type = new_hw_type
        else:
            raise Exception('Invalid type for hw_type')

    @hw_platform.setter
    def hw_platform(self, new_hw_platform):
        # if isinstance(new_hw_platform, int):
        if isinstance(new_hw_platform, str):
            self._hw_platform = new_hw_platform
        else:
            raise Exception('Invalid type for hw_platform')

    @chassis_id.setter
    def chassis_id(self, new_chassis_id):
        if isinstance(new_chassis_id, str):
            self._chassis_id = new_chassis_id
        else:
            raise Exception('Invalid type for chassis_id')

    @mgmt_ip_addr.setter
    def mgmt_ip_addr(self, new_mgmt_ip_addr):
        if isinstance(new_mgmt_ip_addr, str):
            ip_ver_test = test_host_ip_address(new_mgmt_ip_addr)
            if ip_ver_test > 0:
                self._mgmt_ip_addr = new_mgmt_ip_addr
        else:
            raise Exception('Invalid value for mgmt_ip_addr')

    @def_mgmt_gw.setter
    def def_mgmt_gw(self, new_mgmt_def_mgmt_gw):
        if isinstance(new_mgmt_def_mgmt_gw, str):
            ip_ver_test = test_host_ip_address(new_mgmt_def_mgmt_gw)
            if ip_ver_test > 0:
                self._def_mgmt_gw = new_mgmt_def_mgmt_gw
            else:
                raise Exception('Invalid IP address for mgmt_def_mgmt_gw')
        else:
            raise Exception('Invalid value for mgmt_def_mgmt_gw')

    @net_failover_state.setter
    def net_failover_state(self, new_net_failover_state):
        if isinstance(new_net_failover_state, int):
            self._net_failover_state = new_net_failover_state
        else:
            raise Exception('Invalid type for hw_platform')

    @log_hosts.setter
    def log_hosts(self, new_log_hosts):
        if isinstance(new_log_hosts, list):
            self._log_hosts = new_log_hosts
        else:
            raise Exception('Invalid type for log_hosts')

    @act_modules.setter
    def act_modules(self, new_act_modules):
        if isinstance(new_act_modules, list):
            self._act_modules = new_act_modules
        else:
            raise Exception('Invalid type for act_modules')

    @mgmt_routes.setter
    def mgmt_routes(self, new_mgmt_routes):
        if isinstance(new_mgmt_routes, list):
            self._mgmt_routes = new_mgmt_routes
        else:
            raise Exception('Invalid type for mgmt_routes')

    @vcmp_host.setter
    def vcmp_host(self, new_vcmp_host):
        if isinstance(new_vcmp_host, bool):
            self._vcmp_host = new_vcmp_host
        else:
            raise Exception('Invalid type for vcmp_host')

    @viprion.setter
    def viprion(self, new_viprion):
        if isinstance(new_viprion, bool):
            self._viprion = new_viprion
        else:
            raise Exception('Invalid type for viprion')

    @vcmp_guests.setter
    def vcmp_guests(self, new_vcmp_guests):
        if isinstance(new_vcmp_guests, list):
            self._vcmp_guests = new_vcmp_guests
        else:
            raise Exception('Invalid type for vcmp_guests')

    @viprion_blades.setter
    def viprion_blades(self, new_viprion_blades):
        if isinstance(new_viprion_blades, list):
            self._viprion_blades = new_viprion_blades
        else:
            raise Exception('Invalid type for viprion_blades')

# Main Function


def main():
    # Default input files
    login_user_file = "./f5-user.txt"
    hosts_ip_file = "./f5-hosts.txt"
    # Default log file name prefix and location
    log_location = "./"
    log_file_prefix = "f5-info"

    # Assuming default port numbers
    host_https_port = 443

    # Runtime Options
    options = OptionParser()

    options.add_option('-c', '--csv', action='store_true', dest='csv_out',
                       help='CSV Output: EOL CSV output to standard out.',
                       default=False)

    options.add_option('-d', '--devices-file', dest='devices_file',
                       help='Location of file with F5 device management addresses.\n'
                       'Default: %s' % hosts_ip_file, metavar='FILE')

    options.add_option('-i', '--use-icmp-echo', action='store_true', dest='no_tcp_conn',
                       help='Disable TCP port connect test. Use Unix ICMP Echo requests.',
                       default=False)

    options.add_option('-l', '--log-location', dest='log_location',
                       help='Filesystem location of the log file, include tail "/".\n'
                       'Default: %s' % log_location, metavar='LOCATION')

    options.add_option('-m', '--mto', action='store_true', dest='mto_details',
                       help='MTO Items: ACL Review, MJW MTO Input Format',
                       default=False)

    options.add_option('-p', '--prefix-log', dest='log_prefix',
                       help='Prefix of the name of the log file.\n'
                       'Default: %s' % log_file_prefix, metavar='PREFIX')

    options.add_option('-u', '--user-file', dest='user_file',
                       help='Location of file with user ID and password of device.\n'
                       'Default: %s' % login_user_file, metavar='FILE')

    (opt, _) = options.parse_args()
    if opt.devices_file:
        hosts_ip_file = opt.devices_file
    if opt.log_location:
        log_location = opt.log_location
    if opt.log_prefix:
        log_file_prefix = opt.log_prefix
    if opt.user_file:
        login_user_file = opt.user_file

    # Open Log File
    current_time = datetime.datetime.today()
    time_stamp = current_time.strftime(FILENAME_TIMESTAMPFORMAT)
    log_file_full_path = log_location + log_file_prefix + "_" + time_stamp + ".log"

    try:
        time_stamp = current_time.strftime(LOG_TIMESTAMPFORMAT)
        log_file: TextIO = open(log_file_full_path, "w")
        log_file.write("%s - LOG FILE OPENED - %s\n" %
                       (time_stamp, log_file_full_path))
    except IOError as file_error:
        print("Couldn't open or write to log file (%s)." % file_error)
        sys.exit(1)

    (ret, login_user_list, device_ip_list) = parse_input_files(
        log_file, login_user_file, hosts_ip_file)

    if ret != 0:
        print(log_file, "Exiting: Couldn't open one of the input files.")
        write_to_log(
            log_file, "Exiting: Couldn't open one of the input files.")
        sys.exit(1)

    log_str = 'Device IP addresses:'
    for ip in device_ip_list:
        log_str += ' ' + ip
    write_to_log(log_file, log_str)

    # Define the Head or top of the Host linked list.
    # Only the location of the top is defined. The list has no nodes.
    f5_hosts = LinkedList()

    # Build linked list of device host class objects
    for ip in device_ip_list:

        ip_ver = test_host_ip_address(ip)
        if ip_ver < 0:
            write_to_log(
                log_file, ip + ' - SKIPPING - It is not a valid IP address.')
            continue

        if opt.no_tcp_conn is True:
            ret = ping_host(ip, ip_ver)
            if ret != 0:
                write_to_log(log_file, ip +
                             ' - SKIPPING - Unix ICMP ping failed: '
                             + str(ret))
                # Stop doing things for the device.
                continue
        else:
            # Attempt to connect to the TCP on the F5 device.
            ret = tcp_connect_service_port(
                ip, host_https_port)
            if ret != 0:
                write_to_log(log_file, ip +
                             ' - SKIPPING - TCP port connect failed: '
                             + str(ret))
                continue

        # This test only works for remote users starting with TMOS 13 and above.
        if login_user_list[0] == 'admin':
            if test_icontrol_rest_access(log_file, login_user_list[0], login_user_list[1], ip,
                                         host_https_port, "localhost", ip_ver) != 0:
                write_to_log(
                    log_file, ip + ' - SKIPPING - Skipping - iControl REST access failed')
                continue

        # "data" of each node of the f5_hosts linked list is a F5Host object.
        host_node = F5Host(ip, ip_ver)
        host_node.ip_addr = ip
        list_insert(f5_hosts, host_node)

    # Walk F5 host linked list and get host details
    get_host_details(log_file, f5_hosts.head, login_user_list,
                     host_https_port, opt.no_tcp_conn)

    # Walk F5 host list and display the details in the log file.
    log_device_details(log_file, f5_hosts.head, opt.no_tcp_conn)

    if opt.csv_out is True:
        csv_on_stdout(f5_hosts.head)

    # 'opt' was defined by '(opt, _) = options.parse_args()'
    if opt.mto_details is True:

        do_mto_review(log_file, f5_hosts.head, login_user_list,
                      host_https_port)

        # Include in the log the input for MJW's F5 MTO program.
        log_mjw_mto_input_format(log_file, f5_hosts.head)


def parse_input_files(log_file, login_user_file, hosts_ip_file):
    local_rc = 0
    device_list = None

    (ret, login_user_list) = parse_file(log_file, login_user_file)
    if ret == 0:
        write_to_log(log_file, 'Opened Login User file: ' + login_user_file)
    if ret != 0:
        write_to_log(log_file, "Exiting: Couldn't open Login User file (%s)." %
                     login_user_file)
        local_rc = -1

    if local_rc == 0:
        # Simple check of the input user file.
        if len(login_user_list) != 2:
            write_to_log(
                log_file, 'Exiting: Wrong number of login user details.')
            print('Exiting: Wrong number of login user details.')
            local_rc = -2

    if local_rc == 0:
        (ret, device_list) = parse_file(log_file, hosts_ip_file)
        if ret == 0:
            write_to_log(log_file, 'Opened Host IP file: ' + hosts_ip_file)
        if ret != 0:
            write_to_log(log_file, "Exiting: Couldn't open Host IP file (%s)." %
                         hosts_ip_file)
            local_rc = -2

    return local_rc, login_user_list, device_list


def test_icontrol_rest_access(log_file, user_name, pass_word, ip_addr, port, host_name,
                              ip_ver):
    url = 'na'
    # noinspection PyUnusedLocal
    local_rc = -3

    if ip_ver == 4:
        url = "https://%s/mgmt/tm" % ip_addr
    elif ip_ver == 6:
        url = "https://[%s]/mgmt/tm" % ip_addr

    (_, response_data) = get_icontrol_conf(log_file, user_name, pass_word, url,
                                           port, host_name, 0)

    if response_data:
        local_rc = 0
    else:
        local_rc = -2

    return local_rc


def get_host_details(log_file, list_head, login_user, https_port, no_tcp_conn):
    current_node = list_head
    while current_node:

        # Get the F5Host object from the link list node.
        host_data = current_node.get_data()

        ret, auth_token = get_rest_auth_token(log_file, login_user[0],
                                              login_user[1], host_data.ip_addr,
                                              https_port, "localhost",
                                              host_data.ip_ver)
        if ret != 0:
            write_to_log(log_file, host_data.ip_addr +
                         ' - INFO - Error Getting Auth Token')

        # Have to include a user name and password for TMOS 11. TMOS 11 does
        # not use auth tokens.
        rest_items = {'token': auth_token, 'user_name': login_user[0],
                      'password': login_user[1], 'ip-addr': host_data.ip_addr,
                      'port': https_port, 'hostname': "localhost",
                      'ip_ver': host_data.ip_ver, 'log_file': log_file}

        get_basic_host_info(rest_items, host_data, no_tcp_conn)

        # Check if device is a vCMP host. If yes, get the details of the vCMP guests.
        if host_data.vcmp_host is True:
            (ret, guest_info_list) = get_vcmp_guest(rest_items)
            if ret == 0:
                host_data.vcmp_guests = guest_info_list

        current_node = current_node.next_node


def get_basic_host_info(rest_items, host_data, no_tcp_conn):
    global FoundValue
    # noinspection PyUnusedLocal
    local_rc = 0

    (ret, ret_data) = get_host_name(rest_items)
    if ret == 0:
        host_data.hostname = ret_data
        rest_items['hostname'] = ret_data
    # Quick hack to stop processing devices with incomplete iControl REST API.
    # Should be device running TMOS less then version 11.6
    else:
        write_to_log(rest_items['log_file'], host_data.ip_addr +
                     ' - SKIPPING - Device does not have full iControl REST' +
                     ' support.')
        local_rc = -1

    if local_rc != -1:
        (ret, ret_data) = get_mgmt_ip(rest_items)
        if ret == 0:
            host_data.mgmt_ip_addr = ret_data

        (ret, ret_data, ret_data_1) = get_sys_hardware(rest_items)
        if ret == 0:
            host_data.chassis_id = ret_data
            host_data.hw_platform = ret_data_1

        (ret, ret_data) = get_tmos_ver(rest_items)
        if ret == 0:
            host_data.os_ver = ret_data

        (ret, ret_data, ret_data_1, ret_list) = get_mgmt_routes(rest_items)
        if ret == 0:
            if host_data.ip_ver == 4:
                host_data.def_mgmt_gw = ret_data
            elif host_data.ip_ver == 6:
                host_data.def_mgmt_gw = ret_data_1

            if ret_list:
                host_data.mgmt_routes = ret_list

        (ret, ret_data) = get_syslog_dest(rest_items)
        if ret == 0:
            host_data.log_hosts = ret_data

        (ret, ret_data) = get_sys_provision(rest_items)
        if ret == 0:
            host_data.act_modules = ret_data

        (ret, ret_data) = get_device_redundancy_state(rest_items)
        if ret == 0:
            host_data.net_failover_state = ret_data

    #            num - string
    #            0   - Viprion_Chassis
    #            1   - Appliance
    #            2   - VE
    #            3   - vCMP_Guest
    #            42  - None
    #            ?   - ERROR

        (ret, ret_data, host_data.vcmp_host) = get_cm_device(
            rest_items, host_data.chassis_id)
        if ret == 0:

            # A vCMP guest on a Viprion needs host_data.viprion to True
            if ret_data == 'viprion':
                host_data.hw_type = 0
                host_data.viprion = True

            # When the host is a vCMP guest on a Viprion "hw_platform" is
            # set to 3.
            if host_data.hw_platform == 'Z101':
                host_data.hw_type = 3
            elif ret_data == 'viprion':
                host_data.hw_type = 0
                host_data.viprion = True
            elif ret_data == 'individual':
                host_data.hw_type = 1
            else:
                host_data.hw_type = 42

        # The device is a vCMP guest and the management address is set to the
        # default value. Get the device's cluster address.
        if (host_data.hw_type == 3) and (host_data.mgmt_ip_addr == 'NA'):
            (ret, ret_data) = get_cluster_address(rest_items)
            if ret == 0:
                host_data.mgmt_ip_addr = ret_data

        # If device is a Viprion and a Viprion vCMP guest.
        # -Get the blade management addresses.
        # if (host_data.hw_type != 3) and (host_data.viprion is True):
        if host_data.viprion is True:

            (ret, ret_data, ret_data_1) = get_viprion_addresses(rest_items,
                                                                no_tcp_conn)
            if ret == 0:
                host_data.mgmt_ip_addr = ret_data
                host_data.viprion_blades = ret_data_1
            else:
                host_data.mgmt_ip_addr = 'Bad Cluster Address'

        # Wait until after getting the viprion addresses to test for
        # this issue.
        if host_data.ip_addr != host_data.mgmt_ip_addr:
            write_to_log(rest_items['log_file'],
                         host_data.ip_addr + ' - WARNING - Input IP (' + host_data.ip_addr +
                         ') address is not the device\'s management IP' +
                         ' address (' + host_data.mgmt_ip_addr + ').')


def log_device_details(log_file, list_head, no_tcp_conn):

    # Get the size of the largest dynamic output items
    # Initialize the dictionary of list of strings with the description strings.
    # The description strings could be longer then the dynamic output.
    str_dic = {'ip_addr': list(), 'os_ver': list(),
               'hostname': list(), 'chassis_id': list(),
               'mgmt_ip_addr': list(), 'def_mgmt_gw': list()}
    str_dic['ip_addr'].append('Input-Address')
    str_dic['os_ver'].append('OS-Version')
    str_dic['hostname'].append('Hostname')
    str_dic['chassis_id'].append('Chassis-ID')
    str_dic['mgmt_ip_addr'].append('Mgmt-Address')
    str_dic['def_mgmt_gw'].append('Mgmt-Gateway')

    current_node = list_head
    while current_node:

        host_data = current_node.get_data()
        str_dic['ip_addr'].append(host_data.ip_addr)
        str_dic['os_ver'].append(host_data.os_ver)
        str_dic['hostname'].append(host_data.hostname)
        str_dic['chassis_id'].append(host_data.chassis_id)
        str_dic['mgmt_ip_addr'].append(host_data.mgmt_ip_addr)
        str_dic['def_mgmt_gw'].append(host_data.def_mgmt_gw)

        current_node = current_node.next_node

    length_dic = max_object_len(str_dic)

    log_str_width = (5, length_dic['ip_addr'], length_dic['os_ver'],
                     length_dic['hostname'], 15, 8, length_dic['chassis_id'],
                     length_dic['mgmt_ip_addr'], length_dic['def_mgmt_gw'])

    log_str = 'Device details:\n'

    current_node = list_head
    count = 0
    while current_node:

        host_data = current_node.get_data()

        log_item_strings = ('Count', str_dic['ip_addr'][0],
                            str_dic['os_ver'][0], str_dic['hostname'][0],
                            'HW-Type', 'Platform',
                            str_dic['chassis_id'][0], str_dic['mgmt_ip_addr'][0],
                            str_dic['def_mgmt_gw'][0])
        (ret, line) = gen_log_line(log_item_strings, log_str_width, 0)
        if ret == 0:
            log_str += line

        log_item_strings = (count, host_data.ip_addr, host_data.os_ver,
                            host_data.hostname, hw_type_str(host_data.hw_type),
                            host_data.hw_platform, host_data.chassis_id,
                            host_data.mgmt_ip_addr, host_data.def_mgmt_gw)
        (ret, line) = gen_log_line(log_item_strings, log_str_width, 0)
        if ret == 0:
            log_str += line

        if f5_marketing_str(host_data.hw_platform):
            log_str += '      Marketing Name     : '
            log_str += '%s\n' % f5_marketing_str(host_data.hw_platform)

        if host_data.viprion is True:
            if no_tcp_conn is True:
                log_str += '      Viprion Slot Mgmt Addresses (Test: ICMP Echo):\n'
            else:
                log_str += '      Viprion Slot Mgmt Addresses (Test: TCP Conn):\n'

            for item in host_data.viprion_blades:
                log_str += '        %s\n' % item

        if host_data.log_hosts:
            log_str += '      Remote Logging Dest:\n'
            for item in host_data.log_hosts:
                log_str += '        %s\n' % item

        if host_data.act_modules:
            log_str += '      Active Modules:\n'
            for item in host_data.act_modules:
                for key, value in item.items():
                    if key == 'name':
                        log_str += '        {:<4s}: '.format(value)
                    if key == 'level':
                        log_str += '%s\n' % value

        if host_data.net_failover_state >= 0:
            log_str += '      Network Failover State:\n        %s\n' % (
                failover_strings(host_data.net_failover_state))

        # The test for vCMP returns true for a vCMP guest.
        # Do not display vCMP host details for a vCMP guest.
        if (host_data.vcmp_host is True) and (host_data.hw_type != 3):
            log_str += '      vCMP Host: True\n'
            if host_data.vcmp_guests:

                # ???? - Walk the dic for key strings or create dic template - ????

                # Get the size of the largest dynamic output items
                # Initialize the dictionary of list of strings with the description strings.
                # The description strings could be longer then the dynamic output.

                vcmp_guest_str_dic = {'hostname': list(), 'mgmt_ip': list(),
                                      'mgmt_gw': list(), 'state': list(),
                                      'min_slots': list(), 'allowed_slots': list(),
                                      'assigned_slots': list(), 'cores_per_slot': list(),
                                      'total_cpu_cores': list()}
                vcmp_guest_str_dic['hostname'].append('Hostname')
                vcmp_guest_str_dic['mgmt_ip'].append('Mgmt-Address')
                vcmp_guest_str_dic['mgmt_gw'].append('Mgmt-Gateway')
                vcmp_guest_str_dic['state'].append('State')
                vcmp_guest_str_dic['min_slots'].append('Min-Slots')
                vcmp_guest_str_dic['allowed_slots'].append('Allowed-Slots')
                vcmp_guest_str_dic['assigned_slots'].append('Assigned-Slots')
                vcmp_guest_str_dic['cores_per_slot'].append('Cores-Per-Slot')
                vcmp_guest_str_dic['total_cpu_cores'].append('Total-CPU')

                for item in host_data.vcmp_guests:
                    for key, value in item.items():
                        if key == 'hostname':
                            vcmp_guest_str_dic['hostname'].append(value)
                        if key == 'mgmt_ip':
                            vcmp_guest_str_dic['mgmt_ip'].append(value)
                        if key == 'mgmt_gw':
                            vcmp_guest_str_dic['mgmt_gw'].append(value)
                        if key == 'state':
                            vcmp_guest_str_dic['state'].append(value)
                        if key == 'min_slots':
                            vcmp_guest_str_dic['min_slots'].append(value)
                        # Reformat the value string.
                        if key == 'allowed_slots':
                            vcmp_guest_str_dic['allowed_slots'].append(
                                slot_list_to_log_str(value))
                        # Reformat the value string
                        if key == 'assigned_slots':
                            vcmp_guest_str_dic['assigned_slots'].append(
                                slot_list_to_log_str(value))
                        if key == 'cores_per_slot':
                            vcmp_guest_str_dic['cores_per_slot'].append(value)
                        if key == 'total_cpu_cores':
                            vcmp_guest_str_dic['total_cpu_cores'].append(value)

                vcmp_guest_str_len = max_object_len(vcmp_guest_str_dic)
                vcmp_guest_str_width = (vcmp_guest_str_len['hostname'],
                                        vcmp_guest_str_len['mgmt_ip'],
                                        vcmp_guest_str_len['mgmt_gw'],
                                        vcmp_guest_str_len['state'],
                                        vcmp_guest_str_len['min_slots'],
                                        vcmp_guest_str_len['allowed_slots'],
                                        vcmp_guest_str_len['assigned_slots'],
                                        vcmp_guest_str_len['cores_per_slot'],
                                        vcmp_guest_str_len['total_cpu_cores'])

                log_str += '        vCMP Guests:\n'

                log_item_strings = (vcmp_guest_str_dic['hostname'][0],
                                    vcmp_guest_str_dic['mgmt_ip'][0],
                                    vcmp_guest_str_dic['mgmt_gw'][0],
                                    vcmp_guest_str_dic['state'][0],
                                    vcmp_guest_str_dic['min_slots'][0],
                                    vcmp_guest_str_dic['allowed_slots'][0],
                                    vcmp_guest_str_dic['assigned_slots'][0],
                                    vcmp_guest_str_dic['cores_per_slot'][0],
                                    vcmp_guest_str_dic['total_cpu_cores'][0])
                (ret, line) = gen_log_line(log_item_strings, vcmp_guest_str_width,
                                           10)
                if ret == 0:
                    log_str += line

                for item in host_data.vcmp_guests:

                    log_item_strings = (item['hostname'],
                                        item['mgmt_ip'],
                                        item['mgmt_gw'], item['state'],
                                        item['min_slots'],
                                        slot_list_to_log_str(
                                            item['allowed_slots']),
                                        slot_list_to_log_str(
                                            item['assigned_slots']),
                                        item['cores_per_slot'],
                                        item['total_cpu_cores'])
                    (ret, line) = gen_log_line(log_item_strings, vcmp_guest_str_width,
                                               10)
                    if ret == 0:
                        log_str += line

        # Add line feed
        log_str += '\n'

        count += 1
        current_node = current_node.next_node

    write_to_log(log_file, log_str)


def log_mjw_mto_input_format(log_file, list_head):
    log_str = 'Devices in MJW F5 MTO Input Format:\n' \
        '# host-mgmt-ip-address;host-name;chassis-id;tmos-ver\n'
    current_node = list_head
    while current_node:

        host_data = current_node.get_data()
        log_str += '%s;%s;%s;%s\n' % (
            host_data.mgmt_ip_addr, host_data.hostname,
            host_data.chassis_id, host_data.os_ver)

        current_node = current_node.next_node
    write_to_log(log_file, log_str)


def csv_on_stdout(list_head):
    current_node = list_head

    print('mgmt_ip;hostname;chassis_id;sw_ver;sw_EoSD;sw_EoTS;hw_platform;'
          'hw_marketing;hw_EoS;hw_EoNSS;hw_EoSD;hw_EoTS;hw_EoRMA')
    while current_node:
        host_data = current_node.get_data()
        leading_str = '%s;%s;%s;%s;' % (
            host_data.mgmt_ip_addr, host_data.hostname,
            host_data.chassis_id, host_data.os_ver)

        if host_data.os_ver != 'NA':
            os_ver_list = host_data.os_ver.split('.', -1)
            # For TMOS 11.5 needs the main release number.
            if (os_ver_list[0] == 11) and (os_ver_list[1] == 5):
                short_os_ver = os_ver_list[0] + '.' + \
                    os_ver_list[1] + '.' + os_ver_list[2]
            else:
                short_os_ver = os_ver_list[0] + '.' + os_ver_list[1]

        sw_eol_str = ''
        for date in f5_sw_eol_list(short_os_ver):
            sw_eol_str += date + ';'

        hw_str = host_data.hw_platform + ';' + \
            f5_marketing_str(host_data.hw_platform) + ';'

        hw_eol_str = ''
        for date in f5_hw_eol_list(host_data.hw_platform):
            hw_eol_str += date + ';'

        print(leading_str + sw_eol_str + hw_str + hw_eol_str)

        # vCMP Guests

        # Viprion Blades --- should change f5-host.viprion_blades from list
        # to a dict and include blade hw details.

        current_node = current_node.next_node


def do_mto_review(log_file, list_head, login_user, https_port):
    # list of dictionaries
    mto_review_list = list()

    # Walk link list
    current_node = list_head
    while current_node:

        # init on each loop
        loop_error = 0
        httpd_acl_list = list()
        sshd_acl_list = list()
        snmp_acl_list = list()

        # Init individual ACL dictionary and set default values.
        httpd_dic = {'all': False, 'ipv4_loop': False, 'ipv6_loop': False,
                     # 'redundancy_nets' values: all, partial, none, no redundancy,
                     #                           error
                     'redundancy_nets': 'error', 'redundancy_nets_missing': None}
        sshd_dic = {'all': False, 'ipv4_loop': False, 'ipv6_loop': False,
                    # 'redundancy_nets' values: all, partial, none, no redundancy,
                    #                           error
                    'redundancy_nets': 'error', 'redundancy_nets_missing': None}
        # SNMP ACL - Only test for the presence of 'ALL'.
        snmp_dic = {'all': False}

        # Get the F5Host object from the link list node.
        host_data = current_node.get_data()

        # Init host_dic
        host_dic = {'hostname': host_data.hostname,
                    'mgmt_ip': host_data.mgmt_ip_addr,
                    'icmp': False,
                    'https': False,
                    'ssh': False,
                    'default-snmp': False,
                    'default_remote_user_role': 'NA',
                    'remote_console_access': 'NA',
                    'timezone': 'NA',
                    'idle_httpd': -1,
                    'idle_sshd': -1,
                    'idle_console': -1,
                    'acl_httpd': None,
                    'acl_sshd': None,
                    'acl_snmpd': None}

        ret, auth_token = get_rest_auth_token(log_file, login_user[0],
                                              login_user[1], host_data.ip_addr,
                                              https_port, "localhost",
                                              host_data.ip_ver)
        if ret != 0:
            write_to_log(log_file, host_data.ip_addr +
                         ' - INFO - Error Getting Auth Token')

        # Have to include a user name and password for TMOS 11. TMOS 11 does
        # not use auth tokens.
        rest_items = {'token': auth_token, 'user_name': login_user[0],
                      'password': login_user[1], 'ip-addr': host_data.ip_addr,
                      'port': https_port, 'hostname': host_data.hostname,
                      'ip_ver': host_data.ip_ver, 'log_file': log_file}

        # See if device answers ICMP echo request.
        # - Only works with unix system 'ping' utility.
        ret = ping_host(host_data.ip_addr, host_data.ip_ver)
        if ret == 0:
            host_dic['icmp'] = True

        # Try a TCP port connect to the HTTPS management port on the device.
        ret = tcp_connect_service_port(host_data.ip_addr, https_port)
        if ret == 0:
            host_dic['https'] = True

        # Try ssh login to device.
        # !!! HARD CODED SSH PORT NUMBER !!!
        ret = ssh_login_test(login_user[0], login_user[1], host_data.ip_addr,
                             22, host_data.hostname)
        if ret > 0:
            host_dic['ssh'] = True

        # Get configured time zone
        (ret, ret_data) = get_time_zone(rest_items)
        if ret == 0:
            host_dic['timezone'] = ret_data
        # Quick hack to stop processing devices with incomplete iControl REST API.
        # Should be device running TMOS less then version 11.6
        else:
            write_to_log(rest_items['log_file'], rest_items['ip-addr'] +
                         ' - SKIPPING - Device does not have full iControl REST' +
                         ' support.')
            loop_error = -1

        if loop_error == 0:
            # Get the default remote user roll.
            (ret, ret_data, ret_data_1) = get_remote_user_conf(rest_items)
            if ret > 0:
                host_dic['default_remote_user_role'] = ret_data
                host_dic['remote_console_access'] = ret_data_1

            # # Get remote user roles.
            # (ret, ret_data) = get_list_remote_user_roles(rest_items)
            # # Add remote user roles to host dictionary.
            # if ret == 0:
            #     host_dic['remote_roles'] = ret_data

            # Get user session idle timers.
            (ret, ret_data) = get_httpd_idle_timeout(rest_items)
            if ret == 0:
                host_dic['idle_httpd'] = ret_data

            (ret, ret_data) = get_sshd_idle(rest_items)
            if ret == 0:
                host_dic['idle_sshd'] = ret_data

            (ret, ret_data) = get_console_idle_timeout(rest_items)
            if ret == 0:
                host_dic['idle_console'] = ret_data

            # Check for factory default SNMP community
            ret = check_for_factory_default_snmp_community(rest_items)
            if ret == 1:
                host_dic['default-snmp'] = True

            (ret, ret_data) = get_httpd_allow(rest_items)
            if ret == 0:
                httpd_acl_list = ret_data

            (ret, ret_data) = get_sshd_allow(rest_items)
            if ret == 0:
                sshd_acl_list = ret_data

            (ret, ret_data) = get_snmp_allow(rest_items)
            if ret == 0:
                snmp_acl_list = ret_data

            # Check ACL for the presence of 'ALL'.
            if check_acl_for_all(httpd_acl_list) is True:
                httpd_dic['all'] = True
            if check_acl_for_all(sshd_acl_list) is True:
                sshd_dic['all'] = True
            if check_acl_for_all(snmp_acl_list) is True:
                snmp_dic['all'] = True

            # Check ACL for IPv4 and IPv6 localhost loop back addresses.
            ret = check_acl_for_loopbacks(httpd_acl_list)
            # ACL contains only the IPv4 loop back address range, 127.0.0.0/8.
            if ret == 1:
                httpd_dic['ipv4_loop'] = True
            # ACL contains only the IPv6 loop back address, ::1.
            elif ret == 2:
                httpd_dic['ipv6_loop'] = True
            # ACL contains both the IPv4 loop back range and
            # the IPv6 loop back address.
            elif ret == 3:
                httpd_dic['ipv4_loop'] = True
                httpd_dic['ipv6_loop'] = True

            # Check the https and sshd ACL for IPv4 and IPv6 loop back addresses.
            ret = check_acl_for_loopbacks(sshd_acl_list)
            # ACL contains only the IPv4 loop back address range, 127.0.0.0/8.
            if ret == 1:
                sshd_dic['ipv4_loop'] = True
            # ACL contains only the IPv6 loop back address, ::1.
            elif ret == 2:
                sshd_dic['ipv6_loop'] = True
            # ACL contains both the IPv4 loop back range and
            # the IPv6 loop back address.
            elif ret == 3:
                sshd_dic['ipv4_loop'] = True
                sshd_dic['ipv6_loop'] = True

            # Check the https and sshd ACL for network redundancy subnets.
            (ret, redundancy_nets) = get_unicast_redundancy_subnets(rest_items)
            # "ret" will be zero when a device is configured with uni-cast redundancy
            # subnets.
            if ret == 0:
                (httpd_dic['redundancy_nets'],
                 httpd_dic['redundancy_nets_missing']) = check_acl_for_subnets(
                     httpd_acl_list, redundancy_nets)

                (sshd_dic['redundancy_nets'],
                 sshd_dic['redundancy_nets_missing']) = check_acl_for_subnets(
                     sshd_acl_list, redundancy_nets)

            else:
                httpd_dic['redundancy_nets'] = 'no redundancy'
                sshd_dic['redundancy_nets'] = 'no redundancy'

            # Add device ACL review dictionaries to mto_review_list.
            host_dic['acl_httpd'] = httpd_dic
            host_dic['acl_sshd'] = sshd_dic
            host_dic['acl_snmp'] = snmp_dic

            mto_review_list.append(host_dic)

        current_node = current_node.next_node

    # Add ACL review to the log
    log_mto_review(log_file, mto_review_list)


def log_mto_review(log_file, mto_review_list):

    # Get the size of the largest dynamic output items
    # Initialize the dictionary of list of strings with the description strings.
    # The description strings could be longer then the dynamic output.
    str_dic = {'hostname': list(), 'mgmt_ip': list()}
    str_dic['hostname'].append('Hostname')
    str_dic['mgmt_ip'].append('Mgmt-Address')

    for entry in mto_review_list:
        for key, value in entry.items():
            if key == 'hostname':
                str_dic['hostname'].append(value)
            if key == 'mgmt_ip':
                str_dic['mgmt_ip'].append(value)

    length_dic = max_object_len(str_dic)
    log_str_width = (length_dic['hostname'], length_dic['mgmt_ip'])

    log_str = 'MTO Review:\n'

    for entry in mto_review_list:
        # Log Hostname and mgmt address
        log_str_list = ['na', 'na']
        for key, value in entry.items():
            if key == 'hostname':
                log_str_list[0] = value
            if key == 'mgmt_ip':
                log_str_list[1] = value

        (ret, line) = gen_log_line(('Hostname', 'Mgmt-Address'), log_str_width, 1)
        if ret == 0:
            log_str += line

        (ret, line) = gen_log_line(log_str_list, log_str_width, 1)
        if ret == 0:
            log_str += line

        # Access tests
        log_str += '   Access Tests:\n'

        log_str += '     ICMP Echo: '
        if entry['icmp'] is True:
            log_str += 'yes'
        else:
            log_str += 'no'
        log_str += '\n'

        log_str += '     HTTPS    : '
        if entry['https'] is True:
            log_str += 'yes'
        else:
            log_str += 'no'
        log_str += '\n'

        log_str += '     SSH      : '
        if entry['ssh'] is True:
            log_str += 'yes'
        else:
            log_str += 'no'
        log_str += '\n'

        # Log time zone:
        log_str += '   Time Zone                : '
        log_str += '%s\n' % entry['timezone']

        # Default Remote User Role:
        log_str += '   Default Remote User Role : '
        log_str += '%s\n' % entry['default_remote_user_role']

        # Remote user roles:
        if 'remote_roles' in entry:
            log_str += '   Remote User Roles:\n'
            for role in entry['remote_roles']:
                log_str += '     Name              : %s\n' % role['name']
                log_str += '       Line Order      : %d\n' % role['line_order']
                log_str += '       Attribute String: %s\n' % role['attribute']
                log_str += '       Remote Access   : %s\n' % role['enabled']
                log_str += '       Assigned Role   : %s\n' % role['role']
                log_str += '       Partition Access: %s\n' % role['partition']
                log_str += '       Terminal Access : %s\n' % role['console']
        else:
            log_str += '   Remote User Roles        : none\n'

        # Remote Console Access
        log_str += '   Default Console Access   : '
        log_str += '%s\n' % entry['remote_console_access']

        # User Session Idle Timers
        log_str += '   HTTP Session Idle Timeout: '
        log_str += '%s\n' % entry['idle_httpd']

        log_str += '   SSH Session Idle Timeout : '
        log_str += '%s\n' % entry['idle_sshd']

        log_str += '   Console Idle Timeout     : '
        log_str += '%s\n' % entry['idle_console']

        # Log default SNMP community
        log_str += '   Default SNMP Community   : '
        for key, value in entry.items():
            if key == 'default-snmp':
                if value is True:
                    log_str += 'yes\n'
                else:
                    log_str += 'no\n'

        # Log ACL check details
        log_str += '   Access Control Lists:\n'
        for key, value in entry.items():
            if key == 'acl_httpd':
                log_str += '     HTTPD ACL:\n'
                log_str += log_acl_review_dic(value)
            if key == 'acl_sshd':
                log_str += '     SSHD  ACL:\n'
                log_str += log_acl_review_dic(value)
            if key == 'acl_snmp':
                log_str += '     SNMP  ACL:\n'
                log_str += log_acl_review_dic(value)

        # Add new line
        log_str += '\n'

    write_to_log(log_file, log_str)


def log_acl_review_dic(acl_dic):
    log_lines = ''

    for key, value in acl_dic.items():

        if key == 'all':
            log_lines += '       ALL Present      : '
            if value is True:
                log_lines += 'yes'
            else:
                log_lines += 'no'
            log_lines += '\n'

        if key == 'ipv4_loop':
            log_lines += '       IPv4 Loop Back   : '
            if value is False:
                log_lines += 'no'
            else:
                log_lines += 'yes'
            log_lines += '\n'

        if key == 'ipv6_loop':
            log_lines += '       IPv6 Loop Back   : '
            if value is False:
                log_lines += 'no'
            else:
                log_lines += 'yes'
            log_lines += '\n'

        if key == 'redundancy_nets':
            log_lines += '       Redundancy Subnet: %s\n' % value

            log_lines += '         Missing Subnets:'
            # if (value == 'partial') or (value == 'none'):
            if value in ['partial', 'none']:
                log_lines += '\n'
                for subnet in acl_dic['redundancy_nets_missing']:
                    log_lines += '           %s\n' % subnet
            else:
                log_lines += ' none\n'

    return log_lines


def slot_list_to_log_str(slot_list):
    tmp_str = ''
    list_len = len(slot_list)
    for i in range(0, list_len):
        if not slot_list[i] in ['[', ']', ' ', ',']:
            tmp_str += '%s,' % slot_list[i]

    # Remove trailing comma
    tmp_str = tmp_str[:-1]

    return tmp_str


# noinspection PyUnusedLocal
def max_object_len(str_dic):
    object_len = 0
    length_dic = {}

    for key, value in str_dic.items():
        length_dic[key] = 0
        for str_object in value:

            if isinstance(str_object, str):
                object_len = len(str_object)
            elif isinstance(str_object, (int, float)):
                object_len = len(str(str_object))

            if object_len > length_dic[key]:
                length_dic[key] = object_len

    return length_dic


def gen_log_line(str_list, width_list, lead_spaces):
    local_rc = 0
    line_format = ''
    log_line = ''

    number_items = len(str_list)

    # Length of string and width lists need to be the same.
    if number_items != len(width_list):
        local_rc = -1

    if local_rc == 0:

        # Add leading spaces to line.
        for i in range(0, lead_spaces):
            log_line += ' '

        # Add items to log line
        for i in range(0, number_items):
            if isinstance(str_list[i], str):
                line_format = '{:<{width}s} '
            elif isinstance(str_list[i], int):
                line_format = '{:<{width}d} '
            elif isinstance(str_list[i], float):
                line_format = '{:<{width}f} '

            log_line += line_format.format(str_list[i], width=width_list[i])

        # Add new line to the end of the line.
        log_line += '\n'

    return local_rc, log_line


def f5_marketing_str(hw_platform):
    f5_market_names = {
        'NA': 'NA',
        # TMOS 11.6.1 release notes
        'C114': '800',
        'C102': '1600',
        'C103': '3600',
        'C106': '3900',
        'D104': '6900',
        'D106': '8900',
        'D107': '8950',
        'E101': '11000',
        'E102': '11050',
        'C112': '2000s, 2200s',
        'C113': '4000s,4200v',
        'C109': '5000s, 5050s, 5200v, 5250v',
        'D110': '7000s, 7050s, 7200v, 7250v',
        'D111': '12250v',
        'D112': '10150s, 10350v',
        'D113': '10000s, 100050s, 10055, 10200v, 10250v, 10255',
        'A109': 'VIPRION B2100 Blade',
        'A113': 'VIPRION B2150 Blade',
        'A112': 'VIPRION B2250 Blade',
        'A107': 'VIPRION B4200 Blade',
        'A111': 'VIPRION B4200N Blade',
        'A108': 'VIPRION B4300 Blade',
        'A110': 'VIPRION B4340N Blade',
        'Z100': 'Virtual Edition (VE)',
        'Z101': 'vCMP Guest',
        # F5 KB K9412 - 11-MAR-2019
        'C117': 'i850, i2600, i2800',
        'C115': 'i4600, i4800',
        'C119': 'i5600, i5800',
        'C125': 'i5820-DF',
        'C118': 'i7600, i7800',
        'C126': 'i7820-DF',
        'C116': 'i10600, i10800',
        'C123': 'i11600, i11800',
        'C124': 'i11400-DS, i11600-DS, i11800-DS',
        'D116': 'i15600, i15800',
        'C120': 'Herculon i2800',
        'C121': 'Herculon i5800',
        'C122': 'Herculon i10800',
        # Ver 1.4 update - 07-MAY-2020
        'A100': 'VIPRION B4100 Blade',
        'A105': 'VIPRION B4100 Blade NEBS',
        'A114': 'VIPRION B4450N Blade',
        'D63': '6400 NEBS',
    }

    return f5_market_names[hw_platform]


def f5_hw_eol_list(hw_platform):
    f5_hw_eol = {
        # [EoS, EoNSS, EoSD, EoTS,EoRMA]
        'NA': ['NA', 'NA', 'NA', 'NA', 'NA'],
        'A100': ['30-Jun-2012', '30-Jun-2014', '30-Jun-2015', '30-Jun-2019', '30-Jun-2019'],
        'A105': ['30-Jun-2012', '30-Jun-2014', '30-Jun-2015', '30-Jun-2019', '30-Jun-2019'],
        'A107': ['1-Apr-2014', '1-Apr-2016', '1-Apr-2017', '1-Apr-2021', '1-Apr-2021'],
        'A108': ['01-Apr-2018', '01-Apr-2020', '01-Apr-2021', '01-Apr-2025', '01-Apr-2025'],
        'A109': ['01-Oct-2015', '01-Oct-2017', '01-Oct-2018', '01-Oct-2022', '01-Oct-2022'],
        'A110': ['01-Jul-2018', '01-Jul-2020', '01-Jul-2021', '01-Jul-2025', '01-Jul-2025'],
        'A111': ['1-Jul-2014', '1-Jul-2016', '1-Jul-2017', '1-Jul-2021', '1-Jul-2021'],
        'A112': ['---', '---', '---', '---', '---'],
        'A113': ['---', '---', '---', '---', '---'],
        'A114': ['---', '---', '---', '---', '---'],
        'C102': ['01-Oct-2014', '01-Oct-2016', '01-Oct-2017', '01-Oct-2021', '01-Oct-2021'],
        'C103': ['01-Oct-2014', '01-Oct-2016', '01-Oct-2017', '01-Oct-2021', '01-Oct-2021'],
        'C106': ['01-Feb-2015', '01-Feb-2017', '01-Feb-2018', '01-Feb-2022', '01-Feb-2022'],
        'C109': ['01-Apr-2018', '01-Apr-2020', '01-Apr-2021', '01-Apr-2025', '01-Apr-2025'],
        'C112': ['01-Apr-2018', '01-Apr-2020', '01-Apr-2021', '01-Apr-2025', '01-Apr-2025'],
        'C113': ['01-Apr-2018', '01-Apr-2020', '01-Apr-2021', '01-Apr-2025', '01-Apr-2025'],
        'C114': ['31-Jan-2017', '31-Jan-2019', '31-Jan-2020', '31-Jan-2024', '31-Jan-2024'],
        'C115': ['---', '---', '---', '---', '---'],
        'C116': ['---', '---', '---', '---', '---'],
        'C117': ['---', '---', '---', '---', '---'],
        'C118': ['---', '---', '---', '---', '---'],
        'C119': ['---', '---', '---', '---', '---'],
        'C120': ['01-Jul-2018', '01-Jul-2018', '01-Jul-2019', '01-Jul-2021', '01-Jul-2021'],
        'C121': ['01-Jul-2018', '01-Jul-2018', '01-Jul-2019', '01-Jul-2021', '01-Jul-2021'],
        'C122': ['01-Jul-2018', '01-Jul-2018', '01-Jul-2019', '01-Jul-2021', '01-Jul-2021'],
        'C123': ['---', '---', '---', '---', '---'],
        'C124': ['---', '---', '---', '---', '---'],
        'C125': ['---', '---', '---', '---', '---'],
        'C126': ['---', '---', '---', '---', '---'],
        'D63': ['01-Oct-2011', '01-May-2012*', '01-Oct-2014', '01-Oct-2018', '01-Oct-2018'],
        'D104': ['01-Feb-2015', '01-Feb-2017', '01-Feb-2018', '01-Feb-2022', '01-Feb-2022'],
        'D106': ['01-Feb-2015', '01-Feb-2017', '01-Feb-2018', '01-Feb-2022', '01-Feb-2022'],
        'D107': ['01-Feb-2015', '01-Feb-2017', '01-Feb-2018', '01-Feb-2022', '01-Feb-2022'],
        'D110': ['01-Apr-2018', '01-Apr-2020', '01-Apr-2021', '01-Apr-2025', '01-Apr-2025'],
        'D111': ['1-Aug-2019', '1-Aug-2021', '1-Aug-2022', '1-Aug-2026', '1-Aug-2026'],
        'D112': ['1-Aug-2019', '1-Aug-2021', '1-Aug-2022', '1-Aug-2026', '1-Aug-2026'],
        'D113': ['01-Apr-2018', '01-Apr-2020', '01-Apr-2021', '01-Apr-2025', '01-Apr-2025'],
        'E101': ['1-Apr-2016', '1-Apr-2018', '1-Apr-2019', '1-Apr-2023', '1-Apr-2023'],
        'E102': ['1-Jan-2014', '1-Jan-2016', '1-Jan-2017', '1-Jan-2021', '1-Jan-2021'],
        'Z100': ['---', '---', '---', '---', '---'],
        'Z101': ['---', '---', '---', '---', '---'],
    }
    return f5_hw_eol[hw_platform]


def f5_sw_eol_list(hw_platform):
    f5_sw_eol = {
        # [EoSD, EoTS]
        '16.1': ['July 7, 2025','July 7, 2025'],
        '16.0': ['October 7, 2021','October 7, 2021'],
        '15.1': ['December 11, 2024', 'December 11, 2024'],
        '15.0': ['August 23, 2020', 'August 23, 2020'],
        '14.1': ['December 11, 2023', 'December 11 2023'],
        '14.0': ['November 9, 2019', 'November 9, 2019'],
        '13.1': ['December 19, 2022', 'December 19, 2023'],
        '13.0': ['May 22, 2018', 'May 22, 2019'],
        '12.1': ['May 18, 2021', 'May 18, 2022'],
        '12.0': ['December 2, 2016', 'December 2, 2017'],
        '11.6': ['May 10, 2021', 'May 10, 2022'],
        '11.5.10': ['April 8, 2019', 'April 8, 2020'],
        '11.5.9': ['April 8, 2019', 'April 8, 2020'],
        '11.5.8': ['April 8, 2019', 'April 8, 2020'],
        '11.5.7': ['April 8, 2019', 'April 8, 2020'],
        '11.5.6': ['April 8, 2019', 'April 8, 2020'],
        '11.5.5': ['April 8, 2019', 'April 8, 2020'],
        '11.5.4': ['April 8, 2019', 'April 8, 2020'],
        '11.5.3': ['April 8, 2019', 'April 8, 2020'],
        '11.5.2': ['April 8, 2019', 'April 8, 2020'],
        '11.5.1': ['April 8, 2018', 'April 8, 2019'],
        '11.5.0': ['January 31, 2016', 'January 31, 2017'],
    }
    return f5_sw_eol[hw_platform]


def get_httpd_allow(rest_items):
    global FoundValue
    url = 'na'
    return_data = None
    local_rc = -3  # noinspection PyUnusedLocal
    if rest_items['ip_ver'] == 4:
        url = "https://%s/mgmt/tm/sys/httpd" % rest_items['ip-addr']
    elif rest_items['ip_ver'] == 6:
        url = "https://[%s]/mgmt/tm/sys/httpd" % rest_items['ip-addr']

    (ret, response_data) = token_get_icontrol_conf(rest_items['log_file'],
                                                   rest_items['token'],
                                                   rest_items['user_name'],
                                                   rest_items['password'],
                                                   url,
                                                   rest_items['port'],
                                                   rest_items['hostname'],
                                                   1)

    if ret == 0:
        data = json.loads(response_data.decode('utf-8'))

        # HTTPD allowed source IP addresses
        json_search(data, 'allow')
        if FoundValue != 0:
            return_data, FoundValue = FoundValue, 0
            # noinspection PyUnusedLocal
            local_rc = 0
        else:
            # noinspection PyUnusedLocal
            local_rc = -2

    else:
        # noinspection PyUnusedLocal
        local_rc = -1

    return local_rc, return_data


def get_sshd_allow(rest_items):
    global FoundValue
    url = 'na'
    return_data = 'na'
    # noinspection PyUnusedLocal,PyUnusedLocal
    local_rc = -3

    if rest_items['ip_ver'] == 4:
        url = "https://%s/mgmt/tm/sys/sshd" % rest_items['ip-addr']
    elif rest_items['ip_ver'] == 6:
        url = "https://[%s]/mgmt/tm/sys/sshd" % rest_items['ip-addr']

    (ret, response_data) = token_get_icontrol_conf(rest_items['log_file'],
                                                   rest_items['token'],
                                                   rest_items['user_name'],
                                                   rest_items['password'],
                                                   url,
                                                   rest_items['port'],
                                                   rest_items['hostname'],
                                                   1)

    if ret == 0:
        data = json.loads(response_data.decode('utf-8'))

        # SSH allowed source IP addresses
        json_search(data, 'allow')
        if FoundValue != 0:
            return_data, FoundValue = FoundValue, 0
            local_rc = 0
        else:
            local_rc = -2

    else:
        local_rc = -1

    return local_rc, return_data


def get_snmp_allow(rest_items):
    global FoundValue
    url = 'na'
    return_data = None
    # noinspection PyUnusedLocal
    local_rc = -3

    if rest_items['ip_ver'] == 4:
        url = "https://%s/mgmt/tm/sys/snmp" % rest_items['ip-addr']
    elif rest_items['ip_ver'] == 6:
        url = "https://[%s]/mgmt/tm/sys/snmp" % rest_items['ip-addr']

    (ret, response_data) = token_get_icontrol_conf(rest_items['log_file'],
                                                   rest_items['token'],
                                                   rest_items['user_name'],
                                                   rest_items['password'],
                                                   url,
                                                   rest_items['port'],
                                                   rest_items['hostname'], 1)

    if ret == 0:
        data = json.loads(response_data.decode('utf-8'))

        # SNMP ACL
        json_search(data, 'allowedAddresses')
        if FoundValue != 0:
            return_data, FoundValue = FoundValue, 0
            local_rc = 0
        else:
            FoundValue = 0
            local_rc = -2

    else:
        local_rc = -1

    return local_rc, return_data


def get_sshd_idle(rest_items):
    global FoundValue
    url = 'na'
    return_data = None
    # noinspection PyUnusedLocal
    local_rc = -3

    if rest_items['ip_ver'] == 4:
        url = "https://%s/mgmt/tm/sys/sshd" % rest_items['ip-addr']
    elif rest_items['ip_ver'] == 6:
        url = "https://[%s]/mgmt/tm/sys/sshd" % rest_items['ip-addr']

    (ret, response_data) = token_get_icontrol_conf(rest_items['log_file'],
                                                   rest_items['token'],
                                                   rest_items['user_name'],
                                                   rest_items['password'],
                                                   url,
                                                   rest_items['port'],
                                                   rest_items['hostname'],
                                                   1)

    if ret == 0:
        data = json.loads(response_data.decode('utf-8'))

        json_search(data, 'inactivityTimeout')
        if FoundValue != 0:
            return_data, FoundValue = FoundValue, 0
            local_rc = 0
        else:
            local_rc = -2
    else:
        local_rc = -1

    return local_rc, return_data


def get_httpd_idle_timeout(rest_items):
    global FoundValue
    url = 'na'
    return_data = None
    # noinspection PyUnusedLocal
    local_rc = -3

    if rest_items['ip_ver'] == 4:
        url = "https://%s/mgmt/tm/sys/httpd" % rest_items['ip-addr']
    elif rest_items['ip_ver'] == 6:
        url = "https://[%s]/mgmt/tm/sys/httpd" % rest_items['ip-addr']

    (ret, response_data) = token_get_icontrol_conf(rest_items['log_file'],
                                                   rest_items['token'],
                                                   rest_items['user_name'],
                                                   rest_items['password'],
                                                   url,
                                                   rest_items['port'],
                                                   rest_items['hostname'],
                                                   1)

    if ret == 0:
        data = json.loads(response_data.decode('utf-8'))

        # The value for 'authPamidle_timeout'can be 0.
        # -Temporary changing FoundValue test value.
        FoundValue = 'na'
        json_search(data, 'authPamIdleTimeout')
        if FoundValue != 'na':
            temp, FoundValue = FoundValue, 0
            return_data = int(temp)
            local_rc = 0
        else:
            FoundValue = 0
            local_rc = -2
    else:
        local_rc = -1

    return local_rc, return_data


def get_console_idle_timeout(rest_items):
    global FoundValue
    url = 'na'
    return_data = None
    # noinspection PyUnusedLocal
    local_rc = -3

    if rest_items['ip_ver'] == 4:
        url = "https://%s/mgmt/tm/sys/global-settings" % rest_items['ip-addr']
    elif rest_items['ip_ver'] == 6:
        url = "https://[%s]/mgmt/tm/sys/global-settings" % rest_items['ip-addr']

    (ret, response_data) = token_get_icontrol_conf(rest_items['log_file'],
                                                   rest_items['token'],
                                                   rest_items['user_name'],
                                                   rest_items['password'],
                                                   url,
                                                   rest_items['port'],
                                                   rest_items['hostname'],
                                                   1)

    if ret == 0:
        data = json.loads(response_data.decode('utf-8'))

        # The value for 'consoleInactivityTimeout' can be 0.
        # -Temporary changing FoundValue test value.
        FoundValue = 'na'
        json_search(data, 'consoleInactivityTimeout')
        if FoundValue != 'na':
            temp, FoundValue = FoundValue, 0
            return_data = int(temp)
            local_rc = 0
        else:
            FoundValue = 0
            local_rc = -2

    else:
        local_rc = -1

    return local_rc, return_data


def check_acl_for_all(acl_list):
    all_present = False

    for address in acl_list:
        if address in ['ALL', 'All', 'all', 'ANY', 'Any', 'any']:
            all_present = True

    return all_present

# 0: No loop backs in ACL
# 1: Only IPv4 Loop back in ACL
# 2: Only IPv6 Loop back in ACL
# 3: Both IPv4 and IPv6 Loop back in ACL


def check_acl_for_loopbacks(acl_list):
    local_rc = 0

    for address in acl_list:
        if address == '127.0.0.0/8':
            # Case: When on other loopback was found.
            if local_rc == 0:
                local_rc = 1
            # Case: When the IPv6 loopback was found.
            if local_rc == 2:
                local_rc = 3
        if address == '::1':
            # Case: When on other loopback was found.
            if local_rc == 0:
                local_rc = 2
            # Case: When the IPv4 loopback was found.
            if local_rc == 1:
                local_rc = 3

    return local_rc


def check_acl_for_subnets(acl_list, subnet_list):
    missing_list = list()
    count = 0

    for subnet_addr in subnet_list:
        subnet_match = False
        for acl_item in acl_list:
            if subnet_addr == acl_item:
                subnet_match = True
                count += 1
        if subnet_match is False:
            missing_list.append(subnet_addr)

    if count > 0:
        if count == len(subnet_list):
            return_str = 'all'
        else:
            return_str = 'partial'
    else:
        return_str = 'none'

    return return_str, missing_list


def get_unicast_redundancy_subnets(rest_items):
    global FoundValue
    url = 'na'
    return_data = list()
    local_unicast = list()
    local_selfip = list()
    local_match = list()
    # noinspection PyUnusedLocal
    local_rc = -3

    if rest_items['ip_ver'] == 4:
        url = "https://%s/mgmt/tm/cm/device/~Common~%s" % (rest_items['ip-addr'],
                                                           rest_items['hostname'])
    elif rest_items['ip_ver'] == 6:
        url = "https://[%s]/mgmt/tm/cm/device/~Common~%s" % (rest_items['ip-addr'],
                                                             rest_items['hostname'])

    (ret, response_data) = token_get_icontrol_conf(rest_items['log_file'],
                                                   rest_items['token'],
                                                   rest_items['user_name'],
                                                   rest_items['password'],
                                                   url,
                                                   rest_items['port'],
                                                   rest_items['hostname'],
                                                   1)

    if ret == 0:
        data = json.loads(response_data.decode('utf-8'))

        json_search(data, 'unicastAddress')
        if FoundValue != 0:
            temp, FoundValue = FoundValue, 0
            for item in temp:
                for key, value in item.items():
                    if key == 'ip':
                        local_unicast.append(value)
            local_rc = 2

        else:
            local_rc = -2

    else:
        local_rc = -1

    if rest_items['ip_ver'] == 4:
        url = "https://%s/mgmt/tm/net/self" % rest_items['ip-addr']
    elif rest_items['ip_ver'] == 6:
        url = "https://[%s]/mgmt/tm/net/self" % rest_items['ip-addr']

    (ret, response_data) = token_get_icontrol_conf(rest_items['log_file'],
                                                   rest_items['token'],
                                                   rest_items['user_name'],
                                                   rest_items['password'],
                                                   url,
                                                   rest_items['port'],
                                                   rest_items['hostname'],
                                                   1)

    if ret == 0:
        data = json.loads(response_data.decode('utf-8'))

        json_search(data, 'items')
        if FoundValue != 0:
            temp, FoundValue = FoundValue, 0
            for item in temp:
                for key, value in item.items():
                    if key == 'address':
                        local_selfip.append(value)
                local_rc = 3

        else:
            local_rc = -4

    else:
        local_rc = -3

    for addr in local_unicast:

        for selfIp in local_selfip:
            if addr == (selfIp.split('/', 1))[0]:
                local_match.append(selfIp)
                local_rc = 4
                break

        # Mgmt Ethernet port
        if addr == rest_items['ip-addr']:

            if rest_items['ip_ver'] == 4:
                url = "https://%s/mgmt/tm/sys/management-ip" % rest_items['ip-addr']
            elif rest_items['ip_ver'] == 6:
                url = "https://[%s]/mgmt/tm/sys/management-ip" % rest_items['ip-addr']

            (ret, response_data) = token_get_icontrol_conf(rest_items['log_file'],
                                                           rest_items['token'],
                                                           rest_items['user_name'],
                                                           rest_items['password'],
                                                           url,
                                                           rest_items['port'],
                                                           rest_items['hostname'],
                                                           1)

            if ret == 0:
                data = json.loads(response_data.decode('utf-8'))
                json_search(data, 'fullPath')
                if FoundValue != 0:
                    temp, FoundValue = FoundValue, 0
                    local_match.append(temp)
                    local_rc = 5
                else:
                    local_rc = -6

            else:
                local_rc = -5

    # noinspection SpellCheckingInspection
    for unicast in local_match:
        selfip_addr = unicast.split('/', 1)
        # ver = test_ip_address(selfip_addr[0]) # MTO program fuction
        ver = test_host_ip_address(selfip_addr[0])
        if ver > 0:
            (ret, subnet) = get_ip_subnet(
                selfip_addr[0], int(selfip_addr[1]), ver)
            if ret == 0:
                return_data.append(subnet + '/' + selfip_addr[1])
                local_rc = 0

            else:
                local_rc = -8

        else:
            local_rc = -7

    return local_rc, return_data


# Based on calc_subnet() from:
# https://github.com/fdslight/fdslight/blob/master/freenet/lib/utils.py
# - BSD 2-Clause "Simplified" License -
def get_ip_subnet(ip_addr, prefix, ip_ver):
    local_list = -1
    byte_addr = []
    return_data = None
    local_rc = -1

    if prefix == 32 and ip_ver == 4:
        return_data = ip_addr
    elif prefix == 128 and ip_ver == 6:
        return_data = ip_addr
    else:

        if ip_ver == 4:
            byte_addr = socket.inet_pton(socket.AF_INET, ip_addr)
            array = bytearray(4)
            local_list = array
        elif ip_ver == 6:
            byte_addr = socket.inet_pton(socket.AF_INET6, ip_addr)
            array = bytearray(16)
            local_list = array

        if not byte_addr:
            local_rc = -1

        num_octets = int(prefix / 8)
        other_bits = prefix % 8

        local_list[0:num_octets] = byte_addr[0:num_octets]
        if local_list[0] != byte_addr[0]:
            local_rc = -2

        i = 0
        for x in range(other_bits + 1):
            if x == 0:
                continue
            i += 2 ** (8 - x)

        local_list[num_octets] = byte_addr[num_octets] & i

        if ip_ver == 4:
            return_data = socket.inet_ntop(socket.AF_INET, bytes(local_list))
        elif ip_ver == 6:
            return_data = socket.inet_ntop(socket.AF_INET6, bytes(local_list))

        if return_data:
            local_rc = 0

    return local_rc, return_data


def get_remote_user_conf(rest_items):
    global FoundValue
    url = 'na'
    default_role = None
    remote_console = None
    # noinspection PyUnusedLocal
    local_rc = -3

    if rest_items['ip_ver'] == 4:
        url = "https://%s/mgmt/tm/auth/remote-user" % rest_items['ip-addr']
    elif rest_items['ip_ver'] == 6:
        url = "https://[%s]/mgmt/tm/auth/remote-user" % rest_items['ip-addr']

    (ret, response_data) = token_get_icontrol_conf(rest_items['log_file'],
                                                   rest_items['token'],
                                                   rest_items['user_name'],
                                                   rest_items['password'],
                                                   url,
                                                   rest_items['port'],
                                                   rest_items['hostname'],
                                                   1)
    if ret == 0:
        data = json.loads(response_data.decode('utf-8'))

        json_search(data, 'defaultRole')
        if FoundValue != 0:
            default_role, FoundValue = FoundValue, 0
            local_rc = 1
        else:
            local_rc = -2

        json_search(data, 'remoteConsoleAccess')
        if FoundValue != 0:
            remote_console, FoundValue = FoundValue, 0
            if local_rc == 1:
                local_rc = 3
            else:
                local_rc = 2
        else:
            local_rc = -2

    else:
        local_rc = -1

    return local_rc, default_role, remote_console


def get_list_remote_user_roles(rest_items):
    global FoundValue
    url = 'na'
    return_data = list()
    # noinspection PyUnusedLocal
    local_rc = -3

    if rest_items['ip_ver'] == 4:
        url = "https://%s/mgmt/tm/auth/remote-role/role-info" % rest_items['ip-addr']
    elif rest_items['ip_ver'] == 6:
        url = "https://[%s]/mgmt/tm/auth/remote-role/role-info" % rest_items['ip-addr']

    (ret, response_data) = token_get_icontrol_conf(rest_items['log_file'],
                                                   rest_items['token'],
                                                   rest_items['user_name'],
                                                   rest_items['password'],
                                                   url,
                                                   rest_items['port'],
                                                   rest_items['hostname'],
                                                   1)

    if ret == 0:
        data = json.loads(response_data.decode('utf-8'))

        json_search(data, 'items')
        if FoundValue != 0:
            temp, FoundValue = FoundValue, 0
            for role_object in temp:
                role_dic = {'name': 'na', 'attribute': 'na',
                            'console': 'na', 'enabled': False,
                            'line_order': -1, 'role': 'na',
                            'partition': 'na'}
                for key, value in role_object.items():
                    if key == 'name':
                        role_dic['name'] = value
                    elif key == 'attribute':
                        role_dic['attribute'] = value
                    elif key == 'console':
                        role_dic['console'] = value
                    elif key == 'deny':
                        if value == 'disabled':
                            role_dic['enabled'] = True
                        if value == 'enabled':
                            role_dic['enabled'] = False
                    elif key == 'lineOrder':
                        role_dic['line_order'] = value
                    elif key == 'role':
                        role_dic['role'] = value
                    elif key == 'userPartition':
                        role_dic['partition'] = value

                return_data.append(role_dic)

    else:
        # noinspection PyUnusedLocal
        local_rc = -1

    # if len(return_data) > 0:
    if return_data:
        local_rc = 0
    else:
        local_rc = -2

    return local_rc, return_data

#            num - string
#            0   - Viprion_Chassis
#            1   - Appliance
#            2   - VE
#            3   - vCMP_Guest
#            3   - VE
#            42  - None


def hw_type_str(num):
    hw_type_strings = {
        0: 'Viprion_Chassis',
        1: 'Appliance',
        2: 'VE',
        3: 'vCMP_Guest',
        42: 'None'
    }
    return hw_type_strings.get(num, 'ERROR')


def get_vcmp_guest(rest_items):
    global FoundValue
    url = 'na'
    # noinspection PyUnusedLocal
    local_rc = 0
    guest_list = list()

    if rest_items['ip_ver'] == 4:
        url = "https://%s/mgmt/tm/vcmp/guest" % rest_items['ip-addr']
    elif rest_items['ip_ver'] == 6:
        url = "https://[%s]/mgmt/tm/vcmp/guest" % rest_items['ip-addr']

    (ret, response_data) = token_get_icontrol_conf(rest_items['log_file'],
                                                   rest_items['token'],
                                                   rest_items['user_name'],
                                                   rest_items['password'],
                                                   url,
                                                   rest_items['port'],
                                                   rest_items['hostname'],
                                                   0)
    if ret == 0:
        json_data = json.loads(response_data.decode('utf-8'))
        json_search(json_data, 'items')
        if FoundValue != 0:
            temp, FoundValue = FoundValue, 0
            for item in temp:
                guest_dic = {'allowed_slots': '0', 'assigned_slots': '0',
                             'cores_per_slot': '0', 'hostname': 'na',
                             'mgmt_gw': 'na', 'mgmt_ip': 'na',
                             'min_slots': '0', 'total_cpu_cores': '0'}
                for key, value in item.items():
                    if key == 'allowedSlots':
                        guest_dic['allowed_slots'] = str(value)
                    if key == 'assignedSlots':
                        guest_dic['assigned_slots'] = value
                    if key == 'coresPerSlot':
                        guest_dic['cores_per_slot'] = value
                    if key == 'hostname':
                        guest_dic['hostname'] = value
                    if key == 'managementGw':
                        guest_dic['mgmt_gw'] = value
                    if key == 'managementIp':
                        guest_dic['mgmt_ip'] = (value.split('/', 1))[0]
                    if key == 'minSlots':
                        guest_dic['min_slots'] = value
                    if key == 'state':
                        guest_dic['state'] = value

                if guest_dic['assigned_slots'] == '0':
                    guest_dic['total_cpu_cores'] = 0
                else:
                    guest_dic['total_cpu_cores'] = len(
                        guest_dic['assigned_slots']) * guest_dic['cores_per_slot']

                guest_list.append(guest_dic)
        else:
            local_rc = -2
    else:
        local_rc = -1

    return local_rc, guest_list


def check_for_factory_default_snmp_community(rest_items):
    global FoundValue
    url = 'na'
    # noinspection PyUnusedLocal
    local_rc = 0

    if rest_items['ip_ver'] == 4:
        url = "https://%s/mgmt/tm/sys/snmp/communities" % rest_items['ip-addr']
    elif rest_items['ip_ver'] == 6:
        url = "https://[%s]/mgmt/tm/sys/snmp/communities" % rest_items['ip-addr']

    (ret, response_data) = token_get_icontrol_conf(rest_items['log_file'],
                                                   rest_items['token'],
                                                   rest_items['user_name'],
                                                   rest_items['password'],
                                                   url,
                                                   rest_items['port'],
                                                   rest_items['hostname'],
                                                   1)

    if ret == 0:
        data = json.loads(response_data.decode('utf-8'))

        json_search(data, 'items')
        if FoundValue != 0:
            temp, FoundValue = FoundValue, 0

            for item in temp:
                for key, value in item.items():
                    if key == 'name':
                        if value == '/Common/comm-public':
                            local_rc = 1
        else:
            local_rc = -2

    else:
        local_rc = -1

    return local_rc


def get_host_name(rest_items):
    global FoundValue
    url = 'na'
    return_data = None
    # noinspection PyUnusedLocal
    local_rc = -3

    if rest_items['ip_ver'] == 4:
        url = "https://%s/mgmt/tm/sys/global-settings" % rest_items['ip-addr']
    elif rest_items['ip_ver'] == 6:
        url = "https://[%s]/mgmt/tm/sys/global-settings" % rest_items['ip-addr']

    (ret, response_data) = token_get_icontrol_conf(rest_items['log_file'],
                                                   rest_items['token'],
                                                   rest_items['user_name'],
                                                   rest_items['password'],
                                                   url,
                                                   rest_items['port'],
                                                   rest_items['hostname'],
                                                   1)

    if ret == 0:
        json_data = json.loads(response_data.decode('utf-8'))
        json_search(json_data, 'hostname')
        if FoundValue != 0:
            return_data, FoundValue = FoundValue, 0
            local_rc = 0
        else:
            local_rc = -2
    else:
        local_rc = -1

    return local_rc, return_data


def get_mgmt_ip(rest_items):
    global FoundValue
    url = 'na'
    return_data = None
    # noinspection PyUnusedLocal
    local_rc = -3

    if rest_items['ip_ver'] == 4:
        url = "https://%s/mgmt/tm/sys/management-ip" % rest_items['ip-addr']
    elif rest_items['ip_ver'] == 6:
        url = "https://[%s]/mgmt/tm/sys/management-ip" % rest_items['ip-addr']

    (ret, response_data) = token_get_icontrol_conf(rest_items['log_file'],
                                                   rest_items['token'],
                                                   rest_items['user_name'],
                                                   rest_items['password'],
                                                   url,
                                                   rest_items['port'],
                                                   rest_items['hostname'],
                                                   1)

    if ret == 0:
        data = json.loads(response_data.decode('utf-8'))
        json_search(data, 'fullPath')
        if FoundValue != 0:
            temp, FoundValue = FoundValue, 0
            temp = temp.split('/', 1)
            return_data = temp[0]
            local_rc = 0
        else:
            local_rc = -2

    else:
        local_rc = -1

    return local_rc, return_data


def get_sys_hardware(rest_items):
    global FoundValue
    url = 'na'
    chassis_id = None
    platform = None
    # noinspection PyUnusedLocal
    local_rc = -5

    if rest_items['ip_ver'] == 4:
        url = "https://%s/mgmt/tm/sys/hardware" % rest_items['ip-addr']
    elif rest_items['ip_ver'] == 6:
        url = "https://[%s]/mgmt/tm/sys/hardware" % rest_items['ip-addr']

    (ret, response_data) = token_get_icontrol_conf(
        rest_items['log_file'],
        rest_items['token'],
        rest_items['user_name'],
        rest_items['password'],
        url,
        rest_items['port'],
        rest_items['hostname'],
        1)

    # Get chassis_id
    if ret == 0:
        data = json.loads(response_data.decode('utf-8'))
        json_search(data, 'bigipChassisSerialNum')
        if FoundValue != 0:
            temp, FoundValue = FoundValue['description'], 0
            chassis_id = temp
            # noinspection PyUnusedLocal
            local_rc = 0
        else:
            # noinspection PyUnusedLocal
            local_rc = -2
    else:
        # noinspection PyUnusedLocal
        local_rc = -1

    # Get platform
    if ret == 0:
        data = json.loads(response_data.decode('utf-8'))
        json_search(data, 'platform')
        if FoundValue != 0:
            temp, FoundValue = FoundValue['description'], 0
            platform = temp
            # noinspection PyUnusedLocal
            local_rc = 0
        else:
            # noinspection PyUnusedLocal
            local_rc = -4
    else:
        # noinspection PyUnusedLocal
        local_rc = -3

    return local_rc, chassis_id, platform


def get_cluster_address(rest_items):
    global FoundValue
    url = 'na'
    local_rc = -3
    return_data = None

    if rest_items['ip_ver'] == 4:
        url = "https://%s/mgmt/tm/sys/cluster" % rest_items['ip-addr']
    elif rest_items['ip_ver'] == 6:
        url = "https://[%s]/mgmt/tm/sys/cluster" % rest_items['ip-addr']

    (ret, response_data) = token_get_icontrol_conf(
        rest_items['log_file'],
        rest_items['token'],
        rest_items['user_name'],
        rest_items['password'],
        url,
        rest_items['port'],
        rest_items['hostname'],
        1)

    if ret == 0:
        json_data = json.loads(response_data.decode('utf-8'))

        json_search(json_data, 'items')
        if FoundValue != 0:
            temp, FoundValue = FoundValue, 0
            for item in temp:
                for key, value in item.items():
                    if key == 'address':
                        local_rc = 0
                        return_data = (value.split('/', 1))[0]
        else:
            local_rc = -2

    else:
        local_rc = -1

    return local_rc, return_data


def get_viprion_addresses(rest_items, no_tcp_conn):
    global FoundValue
    url = 'na'
    local_rc = 0
    cluster_address = 'na'
    mgmt_addr_list = list()

    if rest_items['ip_ver'] == 4:
        url = "https://%s/mgmt/tm/sys/cluster" % rest_items['ip-addr']
    elif rest_items['ip_ver'] == 6:
        url = "https://[%s]/mgmt/tm/sys/cluster" % rest_items['ip-addr']

    (ret, response_data) = token_get_icontrol_conf(
        rest_items['log_file'],
        rest_items['token'],
        rest_items['user_name'],
        rest_items['password'],
        url,
        rest_items['port'],
        rest_items['hostname'],
        1)

    if ret == 0:
        json_data = json.loads(response_data.decode('utf-8'))

        json_search(json_data, 'items')
        if FoundValue != 0:
            temp, FoundValue = FoundValue, 0
            for item in temp:
                for key, value in item.items():
                    if key == 'address':
                        cluster_address = (value.split('/', 1))[0]
        else:
            local_rc = -2

        json_search(json_data, 'members')
        if FoundValue != 0:
            temp, FoundValue = FoundValue, 0
            for item in temp:
                for key, value in item.items():
                    if key == 'address':
                        if no_tcp_conn is True:
                            if ping_host(value, test_host_ip_address(value)) == 0:
                                mgmt_addr_list.append(value)
                        else:
                            if tcp_connect_service_port(value, rest_items['port']) == 0:
                                mgmt_addr_list.append(value)
        else:
            local_rc = -3
    else:
        local_rc = -1

    return local_rc, cluster_address, mgmt_addr_list


# required correct hostname

def get_cm_device(rest_items, chassis_id):
    global FoundValue
    url = 'na'
    # noinspection PyUnusedLocal
    local_rc = 0
    data = None
    return_data = 0
    vcmp_host = False

    if rest_items['ip_ver'] == 4:
        url = "https://%s/mgmt/tm/cm/device/%s" % (
            rest_items['ip-addr'], rest_items['hostname'])
    elif rest_items['ip_ver'] == 6:
        url = "https://[%s]/mgmt/tm/cm/device/%s" % (
            rest_items['ip-addr'], rest_items['hostname'])

    (ret, response_data) = token_get_icontrol_conf(rest_items['log_file'],
                                                   rest_items['token'],
                                                   rest_items['user_name'],
                                                   rest_items['password'],
                                                   url,
                                                   rest_items['port'],
                                                   rest_items['hostname'],
                                                   1)

    # CM has records for all the devices in the F5 Device Service Cluster (DSC)
    # Need to make sure the CM record matches the chassis_id.
    if ret == 0:
        data = json.loads(response_data.decode('utf-8'))
        json_search(data, 'chassisId')
        if FoundValue != 0:
            temp, FoundValue = FoundValue, 0
            if temp != chassis_id:
                # noinspection PyUnusedLocal
                local_rc = -3
        else:
            # noinspection PyUnusedLocal
            local_rc = -2
    else:
        # noinspection PyUnusedLocal
        local_rc = -1

    if local_rc == 0:
        # Get chassis_type
        json_search(data, 'chassisType')
        if FoundValue != 0:
            temp, FoundValue = FoundValue, 0
            return_data = temp
        else:
            local_rc = -4

    # Is the device a vCMP host?
    if local_rc == 0:
        json_search(data, 'activeModules')
        if FoundValue != 0:
            temp, FoundValue = FoundValue, 0
            for item in temp:
                if 'VCMP Enabled' in item:
                    vcmp_host = True

        else:
            local_rc = -5

    return local_rc, return_data, vcmp_host


def get_syslog_dest(rest_items):
    global FoundValue
    url = 'na'
    return_data = list()
    # noinspection PyUnusedLocal
    local_rc = -3

    if rest_items['ip_ver'] == 4:
        url = "https://%s/mgmt/tm/sys/syslog" % rest_items['ip-addr']
    elif rest_items['ip_ver'] == 6:
        url = "https://[%s]/mgmt/tm/sys/syslog" % rest_items['ip-addr']

    (ret, response_data) = token_get_icontrol_conf(rest_items['log_file'],
                                                   rest_items['token'],
                                                   rest_items['user_name'],
                                                   rest_items['password'],
                                                   url,
                                                   rest_items['port'],
                                                   rest_items['hostname'],
                                                   1)

    if ret == 0:
        data = json.loads(response_data.decode('utf-8'))

        json_search(data, 'remoteServers')

        if FoundValue != 0:
            temp, FoundValue = FoundValue, 0
            for item in temp:
                for key, value in item.items():
                    if key == 'host':
                        return_data.append(value)

            local_rc = 0

        else:
            local_rc = -2
    else:
        local_rc = -1

    return local_rc, return_data


def get_sys_provision(rest_items):
    global FoundValue
    url = 'na'
    return_data = list()
    mod_name = 'na'
    # noinspection PyUnusedLocal
    local_rc = 0

    if rest_items['ip_ver'] == 4:
        url = "https://%s/mgmt/tm/sys/provision" % rest_items['ip-addr']
    elif rest_items['ip_ver'] == 6:
        url = "https://[%s]/mgmt/tm/sys/provision" % rest_items['ip-addr']

    (ret, response_data) = token_get_icontrol_conf(rest_items['log_file'],
                                                   rest_items['token'],
                                                   rest_items['user_name'],
                                                   rest_items['password'],
                                                   url,
                                                   rest_items['port'],
                                                   rest_items['hostname'],
                                                   1)
    if ret == 0:
        data = json.loads(response_data.decode('utf-8'))

        json_search(data, 'items')
        if FoundValue != 0:
            temp, FoundValue = FoundValue, 0

            for item in temp:
                for key, value in item.items():
                    if key == 'name':
                        mod_name = value
                    if (key == 'level') and (value != 'none'):
                        # Initialize dictionary and set 'name' and 'level'.
                        # Then add dic to list
                        local_dic = {'name': mod_name, 'level': value}
                        return_data.append(local_dic)
        else:
            local_rc = -2

    else:
        local_rc = -1

    return local_rc, return_data


def failover_strings(num):
    failover_txt_strings = {
        0: 'Stand-Alone',
        1: 'Redundancy Active',
        2: 'Redundancy Standby',
        3: 'Offline',
    }
    return failover_txt_strings.get(num, 'ERROR')


def get_device_redundancy_state(rest_items):
    local_rc = 0
    device_type = -1
    membership = list()

    # Get all the device-groups on the device.
    (ret, device_groups) = get_device_groups(rest_items)
    if ret != 0:
        local_rc = -1

    # Get the devices's device-group membership.
    # The search is filtered. Membership in the system and
    # DSC (F5 Device Service Cluster) device-groups is not checked.
    if local_rc == 0:
        (ret, membership) = get_non_sys_device_group_membership(
            rest_items, device_groups)
        # A Stand-Alone device may not be a member of any device-group.
        if ret == 0:
            device_type = 0
        elif ret < 0:
            local_rc = -2

    # For devices with membership in at lest one device-group, test if the
    # device is a member of a device-group of type 'sync-failover'
    # that has network failover enabled.
    if (local_rc == 0) and (device_type != 0):
        ret = check_redundancy_device_groups(rest_items, membership)
        if ret == -2:
            device_type = 0
        elif ret < 0:
            # Could not check redundancy device-group
            local_rc = -3

    # Now we need to get the current network failover state of a
    # non-Stand-Alone device.
    if (local_rc == 0) and (device_type != 0):
        ret = get_network_failover_state(rest_items)
        # Redundancy Active device
        if ret == 1:
            device_type = 1
        # Redundancy Standby device
        elif ret == 2:
            device_type = 2
        # Offline device
        elif ret == 3:
            device_type = 3
        elif ret < 1:
            # Could not determine device type
            local_rc = -4

    return local_rc, device_type


def get_device_groups(rest_items):
    global FoundValue
    url = 'na'
    return_data = None
    device_groups = list()
    # noinspection PyUnusedLocal
    local_rc = 0

    # Get list of device-groups
    if rest_items['ip_ver'] == 4:
        url = "https://%s/mgmt/tm/cm/device-group" % rest_items['ip-addr']
    elif rest_items['ip_ver'] == 6:
        url = "https://[%s]/mgmt/tm/cm/device-group" % rest_items['ip-addr']

    (ret, response_data) = token_get_icontrol_conf(rest_items['log_file'],
                                                   rest_items['token'],
                                                   rest_items['user_name'],
                                                   rest_items['password'],
                                                   url,
                                                   rest_items['port'],
                                                   rest_items['hostname'],
                                                   1)

    if ret == 0:
        data = json.loads(response_data.decode('utf-8'))

        json_search(data, 'items')
        if FoundValue != 0:
            temp, FoundValue = FoundValue, 0

            for item in temp:
                for key, value in item.items():
                    if key == 'name':
                        device_groups.append(value)
            return_data = device_groups
        else:
            local_rc = -2
    else:
        local_rc = -1

    if return_data:
        # if len(return_data) < 1:
        if not return_data:
            local_rc = -4
    else:
        local_rc = -3

    return local_rc, device_groups

# Test a list of device-groups for if an one of the device-groups is of
# type 'sync-failover' and has network failover enabled.
# and has network failover enabled.
#  0: One of the device-groups is of type 'sync-failover'
#     and has network failover enabled.
#  1: One of the device-groups is of type 'sync-failover'
# -1: The HTTP get for iControl REST failed.
# -2: No device-group is not of type 'sync-failover. Default return value.


def check_redundancy_device_groups(rest_items, device_groups):
    global FoundValue
    url = 'na'
    sync_failover = False
    network_failover = False
    # noinspection PyUnusedLocal
    local_rc = -2

    for group in device_groups:

        if rest_items['ip_ver'] == 4:
            url = "https://%s/mgmt/tm/cm/device-group/%s" % (
                rest_items['ip-addr'], group)
        elif rest_items['ip_ver'] == 6:
            url = "https://[%s]/mgmt/tm/cm/device-group/%s" % (
                rest_items['ip-addr'], group)

        (ret, response_data) = token_get_icontrol_conf(rest_items['log_file'],
                                                       rest_items['token'],
                                                       rest_items['user_name'],
                                                       rest_items['password'],
                                                       url,
                                                       rest_items['port'],
                                                       rest_items['hostname'],
                                                       1)
        if ret == 0:
            data = json.loads(response_data.decode('utf-8'))
            for key, value in data.items():
                if key == 'networkFailover':
                    if value == 'enabled':
                        network_failover = True
                if key == 'type':
                    if value == 'sync-failover':
                        sync_failover = True
        else:
            local_rc = -1

        if (network_failover is True) and (sync_failover is True):
            local_rc = 0
        elif sync_failover:
            local_rc = 1

    return local_rc


# Get a list of the device-groups in which the device is a member.
# The search is filtered. Membership in the system and
# DSC (F5 Device Service Cluster) device-groups is not checked.
#  0: The device is not a member of any device group.
#  1: The device is a member of at least one device-group
# -1: The HTTP get for iControl REST failed.
# -2: Default value.
def get_non_sys_device_group_membership(rest_items, device_groups):
    global FoundValue
    url = 'na'
    return_data = list()
    # noinspection PyUnusedLocal
    local_rc = -2

    for group in device_groups:

        if group not in ['device_trust_group', 'gtm']:
            if not group.startswith('datasync'):

                if rest_items['ip_ver'] == 4:
                    url = "https://%s/mgmt/tm/cm/device-group/%s/devices" % (
                        rest_items['ip-addr'], group)
                elif rest_items['ip_ver'] == 6:
                    url = "https://[%s]/mgmt/tm/cm/device-group/%s/devices" % (
                        rest_items['ip-addr'], group)

                (ret, response_data) = token_get_icontrol_conf(rest_items['log_file'],
                                                               rest_items['token'],
                                                               rest_items['user_name'],
                                                               rest_items['password'],
                                                               url,
                                                               rest_items['port'],
                                                               rest_items['hostname'],
                                                               1)
                if ret == 0:
                    data = json.loads(response_data.decode('utf-8'))

                    json_search(data, 'items')
                    if FoundValue != 0:
                        temp, FoundValue = FoundValue, 0

                        total_member_count = 0
                        member_of_group = False
                        for item in temp:
                            for key, value in item.items():
                                if key == 'name':
                                    total_member_count += 1
                                    if rest_items['hostname'] == value:
                                        member_of_group = True
                                    # for "/Common/hostname"
                                    if '/' in value:
                                        if rest_items['hostname'] == (value.split('/', 2))[2]:
                                            member_of_group = True

                        # There needs to be more than one device in the
                        # device-group.
                        if (member_of_group is True) and (total_member_count > 1):
                            return_data.append(group)

                else:
                    # noinspection PyUnusedLocal
                    local_rc = -1

    # if len(return_data) > 0:
    if return_data:
        local_rc = 1
    else:
        local_rc = 0

    return local_rc, return_data


#  1: Active device - network failover enabled.
#  2: Standby device - network failover enabled.
#  3: Offline device - network failover enabled.
def get_network_failover_state(rest_items):
    global FoundValue
    url = 'na'
    local_rc = 0

    # Get redundant system failover state
    if rest_items['ip_ver'] == 4:
        url = "https://%s/mgmt/tm/sys/failover" % rest_items['ip-addr']
    elif rest_items['ip_ver'] == 6:
        url = "https://[%s]/mgmt/tm/sys/failover" % rest_items['ip-addr']

    (ret, response_data) = token_get_icontrol_conf(rest_items['log_file'],
                                                   rest_items['token'],
                                                   rest_items['user_name'],
                                                   rest_items['password'],
                                                   url,
                                                   rest_items['port'],
                                                   rest_items['hostname'],
                                                   1)

    if ret == 0:
        data = json.loads(response_data.decode('utf-8'))

        json_search(data, 'apiAnonymous')
        if FoundValue != 0:
            temp, FoundValue = FoundValue, 0
            if re.search('active', temp):
                local_rc = 1
            elif re.search('standby', temp):
                local_rc = 2
            elif re.search('offline', temp):
                local_rc = 3
        else:
            local_rc = -3
    else:
        local_rc = -2

    return local_rc


def get_tmos_ver(rest_items):
    global FoundValue
    url = 'na'
    return_data = None
    # noinspection PyUnusedLocal
    local_rc = -3

    if rest_items['ip_ver'] == 4:
        url = "https://%s/mgmt/tm/sys/version" % rest_items['ip-addr']
    elif rest_items['ip_ver'] == 6:
        url = "https://[%s]/mgmt/tm/sys/version" % rest_items['ip-addr']

    (ret, response_data) = token_get_icontrol_conf(rest_items['log_file'],
                                                   rest_items['token'],
                                                   rest_items['user_name'],
                                                   rest_items['password'],
                                                   url,
                                                   rest_items['port'],
                                                   rest_items['hostname'],
                                                   1)

    if ret == 0:
        data = json.loads(response_data.decode('utf-8'))
        json_search(data, 'Version')
        if FoundValue != 0:
            temp, FoundValue = FoundValue['description'], 0
            return_data = temp
            local_rc = 0
        else:
            local_rc = -2
    else:
        local_rc = -1

    return local_rc, return_data


def get_mgmt_routes(rest_items):
    global FoundValue
    url = 'na'
    def_gw_ipv4 = "127.0.0.1"
    def_gw_ipv6 = "::1"
    return_data = list()
    local_rc = 0

    if rest_items['ip_ver'] == 4:
        url = "https://%s/mgmt/tm/sys/management-route" % rest_items['ip-addr']
    elif rest_items['ip_ver'] == 6:
        url = "https://[%s]/mgmt/tm/sys/management-route" % rest_items['ip-addr']

    (ret, response_data) = token_get_icontrol_conf(rest_items['log_file'],
                                                   rest_items['token'],
                                                   rest_items['user_name'],
                                                   rest_items['password'],
                                                   url,
                                                   rest_items['port'],
                                                   rest_items['hostname'],
                                                   1)

    if ret == 0:
        data = json.loads(response_data.decode('utf-8'))

        json_search(data, 'items')
        if FoundValue != 0:
            temp, FoundValue = FoundValue, 0

            for item in temp:
                for key, value in item.items():

                    if key == 'network':

                        if value == 'default':
                            def_gw_ipv4 = item['gateway']
                        elif value == 'default-inet6':
                            def_gw_ipv6 = item['gateway']
                        else:
                            route = {'net': value, 'gw': item['gateway']}
                            return_data.append(route)

        else:
            local_rc = -2

    else:
        local_rc = -1

    return local_rc, def_gw_ipv4, def_gw_ipv6, return_data


def get_time_zone(rest_items):
    global FoundValue
    url = 'na'
    return_data = None
    # noinspection PyUnusedLocal
    local_rc = -3

    if rest_items['ip_ver'] == 4:
        url = "https://%s/mgmt/tm/sys/ntp" % rest_items['ip-addr']
    elif rest_items['ip_ver'] == 6:
        url = "https://[%s]/mgmt/tm/sys/ntp" % rest_items['ip-addr']

    (ret, response_data) = token_get_icontrol_conf(rest_items['log_file'],
                                                   rest_items['token'],
                                                   rest_items['user_name'],
                                                   rest_items['password'],
                                                   url,
                                                   rest_items['port'],
                                                   rest_items['hostname'],
                                                   1)

    if ret == 0:
        data = json.loads(response_data.decode('utf-8'))

        json_search(data, 'timezone')
        if FoundValue != 0:
            return_data, FoundValue = FoundValue, 0
            local_rc = 0

        else:
            local_rc = -2
    else:
        local_rc = -1

    return local_rc, return_data

#  1: Unix Shell
#  2: TMOS Shell
# -1: SSH Login Error
# -2: Unix Shell Error
# -3: TMOS Shell Error
# -4: Default value - It is an error
# noinspection PyUnusedLocal


def ssh_login_test(user_name, pass_word, ip_addr, port, host_name):
    local_rc = -4
    ssh_client = None
    ssh_stdin = None  # pylint: disable=W0612
    ssh_stdout = None
    ssh_stderr = None
    log_out_str = 'na'

    # paramiko.util.log_to_file("./paramiko.log")

    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(ip_addr, port=port,
                           username=user_name, password=pass_word,
                           allow_agent=False, banner_timeout=300)
    except (paramiko.AuthenticationException, paramiko.BadAuthenticationType):
        local_rc = -1

    # Default behavior on the device is to open an interactive ssh channel.
    # shell_channel = ssh_client.invoke_shell()

    if local_rc != -1:
        # Unix shell
        ssh_stdin, ssh_stdout, ssh_stderr = ssh_client.exec_command(
            'tmsh list sys global-settings hostname')

        for message in ssh_stdout:
            if isinstance(message, str):
                log_out_str = 'exit'  # In Unix Bash shell
                # Test message string for device host-name
                if re.search(host_name, message):
                    local_rc = 1

        for message in ssh_stderr:
            log_out_str = 'quit'  # In TMOS shell
            if isinstance(message, str):
                local_rc = -2

        # Logout of interactive shell_channel
        ssh_stdin, ssh_stdout, ssh_stderr = ssh_client.exec_command(
            log_out_str)

        # TMSH Shell
        if local_rc < 0:
            ssh_stdin, ssh_stdout, ssh_stderr = ssh_client.exec_command(
                "list sys global-settings hostname")

            for message in ssh_stdout:
                log_out_str = 'quit'  # In TMOS shell
                if isinstance(message, str):

                    # Test message string for device host-name
                    if re.search(host_name, message):
                        local_rc = 2

            for message in ssh_stderr:
                log_out_str = 'exit'  # In Unix Bash shell
                if isinstance(message, str):
                    if local_rc < 0:
                        local_rc = -3

        # Logout of interactive shell_channel
        ssh_stdin, ssh_stdout, ssh_stderr = ssh_client.exec_command(
            log_out_str)

    ssh_client.close()

    return local_rc


def parse_file(log_file, file_name):
    local_rc = 0
    host_ips = None
    local_list = []

    try:
        host_ips: TextIO = open(file_name, "r")
    except IOError as file_error:
        write_to_log(log_file, "Couldn't open file (%s)." % file_error)
        local_rc = -1

    if local_rc == 0:
        line = host_ips.readline()
        while line:
            # Simple test to see if a comment.
            # Lines that are a comment start with the "#" character.
            if line.startswith("#") is False:
                local_list.append(line.strip())
            line = host_ips.readline()

    return local_rc, local_list


def test_host_ip_address(ip_addr):
    local_rc = -1

    if ipv4HostRegEx.match(ip_addr):
        local_rc = 4
    elif ipv6HostRegEx.match(ip_addr):
        local_rc = 6

    return local_rc

# Using Unix (Linux) ping utility via Unix shell
# The ping utility needs to be in users shell PATH variable.


def ping_host(ip_addr, ip_ver):
    local_rc = -1

    if ip_ver == 4:
        local_rc = subprocess.call(['ping', '-nq', '-c', '5', ip_addr],
                                   stdout=open(os.devnull, 'w'),
                                   stderr=open(os.devnull, 'w'))
    elif ip_ver == 6:
        local_rc = subprocess.call(['ping6', '-nq', '-c', '5', ip_addr],
                                   stdout=open(os.devnull, 'w'),
                                   stderr=open(os.devnull, 'w'))

    return local_rc


# noinspection PyUnusedLocal
def tcp_connect_service_port(ip_addr, tcp_port):
    local_rc = -3
    ret = -1
    host_socket = None

    ip_ver = test_host_ip_address(ip_addr)

    if ip_ver == 4:
        host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    elif ip_ver == 6:
        host_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    else:
        local_rc = -1

    if local_rc != -1:

        # Set the socket connect timeout to 10 seconds
        host_socket.settimeout(10)
        ret = host_socket.connect_ex((ip_addr, tcp_port))
        host_socket.close()
        if ret == 0:
            # noinspection PyUnusedLocal
            local_rc = 0
        else:
            local_rc = -2

    return ret


def write_to_log(log_file, message):
    local_current_time = datetime.datetime.today()
    local_time_stamp = local_current_time.strftime(LOG_TIMESTAMPFORMAT)
    log_file.write("%s - %s\n" % (local_time_stamp, message))
    log_file.flush()


def get_icontrol_conf(log_file, user_name, pass_word, url, port, host_name,
                      log_error):
    return_data = None
    # noinspection PyUnusedLocal
    local_rc = -3

    urllib3.disable_warnings()

    http_pool = urllib3.PoolManager(port=port, cert_reqs='CERT_NONE')
    http_headers = urllib3.util.make_headers(
        basic_auth=user_name + ':' + pass_word,
        user_agent=programVersion)
    http_headers['Content-Type'] = 'application/json'
    http_headers['Host'] = host_name

    response = http_pool.request('GET', url, headers=http_headers)

    if (int(response.status) < 200) or (int(response.status) > 299):
        if log_error:
            write_to_log(
                log_file, 'get_icontrol_conf: ' + str(response.data))
        local_rc = -1
    else:
        return_data = response.data
        local_rc = 0

    return local_rc, return_data


def token_get_icontrol_conf(log_file, auth_token, user_name, password, url, port,
                            host_name, log_error):
    global programVersion
    return_data = None
    # noinspection PyUnusedLocal
    local_rc = -2

    urllib3.disable_warnings()

    http_pool = urllib3.PoolManager(port=port, cert_reqs='CERT_NONE')

    if auth_token is not None:
        http_headers = urllib3.util.make_headers(
            user_agent=programVersion)
        http_headers['X-F5-Auth-Token'] = auth_token
    else:
        http_headers = urllib3.util.make_headers(
            basic_auth=user_name + ':' + password)

    http_headers['Content-Type'] = 'application/json'
    http_headers['Host'] = host_name

    response = http_pool.request('GET', url, headers=http_headers)

    if (int(response.status) < 200) or (int(response.status) > 299):
        if log_error:
            write_to_log(log_file, 'token_get_icontrol_conf: ' + url + ' :' +
                         str(response.data))
        local_rc = -1
    else:
        return_data = response.data
        local_rc = 0

    return local_rc, return_data


def token_post_icontrol_conf(log_file, auth_token, user_name, password, url, port,
                             host_name, data_dic, log_error):
    global programVersion
    return_data = None
    # noinspection PyUnusedLocal
    local_rc = -2

    content = json.dumps(data_dic).encode('utf-8')

    http_pool = urllib3.PoolManager(port=port, cert_reqs='CERT_NONE')

    if auth_token is not None:
        http_headers = urllib3.util.make_headers(
            user_agent=programVersion)
        http_headers['X-F5-Auth-Token'] = auth_token
    else:
        http_headers = urllib3.util.make_headers(
            basic_auth=user_name + ':' + password,
            user_agent=programVersion)

    http_headers['Content-Type'] = 'application/json'
    http_headers['Host'] = host_name

    response = http_pool.request(
        'POST', url, body=content, headers=http_headers)

    if (int(response.status) < 200) or (int(response.status) > 299):
        if log_error:
            write_to_log(log_file, 'token_post_icontrol_conf: ' +
                         str(response.data))
        local_rc = -1
    else:
        return_data = response.data
        local_rc = 0

    return local_rc, return_data


def get_rest_auth_token(log_file, user_name, password, ip_addr, port, host_name, ip_ver):
    global FoundValue
    url = 'na'
    return_data = None
    # noinspection PyUnusedLocal
    local_rc = -2

    if ip_ver == 4:
        url = "https://%s/mgmt/shared/authn/login" % ip_addr
    elif ip_ver == 6:
        url = "https://[%s]/mgmt/shared/authn/login" % ip_addr

    data_dic = {'username': user_name, 'password': password,
                'loginProviderName': 'tmos'}

    (ret, response_data) = token_post_icontrol_conf(log_file, None, user_name, password,
                                                    url, port, host_name,
                                                    data_dic, 0)

    if ret == 0:
        data = json.loads(response_data.decode('utf-8'))

        json_search(data, 'token')
        temp, FoundValue = FoundValue, 0
        json_search(temp, 'token')
        return_data, FoundValue = FoundValue, 0
        local_rc = 0
    else:
        local_rc = -1

    return local_rc, return_data

# Recursive function with non-local exit. The found value is placed into a global
# variable.

# pylint: disable=C0123
# pylint: disable=R1705
# pylint: disable=R1710


def json_search(json_data, skey):
    global FoundValue

    if type(json_data) == str:
        json_data = json.loads(json_data)
    if type(json_data) is dict:
        for key in json_data:
            if key == skey:
                FoundValue = json_data[key]
                return
            elif type(json_data[key]) in (list, dict):
                json_search(json_data[key], skey)
    elif type(json_data) is list:
        for item in json_data:
            if type(item) in (list, dict):
                return json_search(item, skey)
    return

# https://www.codefellows.org/blog/implementing-a-singly-linked-list-in-python/


def list_insert(self, data):
    new_node = Node(data)
    new_node.set_next(self.head)
    self.head = new_node


# def list_search(self, data):
#     current = self.head
#     found = False
#     while current and found is False:
#         if current.get_data() == data:
#             found = True
#         else:
#             current = current.get_next()
#     if current is None:
#         raise ValueError("Data not in list")
#     return current
#
#
# def list_delete(self, data):
#     current = self.head
#     previous = None
#     found = False
#     while current and found is False:
#         if current.get_data() == data:
#             found = True
#         else:
#             previous = current
#             current = current.get_next()
#     if current is None:
#         raise ValueError("Data not in list")
#     if previous is None:
#         self.head = current.get_next()
#     else:
#         previous.set_next(current.get_next())
#
#
# def list_size(self):
#     current = self.head
#     count = 0
#     while current:
#         count += 1
#         current = current.get_next()
#     return count

# Run program


# Global variables
programVersion = "F5-Device-Discovery-1.2"
FoundValue = 0

# Static variables
FILENAME_TIMESTAMPFORMAT = "%d-%b-%Y_%H-%M-%S"
LOG_TIMESTAMPFORMAT = "%d-%b-%Y %H:%M:%S"

# -Regular Expressions

validIPv4HostAddr = '^(([01]?[0-9]?[0-9]|2[0-4][0-9]|2[5][0-5]).){3}' + \
    '([01]?[0-9]?[0-9]|2[0-4][0-9]|2[5][0-5])$'
ipv4HostRegEx = re.compile(validIPv4HostAddr)

validIPv6HostAddr = '^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|' + \
    '([0-9a-fA-F]{1,4}:){1,7}:|' + \
    '([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|' + \
    '([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|' + \
    '([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|' + \
    '([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|' + \
    '([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|' + \
    '[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|' + \
    ':((:[0-9a-fA-F]{1,4}){1,7}|:)|' + \
    'fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|' + \
    '::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).)' + \
    '{3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|' + \
    '([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).)' + \
    '{3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$'
ipv6HostRegEx = re.compile(validIPv6HostAddr)

# Host-names can only be comprised of "alphabet (A-Z), digits (0-9),
# and minus sign (-)". "The first character must be an alpha character".
# "The last character must not be a minus sign or period",
# [RFC952 "ASSUMPTIONS"].
# "The first character is relaxed to allow either a letter or a digit".
# "Host software MUST handle host names of up to 63 characters",
# [RFC1123 2.1].
# pylint: disable=W1401
ValidHostName = '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?' + \
    '(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
HostNameRegEx = re.compile(ValidHostName)

validtmos_ver = '^([0-9]{1,}.){2,}[0-9]{1,}'
tmos_verRegEx = re.compile(validtmos_ver)

# Run main function
main()
