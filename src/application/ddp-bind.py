#! /usr/bin/env python3


# Copyright (C) 2018 Brno University of Technology
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import sys
import os
import argparse
import subprocess
import multiprocessing
import time
import datetime
import re
import binascii
import pathlib
from os.path import exists, abspath, dirname, basename

network_class = {'Class': '02', 'Vendor': None, 'Device': None, 
                'SVendor': None, 'SDevice': None}
network_devices = [network_class]
# supported DPDK drivers
dpdk_driver = ["igb_uio"]
# devices to run
devices = {}
args = []
saved_drivers = {}

# This is roughly compatible with check_output function in subprocess module
# which is only available in python 2.7.
def check_output(args, stderr=None):
    '''Run a command and capture its output'''
    return subprocess.Popen(args, stdout=subprocess.PIPE,
                            stderr=stderr).communicate()[0]

def has_driver(dev_id):
    global devices
    '''return true if a device is assigned to a driver. False otherwise'''
    return "Driver_str" in devices[dev_id]


def get_pci_device_details(dev_id, probe_lspci):
    '''This function gets additional details for a PCI device'''
    device = {}

    if probe_lspci:
        extra_info = check_output(["lspci", "-vmmks", dev_id]).splitlines()

        # parse lspci details
        for line in extra_info:
            if len(line) == 0:
                continue
            name, value = line.decode().split("\t", 1)
            name = name.strip(":") + "_str"
            device[name] = value
    # check for a unix interface name
    device["Interface"] = ""
    for base, dirs, _ in os.walk("/sys/bus/pci/devices/%s/" % dev_id):
        if "net" in dirs:
            device["Interface"] = \
                ",".join(os.listdir(os.path.join(base, "net")))
            break
    # check if a port is used for ssh connection
    device["Ssh_if"] = False
    device["Active"] = ""

    return device

def get_device_details(devices_type):
    '''This function populates the "devices" dictionary. The keys used are
    the pci addresses (domain:bus:slot.func). The values are themselves
    dictionaries - one for each NIC.'''
    global args
    global devices
    global dpdk_driver

    # first loop through and read details for all devices
    # request machine readable format, with numeric IDs and String
    devices = args.INTERFACE
    dev = {}
    dev_lines = check_output(["lspci", "-Dvmmnnk"]).splitlines()
    for dev_line in dev_lines:
        if len(dev_line) == 0:
            if device_type_match(dev, devices_type):
                # Replace "Driver" with "Driver_str" to have consistency of
                # of dictionary key names
                if "Driver" in dev.keys():
                    dev["Driver_str"] = dev.pop("Driver")
                if "Module" in dev.keys():
                    dev["Module_str"] = dev.pop("Module")
                # use dict to make copy of dev
                devices[dev["Slot"]] = dict(dev)
            # Clear previous device's data
            dev = {}
        else:
            name, value = dev_line.decode().split("\t", 1)
            value_list = value.rsplit(' ', 1)
            if len(value_list) > 1:
                # String stored in <name>_str
                dev[name.rstrip(":") + '_str'] = value_list[0]
            # Numeric IDs
            dev[name.rstrip(":")] = value_list[len(value_list) - 1] \
                .rstrip("]").lstrip("[")

    if devices_type == network_devices:
        # check what is the interface if any for an ssh connection if
        # any to this host, so we can mark it later.
        ssh_if = []
        route = check_output(["ip", "-o", "route"])
        # filter out all lines for 169.254 routes
        route = "\n".join(filter(lambda ln: not ln.startswith("169.254"),
                             route.decode().splitlines()))
        rt_info = route.split()
        for i in range(len(rt_info) - 1):
            if rt_info[i] == "dev":
                ssh_if.append(rt_info[i+1])

    # based on the basic info, get extended text details
    for d in devices.keys():
        if not device_type_match(devices[d], devices_type):
            continue

        # get additional info and add it to existing data
        devices[d] = devices[d].copy()
        # No need to probe lspci
        devices[d].update(get_pci_device_details(d, False).items())

        if devices_type == network_devices:
            for _if in ssh_if:
                if _if in devices[d]["Interface"].split(","):
                    devices[d]["Ssh_if"] = True
                    devices[d]["Active"] = "*Active*"
                    break

        # add igb_uio to list of supporting modules if needed
        if "Module_str" in devices[d]:
            for driver in dpdk_driver:
                if driver not in devices[d]["Module_str"]:
                    devices[d]["Module_str"] = \
                        devices[d]["Module_str"] + ",%s" % driver
        else:
            devices[d]["Module_str"] = ",".join(dpdk_driver)

        # make sure the driver and module strings do not have any duplicates
        if has_driver(d):
            modules = devices[d]["Module_str"].split(",")
            if devices[d]["Driver_str"] in modules:
                modules.remove(devices[d]["Driver_str"])
                devices[d]["Module_str"] = ",".join(modules)


def device_type_match(dev, devices_type):
    '''Match type of the given device'''
    for i in range(len(devices_type)):
        param_count = len(
            [x for x in devices_type[i].values() if x is not None])
        match_count = 0
        if dev["Class"][0:2] == devices_type[i]["Class"]:
            match_count = match_count + 1
            for key in devices_type[i].keys():
                if key != 'Class' and devices_type[i][key]:
                    value_list = devices_type[i][key].split(',')
                    for value in value_list:
                        if value.strip(' ') == dev[key]:
                            match_count = match_count + 1
            # count must be the number of non None parameters to match
            if match_count == param_count:
                return True
    return False

def dev_id_from_dev_name(dev_name):
    '''Get PCI ID from linux interface name'''
    if dev_name in devices:
        return dev_name
    elif "0000:" + dev_name in devices:
        return "0000:" + dev_name
    else:
        for d in devices.keys():
            if dev_name in devices[d]["Interface"].split(","):
                return devices[d]["Slot"]

    print("Unknown device: %s. Please specify device in \"bus:slot.func\" format" % dev_name)
    sys.exit(1)

def bind_one(dev, driver):
    '''Bind the device given by "dev" to the driver "driver". If the device
    is already bound to a different driver, it will be unbound first'''
    global saved_drivers
    device = devices[dev]
    saved_drivers[dev] = None

    # prevent disconnection of our ssh session
    if device["Ssh_if"]:
        print("Routing table indicates that interface %s is active. Not modifying" % (dev))
        return

    # unbind any existing drivers we don't want and save them for furure rebind
    if has_driver(dev):
        if device["Driver_str"] == driver:
            saved_drivers[dev] = device["Driver_str"]
            print("%s already bound to driver %s, skipping\n" % (dev, driver))
            return
        else:
            saved_drivers[dev] = device["Driver_str"]
            unbind_one(dev)
            device["Driver_str"] = driver

    # For kernels >= 3.15 driver_override can be used to specify the driver
    # for a device rather than relying on the driver to provide a positive
    # match of the device.  The existing process of looking up
    # the vendor and device ID, adding them to the driver new_id,
    # will erroneously bind other devices too which has the additional burden
    # of unbinding those devices
    filename = "/sys/bus/pci/devices/%s/driver_override" % dev
    if os.path.exists(filename):
        try:
            f = open(filename, "w")
        except:
            print("Error: bind failed for %s - Cannot open %s" % (dev, filename))
            return
        try:
            f.write("%s" % driver)
            f.close
        except:
            print("Error: bind failed for %s - Cannot write "
                    "driver %s to PCI ID" % (dev, driver))
            return
    # For kernels < 3.15 use new_id to add PCI id's to the driver
    else:
        filename = "/sys/bus/pci/drivers/%s/new_id" % driver
        try:
            f = open(filename, "w")
        except:
            print("Error: bind failed for %s - Cannot open %s" % (dev, filename))
            return
        try:
            f.write("%04x %04x" % (int(device["Vendor"], 16), int(device["Device"], 16)))
            f.close()
        except:
            print("Error: bind failed for %s - Cannot write new PCI ID to "
                    "driver %s" % (dev, driver))
            return

    # do the bind by writing to /sys
    filename = "/sys/bus/pci/drivers/%s/bind" % driver
    try:
        f = open(filename, "a")
    except:
        print("Error: bind failed for %s - Cannot open %s"
                % (dev, filename))
        if saved_drivers[dev] is not None:
            bind_one(dev, saved_drivers[dev])
        return

    try:
        f.write(dev)
        f.close()
    except:
        # for some reason, closing dev_id after adding a new PCI ID to new_id
        # results in IOError. however, if the device was successfully bound,
        # we don't care for any errors and can safely ignore IOError
        tmp = get_pci_device_details(dev, True)
        if "Driver_str" in tmp and tmp["Driver_str"] == driver:
            return
        print("Error: bind failed for %s - Cannot bind to driver %s"
                % (dev, driver))
        if saved_drivers[dev] is not None:
            bind_one(dev, saved_drivers[dev])
        return

    # For kernels > 3.15 driver_override is used to bind a device to a driver.
    # Before unbinding it, overwrite driver_override with empty string so that
    # the device can be bound to any other driver
    filename = "/sys/bus/pci/devices/%s/driver_override" % dev
    if os.path.exists(filename):
        try:
            f = open(filename, "w")
        except:
            print("Error: unbind failed for %s - Cannot open %s"
                    % (dev, filename))
            sys.exit(1)

        try:
            f.write("\00")
            f.close()
        except:
            print("Error: unbind failed for %s - Cannot open %s"
                    % (dev, filename))
            sys.exit(1)

def unbind_one(dev):
    '''Unbind the device identified by "dev" from its current driver'''
    device = devices[dev]
    if not has_driver(dev):
        print("%s %s %s is not currently managed by any driver\n" 
                % (device["Slot"], device["Device_str"], device["Interface"]))
        return

    if device["Ssh_if"]:
        print("Routing table indicates that interface %s is active. "
                "Skipping unbind" % dev)
        return

    filename = "/sys/bus/pci/drivers/%s/unbind" % device["Driver_str"]
    try:
        f = open(filename, "a")
    except:
        print("unbind failed")
        print("Error: unbind failed for %s - Cannot open %s" 
                % (dev, filename))
        sys.exit(1)
    f.write(dev)
    f.close()

def bind_devices(dev_list, driver):
    '''Bind devices given in "dev_list" to DPDK driver igb_uio'''
    global devices

    devs = []
    #dev_list = map(dev_id_from_dev_name, dev_list)
    for dev in dev_list:
        devs.append(dev_id_from_dev_name(dev))

    for d in devs:
        bind_one(d, driver)

    if not os.path.exists("/sys/bus/pci/devices/%s/driver_override" % d):
        for d in devices.keys():
            if "Driver_str" in devices[d] or d in dev_list:
                continue

            devices[d] = dict(devices[d].items() + get_pci_device_details(d, True).items())

            if "Driver_str" in devices[d]:
                unbind_one(d)

def unbind_devices(dev_list):
    '''Bind devices given in "dev_list" from DPDK driver to their original drivers'''
    global devices

    devs = []
    for dev in dev_list:
        devs.append(dev_id_from_dev_name(dev))

    for d in devs:
        bind_one(d, saved_drivers[d])

    if not os.path.exists("/sys/bus/pci/devices/%s/driver_override" % d):
        for d in devices.keys():
            if "Driver_str" in devices[d] or d in dev_list:
                continue

            devices[d] = dict(devices[d].items() + get_pci_device_details(d, True).items())

            if "Driver_str" in devices[d]:
                unbind_one(d)

def run_command(args):
    '''Run a command and capture its output'''
    proc = subprocess.Popen(args, shell=True)
    
    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.wait()
        pass
    except:
        proc.kill()
        proc.wait()
        if args.INTERFACE:
            unbind_devices(args)
        raise

def run_app():
    global args
    pcaps = ""
    interfaces = ""
    raw_pcap = ""
    version = ""

    path = str(pathlib.Path(sys.argv[0]).parent.absolute() / "dp-dpdk")

    if args.PCAP:
        for pcap in args.PCAP:
            pcaps += " -p \"" + pcap + "\""

    if args.INTERFACE:
        for iface in args.INTERFACE:
            interfaces += " -i " + iface

    if args.r:
        raw_pcap = " -r"

    command = "\"" + path + "\"" + pcaps + interfaces + raw_pcap + version
    run_command(command)

def check_drivers():
    '''Checks that igb_uio is loaded'''
    global dpdk_driver

    drivers = [{"Name": driver, "Found": False} for driver in dpdk_driver]

    try:
        sysfs_path = '/sys/module/'
        sysfs_drivers = [os.path.join(sysfs_path, o) for o in os.listdir(sysfs_path)
                            if os.path.isdir(os.path.join(sysfs_path, o))]

        sysfs_drivers = [a.split('/')[-1] for a in sysfs_drivers]

        sysfs_drivers = [a if a != 'vfio_pci' else 'vfio-pci' for a in sysfs_drivers]

        for driver in drivers:
            if driver["Name"] in sysfs_drivers:
                driver["Found"] = True

    except:
        pass

    if True not in [driver["Found"] for driver in drivers]:
        print("Error - no supported DPDK drivers are loaded")
        sys.exit(1)

    dpdk_driver = [driver["Name"] for driver in drivers if driver["Found"]]

def parse_args():
    '''Parse script's arguments'''
    global args

    parser = argparse.ArgumentParser()
    parser.add_argument("-p", action="append", dest="PCAP", help="indicates PCAPs as input interfaces")
    parser.add_argument("-i", action="append", dest="INTERFACE", help="interface PCI ID e.g. 00:1f.6")
    parser.add_argument("-r", action="store_true", help="indicates RAW PCAPs as input. Can't be used together with -i parameter.")
    args = parser.parse_args()

def main():
    '''program main function'''
    parse_args()
    if args.INTERFACE and not args.g:
        check_drivers()
        get_device_details(network_devices)
        bind_devices(args, dpdk_driver[0])
    run_app()
    if args.INTERFACE and not args.g:
        unbind_devices(args)

if __name__ == "__main__":
    main()
