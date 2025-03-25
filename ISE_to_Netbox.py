#!/usr/bin/env python3

import os
import sys
import logging
import argparse
import requests
import urllib3
from requests.auth import HTTPBasicAuth
from pynetbox import api
from pynetbox.core.query import RequestError
import asyncio
from pysnmp.hlapi.v3arch.asyncio import *
import time
import re
from tqdm import tqdm
import datetime

def sanitize_slug(text):
    """
    Sanitize a string to create a valid Netbox slug
    - Convert to lowercase
    - Replace spaces with hyphens
    - Remove any characters that aren't letters, numbers, underscores, or hyphens
    """
    # Convert to lowercase and replace spaces with hyphens
    slug = text.lower().replace(" ", "-")
    # Remove any characters that aren't allowed
    slug = re.sub(r'[^a-z0-9_-]', '', slug)
    # Ensure slug isn't empty and doesn't start/end with hyphens
    slug = slug.strip('-')
    if not slug:
        slug = "site"  # Default if nothing valid remains
    return slug

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# SNMP OIDs for Cisco devices
SNMP_OIDS = {
    'sysDescr': '1.3.6.1.2.1.1.1.0',           # System description
    'sysName': '1.3.6.1.2.1.1.5.0',            # System name
    'sysLocation': '1.3.6.1.2.1.1.6.0',        # System location
    'sysContact': '1.3.6.1.2.1.1.4.0',         # System contact
    'sysUpTime': '1.3.6.1.2.1.1.3.0',          # System uptime
    'ifNumber': '1.3.6.1.2.1.2.1.0',           # Number of interfaces
    'ciscoModel': '1.3.6.1.2.1.47.1.1.1.1.13.1', # Cisco model number
    'ciscoSerial': '1.3.6.1.2.1.47.1.1.1.1.11.1', # Cisco serial number
    'ciscoIOS': '1.3.6.1.2.1.1.1.0',           # Cisco IOS version (parsed from sysDescr)
}

def truncate_name(name, max_length=64):
    """
    Truncate a name by:
    1. Removing everything after and including the first decimal point
    2. Ensuring the result doesn't exceed max_length characters
    """
    # First, remove everything after and including the first decimal point
    if '.' in name:
        name = name.split('.')[0]
        logger.debug(f"Removed decimal portion, new name: {name}")
    
    # Then ensure it doesn't exceed max_length
    if len(name) > max_length:
        logger.warning(f"Name '{name}' exceeds {max_length} characters, truncating")
        name = name[:max_length]
    
    return name

def truncate_description(description, max_length=200):
    """
    Truncate a description to ensure it doesn't exceed max_length characters
    """
    if len(description) > max_length:
        logger.warning(f"Description exceeds {max_length} characters, truncating")
        return description[:max_length-3] + "..."
    return description

def get_ise_devices(ise_url, username, password, verify_ssl=False):
    """Get all network devices from Cisco ISE"""
    logger.info("Getting network devices from Cisco ISE")
    
    all_devices = []
    page = 1
    size = 100  # Number of devices per page
    
    # Initial request to get first page of devices
    url = f"{ise_url}/ers/config/networkdevice?size={size}&page={page}"
    
    while url:
        logger.info(f"Fetching page {page} of network devices")
        
        response = requests.get(
            url,
            auth=HTTPBasicAuth(username, password),
            headers={
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            verify=verify_ssl
        )
        
        if response.status_code != 200:
            logger.error(f"Error fetching devices: {response.status_code} - {response.text}")
            raise Exception(f"Failed to get devices from ISE: {response.status_code}")
        
        data = response.json()
        resources = data.get('SearchResult', {}).get('resources', [])
        
        # Get detailed information for each device
        for resource in resources:
            device_id = resource.get('id')
            device_detail = get_ise_device_detail(ise_url, device_id, username, password, verify_ssl)
            all_devices.append(device_detail)
        
        # Check if there's a next page
        next_page = data.get('SearchResult', {}).get('nextPage', {}).get('href')
        if next_page:
            url = next_page
            page += 1
        else:
            url = None
    
    logger.info(f"Found {len(all_devices)} network devices in ISE")
    return all_devices

def find_site_by_name(nb, site_name):
    """Find a site in Netbox by name (exact or partial match)"""
    try:
        # Try exact match first
        site = nb.dcim.sites.get(name=site_name)
        if site:
            logger.info(f"Found exact site match: {site_name}")
            return site
            
        # Try case-insensitive search
        sites = nb.dcim.sites.filter(name__ic=site_name)
        if sites and len(sites) > 0:
            logger.info(f"Found site by partial match: {sites[0].name}")
            return sites[0]
            
        return None
    except Exception as e:
        logger.debug(f"Error searching for site {site_name}: {str(e)}")
        return None

def get_ise_device_detail(ise_url, device_id, username, password, verify_ssl=False):
    """Get detailed information for a specific network device"""
    url = f"{ise_url}/ers/config/networkdevice/{device_id}"
    
    response = requests.get(
        url,
        auth=HTTPBasicAuth(username, password),
        headers={
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        verify=verify_ssl
    )
    
    if response.status_code != 200:
        logger.error(f"Error fetching device detail: {response.status_code} - {response.text}")
        raise Exception(f"Failed to get device detail from ISE: {response.status_code}")
    
    return response.json().get('NetworkDevice', {})

def get_ise_device_groups(ise_url, username, password, verify_ssl=False):
    """Get all network device groups from Cisco ISE"""
    logger.info("Getting network device groups from Cisco ISE")
    
    all_groups = []
    page = 1
    size = 100  # Number of groups per page
    
    # Initial request to get first page of device groups
    url = f"{ise_url}/ers/config/networkdevicegroup?size={size}&page={page}"
    
    while url:
        logger.info(f"Fetching page {page} of network device groups")
        
        response = requests.get(
            url,
            auth=HTTPBasicAuth(username, password),
            headers={
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            verify=verify_ssl
        )
        
        if response.status_code != 200:
            logger.error(f"Error fetching device groups: {response.status_code} - {response.text}")
            raise Exception(f"Failed to get device groups from ISE: {response.status_code}")
        
        data = response.json()
        resources = data.get('SearchResult', {}).get('resources', [])
        all_groups.extend(resources)
        
        # Check if there's a next page
        next_page = data.get('SearchResult', {}).get('nextPage', {}).get('href')
        if next_page:
            url = next_page
            page += 1
        else:
            url = None
    
    logger.info(f"Found {len(all_groups)} network device groups in ISE")
    return all_groups

async def get_snmp_value(engine, ip_address, snmp_user, auth_key, priv_key, oid_tuple, oid_name):
    """Get a single SNMP value"""
    try:
        oid, mib, instance = oid_tuple
        
        # If MIB and instance are provided, use them, otherwise use the OID directly
        if mib and instance is not None:
            obj_identity = ObjectIdentity(mib, oid, instance)
        else:
            obj_identity = ObjectIdentity(oid)
            
        # Create SNMP GET command
        iterator = await get_cmd(
            engine,
            UsmUserData(
                snmp_user,
                authKey=auth_key,
                privKey=priv_key,
                authProtocol=usmHMACSHAAuthProtocol,
                privProtocol=usmAesCfb128Protocol
            ),
            await UdpTransportTarget.create((ip_address, 161), timeout=1, retries=1),
            ContextData(),
            ObjectType(obj_identity)
        )
        
        error_indication, error_status, error_index, var_binds = iterator
        
        # Check for errors
        if error_indication:
            logger.warning(f"Error getting SNMP data for {ip_address} ({oid_name}): {error_indication}")
            return None
        elif error_status:
            logger.warning(f"Error getting SNMP data for {ip_address} ({oid_name}): {error_status.prettyPrint()} at {var_binds[int(error_index) - 1][0] if error_index else '?'}")
            return None
        
        # Get the value
        for var_bind in var_binds:
            # Get the raw value
            value = var_bind[1]
            
            # Check if it's an OctetString and decode it properly
            if hasattr(value, 'asOctets'):
                try:
                    # Try to decode as ASCII/UTF-8
                    decoded_value = value.asOctets().decode('utf-8', errors='replace')
                    logger.debug(f"Got SNMP data for {ip_address} - {oid_name}: {decoded_value}")
                    return decoded_value
                except Exception as e:
                    logger.debug(f"Failed to decode OctetString for {oid_name}: {e}")
            
            # Fall back to pretty print for other types
            pretty_value = value.prettyPrint()
            logger.debug(f"Got SNMP data for {ip_address} - {oid_name}: {pretty_value}")
            return pretty_value
            
    except Exception as e:
        logger.warning(f"Error getting SNMP data for {ip_address} ({oid_name}): {str(e)}")
        return None

async def get_snmp_data_async(ip_address, snmp_user, auth_key, priv_key):
    """Get device information via SNMPv3 asynchronously"""
    logger.info(f"Getting SNMP data for device at {ip_address}")
    
    # Set overall timeout for the entire SNMP data collection process
    try:
        # Use asyncio.wait_for to put a hard timeout on the entire operation
        return await asyncio.wait_for(get_snmp_data_async_impl(ip_address, snmp_user, auth_key, priv_key), timeout=15.0)
    except asyncio.TimeoutError:
        logger.warning(f"SNMP collection timed out after 15 seconds for {ip_address}")
        return {}  # Return empty dict on timeout
    except Exception as e:
        logger.error(f"Error in SNMP collection for {ip_address}: {str(e)}")
        return {}

async def get_snmp_data_async_impl(ip_address, snmp_user, auth_key, priv_key):
    """Get device information via SNMPv3 asynchronously"""
    logger.info(f"Getting SNMP data for device at {ip_address}")
    
    # Update SNMP_OIDS to match the format in testsnmp.py
    snmp_oids = {
        # Base
        'sysDescr': (SNMP_OIDS['sysDescr'], None, None),
        'sysName': (SNMP_OIDS['sysName'], None, None),
        'sysLocation': (SNMP_OIDS['sysLocation'], None, None),
        'sysContact': (SNMP_OIDS['sysContact'], None, None),
        'sysUpTime': (SNMP_OIDS['sysUpTime'], None, None),
        'ifNumber': (SNMP_OIDS['ifNumber'], None, None),
        'ciscoModel': (SNMP_OIDS['ciscoModel'], None, None),
        'ciscoSerial': (SNMP_OIDS['ciscoSerial'], None, None),
        'ciscoIOS': (SNMP_OIDS['ciscoIOS'], None, None),
        
        # Physical specifications
        'entPhysicalModelName': (SNMP_OIDS['entPhysicalModelName'], None, None),
        'entPhysicalHardwareRev': (SNMP_OIDS['entPhysicalHardwareRev'], None, None),
        'entPhysicalMfgName': (SNMP_OIDS['entPhysicalMfgName'], None, None),
        'entPhysicalHeight': (SNMP_OIDS['entPhysicalHeight'], None, None),
        
        # Power and environment
        'cefcFRUPowerAdminStatus': (SNMP_OIDS['cefcFRUPowerAdminStatus'], None, None),
        'ciscoEnvMonTemperatureStatusDescr': (SNMP_OIDS['ciscoEnvMonTemperatureStatusDescr'], None, None),
        
        # Memory and CPU
        'ciscoMemoryPoolName': (SNMP_OIDS['ciscoMemoryPoolName'], None, None),
        'ciscoMemoryPoolUsed': (SNMP_OIDS['ciscoMemoryPoolUsed'], None, None),
        'ciscoMemoryPoolFree': (SNMP_OIDS['ciscoMemoryPoolFree'], None, None),
        
        # Interface details
        'ifType': (SNMP_OIDS['ifType'], None, None),
        'ifHighSpeed': (SNMP_OIDS['ifHighSpeed'], None, None),
    }
    
    snmp_data = {}
    engine = SnmpEngine()
    
    try:
        # Create tasks for each OID
        tasks = []
        for oid_name, oid_tuple in snmp_oids.items():
            # Add a small delay between requests to avoid overwhelming the device
            await asyncio.sleep(0.2)
            tasks.append(get_snmp_value(engine, ip_address, snmp_user, auth_key, priv_key, oid_tuple, oid_name))
        
        # Wait for all tasks to complete
        results = await asyncio.gather(*tasks)
        
        # Process results
        for oid_name, result in zip(snmp_oids.keys(), results):
            if result is not None:
                snmp_data[oid_name] = result
        
        # Parse IOS version from sysDescr if available
        if 'sysDescr' in snmp_data:
            desc = snmp_data['sysDescr']
            if 'Version' in desc:
                try:
                    ios_version = desc.split('Version')[1].split(',')[0].strip()
                    snmp_data['ciscoIOS'] = ios_version
                except Exception as e:
                    logger.debug(f"Failed to parse IOS version: {e}")
            
        logger.info(f"Retrieved {len(snmp_data)} SNMP values for {ip_address}")
        
    except Exception as e:
        logger.error(f"Failed to get SNMP data for {ip_address}: {str(e)}")
    
    return snmp_data

def get_snmp_data(ip_address, snmp_user, auth_key, priv_key):
    """Get device information via SNMPv3 (wrapper for async function)"""
    return asyncio.run(get_snmp_data_async(ip_address, snmp_user, auth_key, priv_key))

def parse_device_type(device_groups):
    """Parse device type from device groups"""
    device_type = "Unknown"
    
    for group in device_groups:
        if group.startswith("Device Type#"):
            parts = group.split('#')
            if len(parts) > 2:
                # Get the last part of the device type hierarchy
                device_type = parts[-1]
    
    return device_type

def parse_location(device_groups):
    """Parse location from device groups"""
    location = "Unknown"
    
    for group in device_groups:
        if group.startswith("Location#"):
            parts = group.split('#')
            if len(parts) > 2:
                # Get the last part of the location hierarchy
                location = parts[-1]
    
    return location

def get_or_create_tag(nb, tag_name, tag_slug, tag_description):
    """Get or create a tag in Netbox"""
    # Try to find the tag first
    try:
        tag = nb.extras.tags.get(slug=tag_slug)
        if tag:
            logger.info(f"Found existing tag: {tag_slug}")
            return tag
    except Exception as e:
        logger.debug(f"Error getting tag {tag_slug}: {str(e)}")
    
    # Create the tag if it doesn't exist
    logger.info(f"Creating new tag: {tag_slug}")
    return nb.extras.tags.create(
        name=tag_name,
        slug=tag_slug,
        description=tag_description
    )

def get_or_create_device_type(nb, model, manufacturer_name, tags):
    """Get or create a device type in Netbox"""
    try:
        device_type = nb.dcim.device_types.get(model=model)
        if device_type:
            return device_type
    except Exception as e:
        logger.debug(f"Error getting device type {model}: {str(e)}")
    
    # Get or create manufacturer
    try:
        manufacturer = nb.dcim.manufacturers.get(name=manufacturer_name)
        if not manufacturer:
            manufacturer = nb.dcim.manufacturers.create(
                name=manufacturer_name,
                slug=sanitize_slug(manufacturer_name),
                description=f'Created by ISE sync script'
            )
        manufacturer_id = manufacturer.id
    except Exception as e:
        logger.debug(f"Error getting manufacturer {manufacturer_name}: {str(e)}")
        manufacturer = nb.dcim.manufacturers.create(
            name=manufacturer_name,
            slug=sanitize_slug(manufacturer_name),
            description=f'Created by ISE sync script'
        )
        manufacturer_id = manufacturer.id
    
    # Create device type with a slug based on the model name
    model_slug = model.lower().replace(" ", "-")
    return nb.dcim.device_types.create(
        model=model,
        manufacturer=manufacturer_id,
        slug=model_slug,
        tags=tags
    )

def get_or_create_device_role(nb, name, tags):
    """Get or create a device role in Netbox"""
    try:
        role = nb.dcim.device_roles.get(name=name)
        if role:
            return role
    except Exception as e:
        logger.debug(f"Error getting device role {name}: {str(e)}")
    
    return nb.dcim.device_roles.create(
        name=name,
        slug=sanitize_slug(name),
        vm_role=False,
        tags=tags
    )

def get_or_create_site(nb, name, description, tags):
    """Get or create a site in Netbox"""
    try:
        site = nb.dcim.sites.get(name=name)
        if site:
            return site
    except Exception as e:
        logger.debug(f"Error getting site {name}: {str(e)}")
    
    return nb.dcim.sites.create(
        name=name,
        status='active',
        slug=sanitize_slug(name),
        description=description,
        tags=tags
    )

def get_or_create_ip_address(nb, ip_address, mask, description, tags, interface_id=None):
    """Get or create an IP address in Netbox"""
    cidr = f"{ip_address}/{mask}"
    
    try:
        ip = nb.ipam.ip_addresses.get(address=cidr)
        if ip:
            logger.info(f"Found existing IP address: {cidr}")
            
            # Update interface assignment if needed
            if interface_id and (ip.assigned_object_id != interface_id or ip.assigned_object_type != 'dcim.interface'):
                ip.assigned_object_id = interface_id
                ip.assigned_object_type = 'dcim.interface'
                ip.save()
                logger.info(f"Updated interface assignment for IP: {cidr}")
                
            return ip
    except Exception as e:
        logger.debug(f"Error getting IP address {cidr}: {str(e)}")
    
    # Create new IP address
    ip_data = {
        'address': cidr,
        'description': description,
        'status': 'active',
        'tags': tags
    }
    
    if interface_id:
        ip_data['assigned_object_type'] = 'dcim.interface'
        ip_data['assigned_object_id'] = interface_id
    
    logger.info(f"Creating new IP address: {cidr}")
    return nb.ipam.ip_addresses.create(**ip_data)

def remove_stale_devices(nb, ise_devices):
    """Remove devices from Netbox that no longer exist in ISE"""
    logger.info("Checking for devices in Netbox that no longer exist in ISE")
    
    # Get all devices in Netbox with the ise-sync tag
    try:
        ise_tag = nb.extras.tags.get(slug="ise-sync")
        if not ise_tag:
            logger.warning("ISE sync tag not found in Netbox, skipping stale device removal")
            return
            
        netbox_devices = nb.dcim.devices.filter(tag="ise-sync")
        logger.info(f"Found {len(netbox_devices)} devices in Netbox with ISE sync tag")
        
        # Create a set of ISE device names for quick lookup
        ise_device_names = {device.get('name') for device in ise_devices}
        
        # Check each Netbox device
        removed_count = 0
        for nb_device in netbox_devices:
            # Check if the device name exists in the ISE device list
            if nb_device.name not in ise_device_names:
                logger.info(f"Device {nb_device.name} no longer exists in ISE, removing from Netbox")
                nb_device.delete()
                removed_count += 1
        
        logger.info(f"Removed {removed_count} stale devices from Netbox")
        
    except Exception as e:
        logger.error(f"Error removing stale devices: {str(e)}")

def sync_to_netbox(ise_devices, netbox_url, netbox_token, snmp_user, auth_key, priv_key):
    """Sync ISE network devices to Netbox"""
    logger.info(f"Syncing data to Netbox at {netbox_url}")
    nb = api(netbox_url, token=netbox_token)
    session = requests.Session()
    session.verify = False
    nb.http_session = session
    
    # Create a tag for ISE-synced objects
    ise_tag = get_or_create_tag(
        nb,
        tag_name="ise-sync",
        tag_slug="ise-sync",
        tag_description="Synced from Cisco ISE"
    )
    
    # Process each device with progress reporting
    logger.info(f"Starting to process {len(ise_devices)} devices from ISE")
    for i, device in enumerate(tqdm(ise_devices, desc="Processing devices")):
        # Print progress every few devices to keep the agent alive
        if i % 5 == 0:
            print(f"[{datetime.datetime.now()}] Processing device {i+1}/{len(ise_devices)}: {device.get('name', 'unknown')}")
        device_name = device.get('name')
        device_id = device.get('id')
        device_description = device.get('description', '')
        device_groups = device.get('NetworkDeviceGroupList', [])
        
        # Parse device type and location from device groups
        device_type_name = parse_device_type(device_groups)
        location_name = parse_location(device_groups)
        
        # Get IP addresses for the device
        ip_list = device.get('NetworkDeviceIPList', [])
        primary_ip = None
        if ip_list and len(ip_list) > 0:
            primary_ip = ip_list[0].get('ipaddress')
        
        # Get additional device info via SNMP if we have an IP
        snmp_data = {}
        model = device_type_name
        manufacturer_name = 'Cisco'
        serial = device_id  # Default to ISE ID
        
        if primary_ip:
            snmp_data = get_snmp_data(primary_ip, snmp_user, auth_key, priv_key)
            
            # Update device information based on SNMP data
            if 'ciscoModel' in snmp_data and snmp_data['ciscoModel'] != '':
                model = snmp_data['ciscoModel']
            
            if 'ciscoSerial' in snmp_data and snmp_data['ciscoSerial'] != '':
                serial = snmp_data['ciscoSerial']
            
            # Use SNMP location if available
            if 'sysLocation' in snmp_data and snmp_data['sysLocation'] != '':
                location_name = snmp_data['sysLocation']
            
            # Build description with potential SNMP data
            full_description = device_description

            if 'sysDescr' in snmp_data:
                full_description += f"\n\nSystem Description: {snmp_data['sysDescr']}"

            if 'ciscoIOS' in snmp_data:
                full_description += f"\nIOS Version: {snmp_data['ciscoIOS']}"

            # Ensure description doesn't exceed Netbox's limit
            device_description = truncate_description(full_description)
        
        # Create or get device type
        device_type = get_or_create_device_type(
            nb,
            model=model,
            manufacturer_name=manufacturer_name,
            tags=[ise_tag.id]
        )
        
        # Create or get device role
        device_role = get_or_create_device_role(
            nb,
            name=device_type_name,
            tags=[ise_tag.id]
        )
        
        # Try to find an existing site that matches the location_name
        site = find_site_by_name(nb, location_name)
        
        # Create site if no match found
        if not site:
            site = get_or_create_site(
                nb,
                name=location_name,
                description=f"Location: {location_name}",
                tags=[ise_tag.id]
            )
            logger.info(f"Created new site: {location_name}")
        else:
            logger.info(f"Using existing site: {site.name} for location: {location_name}")
        
        # Truncate device name if needed
        device_name = truncate_name(device_name)
        
        # Try to get existing device
        try:
            nb_device = nb.dcim.devices.get(name=device_name, site_id=site.id)
            if nb_device:
                logger.info(f"Found existing device: {device_name}")
                
                # Update device with new information
                update_data = {
                    'device_type': device_type.id,
                    'role': device_role.id,
                    'site': site.id,
                    'serial': serial,
                    'description': device_description
                }
                
                for key, value in update_data.items():
                    setattr(nb_device, key, value)
                
                nb_device.save()
                logger.info(f"Updated device: {device_name}")
            else:
                # Create new device
                nb_device = nb.dcim.devices.create(
                    name=device_name,
                    device_type=device_type.id,
                    role=device_role.id,
                    site=site.id,
                    status='active',
                    tags=[ise_tag.id],
                    serial=serial,
                    description=truncate_description(device_description)
                )
                logger.info(f"Created new device: {device_name}")
        except RequestError as e:
            # Handle the case where device name already exists in the site
            if "Device name must be unique per site" in str(e):
                # Make the name unique by appending a suffix
                suffix = 1
                while True:
                    unique_name = f"{device_name}-{suffix}"
                    try:
                        # Check if this name is available
                        if len(unique_name) > 64:
                            # Truncate again if needed
                            unique_name = f"{device_name[:60]}-{suffix}"
                        
                        nb_device = nb.dcim.devices.create(
                            name=unique_name,
                            device_type=device_type.id,
                            role=device_role.id,
                            site=site.id,
                            status='active',
                            tags=[ise_tag.id],
                            serial=serial,
                            description=truncate_description(device_description)
                        )
                        logger.info(f"Created new device with unique name: {unique_name}")
                        break
                    except RequestError as inner_e:
                        if "Device name must be unique per site" in str(inner_e):
                            suffix += 1
                        else:
                            # Re-raise if it's a different error
                            raise
            else:
                # Re-raise if it's a different error
                raise
        except Exception as e:
            logger.debug(f"Error getting device {device_name}: {str(e)}")
            try:
                # Create new device
                nb_device = nb.dcim.devices.create(
                    name=device_name,
                    device_type=device_type.id,
                    role=device_role.id,
                    site=site.id,
                    status='active',
                    tags=[ise_tag.id],
                    serial=serial,
                    description=truncate_description(device_description)
                )
                logger.info(f"Created new device: {device_name}")
            except RequestError as e:
                # Handle the case where device name already exists in the site
                if "Device name must be unique per site" in str(e):
                    # Make the name unique by appending a suffix
                    suffix = 1
                    while True:
                        unique_name = f"{device_name}-{suffix}"
                        try:
                            # Check if this name is available
                            if len(unique_name) > 64:
                                # Truncate again if needed
                                unique_name = f"{device_name[:60]}-{suffix}"
                            
                            nb_device = nb.dcim.devices.create(
                                name=unique_name,
                                device_type=device_type.id,
                                role=device_role.id,
                                site=site.id,
                                status='active',
                                tags=[ise_tag.id],
                                serial=serial,
                                description=truncate_description(device_description)
                            )
                            logger.info(f"Created new device with unique name: {unique_name}")
                            break
                        except RequestError as inner_e:
                            if "Device name must be unique per site" in str(inner_e):
                                suffix += 1
                            else:
                                # Re-raise if it's a different error
                                raise
                else:
                    # Re-raise if it's a different error
                    raise
        
        # Create interface if it doesn't exist
        interface_name = "mgmt"  # Default management interface name
        try:
            interface = nb.dcim.interfaces.get(device_id=nb_device.id, name=interface_name)
            if not interface:
                interface = nb.dcim.interfaces.create(
                    device=nb_device.id,
                    name=interface_name,
                    type="1000base-t",
                    tags=[ise_tag.id]
                )
                logger.info(f"Created interface {interface_name} for device {device_name}")
            else:
                logger.info(f"Found existing interface {interface_name} for device {device_name}")
        except Exception as e:
            logger.debug(f"Error getting interface {interface_name} for device {device_name}: {str(e)}")
            interface = nb.dcim.interfaces.create(
                device=nb_device.id,
                name=interface_name,
                type="1000base-t",
                tags=[ise_tag.id]
            )
            logger.info(f"Created interface {interface_name} for device {device_name}")
        
        # Process IP addresses
        for ip_entry in ip_list:
            ip_address = ip_entry.get('ipaddress')
            mask = ip_entry.get('mask', 32)
            
            if ip_address:
                # Create IP address
                try:
                    ip = get_or_create_ip_address(
                        nb,
                        ip_address=ip_address,
                        mask=mask,
                        description=f"IP for {device_name} from ISE",
                        tags=[ise_tag.id],
                        interface_id=interface.id
                    )
                    logger.info(f"Processed IP address for {device_name}: {ip_address}/{mask}")
                except Exception as e:
                    logger.error(f"Error processing IP address {ip_address}/{mask} for {device_name}: {str(e)}")

        # Add custom fields for SNMP data if available
        if snmp_data:
            try:
                # Update device with custom fields for SNMP data
                custom_fields = {}
                
                if 'sysContact' in snmp_data:
                    custom_fields['snmp_contact'] = snmp_data['sysContact']
                
                if 'sysUpTime' in snmp_data:
                    custom_fields['snmp_uptime'] = snmp_data['sysUpTime']
                
                if 'ciscoIOS' in snmp_data:
                    custom_fields['ios_version'] = snmp_data['ciscoIOS']
                
                if custom_fields:
                    nb_device.custom_fields = custom_fields
                    nb_device.save()
                    logger.info(f"Updated device {device_name} with SNMP custom fields")
            except Exception as e:
                logger.error(f"Error updating device {device_name} with SNMP data: {str(e)}")

    remove_stale_devices(nb, ise_devices)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Sync Cisco ISE network devices to Netbox')
    parser.add_argument('--ise-url', help='Cisco ISE URL (e.g., https://10.65.2.8)', default=os.environ.get('ISE_URL'))
    parser.add_argument('--ise-username', help='Cisco ISE username', default=os.environ.get('ISE_USERNAME'))
    parser.add_argument('--ise-password', help='Cisco ISE password', default=os.environ.get('ISE_PASSWORD'))
    parser.add_argument('--netbox-url', help='Netbox URL', default=os.environ.get('NETBOX_URL'))
    parser.add_argument('--netbox-token', help='Netbox API token', default=os.environ.get('NETBOX_TOKEN'))
    parser.add_argument('--verify-ssl', action='store_true', help='Verify SSL certificates for ISE API calls')
    parser.add_argument('--snmp-user', help='SNMPv3 username', default=os.environ.get('SNMP_USER', 'PRTGUser'))
    parser.add_argument('--snmp-auth', help='SNMPv3 authentication key', default=os.environ.get('SNMP_AUTH', 'f84366043b79c73cc61710b3664ad88e'))
    parser.add_argument('--snmp-priv', help='SNMPv3 privacy key', default=os.environ.get('SNMP_PRIV', '74c352800c52ea1196f796a94bb3f3c9'))
    return parser.parse_args()

def main():
    """Main function to orchestrate the ISE to Netbox sync"""
    args = parse_arguments()
    
    # Validate ISE parameters
    if not args.ise_url or not args.ise_username or not args.ise_password:
        logger.error("ISE URL, username, and password must be provided either as arguments or environment variables")
        sys.exit(1)
    
    # Validate Netbox parameters
    if not args.netbox_url or not args.netbox_token:
        logger.error("Netbox URL and token must be provided either as arguments or environment variables")
        sys.exit(1)
    
    try:
        logger.info("Starting Cisco ISE to Netbox sync")
        
        # Get ISE network devices
        ise_devices = get_ise_devices(
            args.ise_url, 
            args.ise_username, 
            args.ise_password, 
            args.verify_ssl
        )
        
        # Sync to Netbox
        sync_to_netbox(
            ise_devices, 
            args.netbox_url, 
            args.netbox_token,
            args.snmp_user,
            args.snmp_auth,
            args.snmp_priv
        )
        
        logger.info("Cisco ISE to Netbox sync completed successfully")
        
    except Exception as e:
        logger.error(f"Error during Cisco ISE to Netbox sync: {str(e)}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
