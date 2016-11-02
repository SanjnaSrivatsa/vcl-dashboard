from django.shortcuts import render, render_to_response, RequestContext

from django.shortcuts import render_to_response, get_object_or_404
from .models import computerlab,instructor,sandbox,faculty
from django.template import Context, loader, RequestContext
from django.http import HttpResponseRedirect, HttpResponse
from django.core.urlresolvers import reverse
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import logout_then_login
from django.contrib.auth import logout
from django.contrib.auth.models import User
from django.db.models import Q

import os
import time
import boto
import boto.manage.cmdshell
import boto.manage.server
import boto.ec2.cloudwatch
import re


def create_instance(
        ami='ami-ddb239b4',
        instance_type='t1.micro',
        # key_name='aws_vcl_key',
        key_name='instance_key',
        key_extension='.pem',
        key_dir='~/.ssh',
        # key_dir='/home/infoadmin/keys',
        group_name='default',
        ssh_port=22,
        cidr='0.0.0.0/0',
        tag='LBSC_670',
        user_data=None,
        cmd_shell=True,
        login_user='ubuntu',
        ssh_passwd=None,
        username='',
        classcode='iSchool',
        instructor_id='',
        credentials='',
        azone='us-east-1c'):

    """
    Launch an instance and wait for it to start running.
    Returns a tuple consisting of the Instance object and the CmdShell
    object, if request, or None.
    ami        The ID of the Amazon Machine Image that this instance will
               be based on.  Default is a 64-bit Amazon Linux EBS image.
    instance_type The type of the instance.
    key_name   The name of the SSH Key used for logging into the instance.
               It will be created if it does not exist.
    key_extension The file extension for SSH private key files.
    key_dir    The path to the directory containing SSH private keys.
               This is usually ~/.ssh.
    group_name The name of the security group used to control access
               to the instance.  It will be created if it does not exist.
    ssh_port   The port number you want to use for SSH access (default 22).
    cidr       The CIDR block used to limit access to your instance.
    tag        A name that will be used to tag the instance so we can
               easily find it later.
    user_data  Data that will be passed to the newly started
               instance at launch and will be accessible via
               the metadata service running at http://169.254.169.254.
    cmd_shell  If true, a boto CmdShell object will be created and returned.
               This allows programmatic SSH access to the new instance.
    login_user The user name used when SSH'ing into new instance.  The
               default is 'ec2-user'
    ssh_passwd The password for your SSH key if it is encrypted with a
               passphrase.
    """
    cmd = None
    user_data = """#!/bin/bash
set -e -x
export DEBIAN_FRONTEND=noninteractive
apt-get --yes remove --force-yes freenx-server
apt-get install --force-yes freenx-server
"""
    # user_data =
    #   "apt-get install -o Dpkg::Options::='--force-confdef' \
    #   -o Dpkg::Options::='--force-confold'  -f -q -y freenx-server"
    # new_register =
    #   instructor(instructor_id=instructor_id,course_id=classcode,student_id=username)

    aws_conn = boto.ec2.connection.EC2Connection()
    student_records = instructor.objects.filter(
            course_id=classcode, student_id=username
        )
    for student in student_records:
        try:
            res = aws_conn.get_all_instances(
                    instance_ids=[student.instance_id]
                    )
            instances = [i for r in res for i in r.instances]
            for i in instances:
                if str(i._state) == 'terminated(48)':
                    instructor.objects.filter(
                            instance_id=student.instance_id
                        ).delete()
        except:
            instructor.objects.filter(instance_id=student.instance_id).delete()

    count_of_records = instructor.objects.filter(
            course_id=classcode,
            student_id=username
        ).count()

    if count_of_records > 0:
        return "IntegrityError"

    # Create a connection to EC2 service.
    # You can pass credentials in to the connect_ec2 method explicitly
    # or you can use the default credentials in your ~/.boto config file
    # as we are doing here.
    ec2 = boto.connect_ec2()

    # Check to see if specified keypair already exists.
    # If we get an InvalidKeyPair.NotFound error back from EC2,
    # it means that it doesn't exist and we need to create it.
    try:
        key = ec2.get_all_key_pairs(keynames=[key_name])[0]
    except ec2.ResponseError, e:
        if e.code == 'InvalidKeyPair.NotFound':
            print 'Creating keypair: %s' % key_name
            # Create an SSH key to use when logging into instances.
            key = ec2.create_key_pair(key_name)

            # AWS will store the public key but the private key is
            # generated and returned and needs to be stored locally.
            # The save method will also chmod the file to protect
            # your private key.
            key.save(key_dir)
        else:
            raise

    # Check to see if specified security group already exists.
    # If we get an InvalidGroup.NotFound error back from EC2,
    # it means that it doesn't exist and we need to create it.
    try:
        group = ec2.get_all_security_groups(groupnames=[group_name])[0]
    except ec2.ResponseError, e:
        if e.code == 'InvalidGroup.NotFound':
            print 'Creating Security Group: %s' % group_name
            # Create a security group to control access to instance via SSH.
            group = ec2.create_security_group(group_name,
                                              'A group that allows SSH access')
        else:
            raise

    # Add a rule to the security group to authorize SSH traffic
    # on the specified port.
    try:
        group.authorize('tcp', ssh_port, ssh_port, cidr)
    except ec2.ResponseError, e:
        if e.code == 'InvalidPermission.Duplicate':
            print 'Security Group: %s already authorized' % group_name
        else:
            raise

    # find the volume for the user and class in question
    # volumes = ec2.get_all_volumes(
    #     filters={'tag-value': username, 'tag-value':classcode}
    #     )
    # Attach the volume to the server
    # result = volumes.attach(instance, '/dev/sdf')
    # define user data to mount the volume
    # Now start up the instance.  The run_instances method
    # has many, many parameters but these are all we need
    # for now.
    reservation = ec2.run_instances(ami,
                                    key_name=key_name,
                                    security_groups=[group_name],
                                    instance_type=instance_type,
                                    user_data=user_data,
                                    placement=azone)

    # Find the actual Instance object inside the Reservation object
    # returned by EC2.

    instance = reservation.instances[0]
    machinename = classcode + "--" + username + "--Instructor:" + instructor_id
    # Add user tags to it
    instance.add_tag('username', username)
    instance.add_tag('classcode', classcode)
    instance.add_tag('Name', machinename)

    # The instance has been launched but it's not yet up and
    # running.  Let's wait for its state to change to 'running'.

    print 'waiting for instance'
    while instance.state != 'running':
        print '.'
        time.sleep(5)
        instance.update()

    create_status_alarm(instance.id)

    new_register = instructor(
            instance_id=instance.id,
            instructor_id=instructor_id,
            course_id=classcode,
            student_id=username,
            credentials=credentials
        )
    new_register.save()

    return (
        'Your instance has been created and is running at',
        instance.dns_name,
        '  Please use NX Viewer or remote desktop to connect.'
        )

def start_instance(iid):
    ec2 = boto.connect_ec2()
    reservations = ec2.get_all_instances(filters={'instance-id': iid})
    instance = reservations[0].instances[0]
    iid = [instance.id]
    instance_state = ec2.start_instances(iid)
    while instance.state != 'running':
        print '.'
        time.sleep(5)
        instance.update()


def stop_instance(iid):
    ec2 = boto.connect_ec2()
    reservations = ec2.get_all_instances(filters={'instance-id': iid})
    instance = reservations[0].instances[0]
    iid = [instance.id]
    instance_state = ec2.stop_instances(iid)
    while instance.state != 'stopped':
        print '.'
        time.sleep(5)
        instance.update()


def terminate_instance(iid):
    ec2 = boto.connect_ec2()
    reservations = ec2.get_all_instances(filters={'instance-id': iid})
    instance = reservations[0].instances[0]
    delete_status_alarm(iid)
    iid = [instance.id]
    instance_state = ec2.terminate_instances(iid)
    while instance.state != 'terminated':
        print '.'
        time.sleep(5)
        instance.update()


def list_instances(ami='ami-',
                   instance_type='t1.micro',
                   key_name='instance_key',
                   key_extension='.pem',
                   key_dir='~/.ssh',
                   # key_dir='/home/infoadmin/keys',
                   group_name='vcl_lab',
                   ssh_port=22,
                   cidr='0.0.0.0/0',
                   tag='LBSC_670',
                   user_data=None,
                   cmd_shell=True,
                   login_user='ubuntu',
                   ssh_passwd=None,
                   username='',
                   classcode='',
                   azone='us-east-1c'):
    ec2 = boto.connect_ec2()
    reservations = ec2.get_all_instances(filters={'tag-value': username})
    machines = {}
    for reservation in reservations:
        instance = reservation.instances[0]
        instance_tags = instance.tags
        if instance_tags[u'Name']:
            instance_name = instance_tags[u'Name']
        else:
            instance_name = "Lab machine"
        if instance.state != 'terminated':
            tmpinstance = str(instance.image_id)
            # comp_lab_info = {
            # 'lab_auth_info':
            # 'Sorry, I could not find any authentication information',
            # 'lab_connection_options':
            # 'Sorry, I could not find connection options!'}
            try:
                comp_lab_info = computerlab.objects.get(amazonami=tmpinstance)
                lab_auth_info = comp_lab_info.lab_auth_info
                connect_info = comp_lab_info.lab_connection_options
                coursecode = comp_lab_info.coursecode
            except Exception:
                comp_lab_info = {'lab_auth_info': 'simple',
                                 'lab_connection_options': 'test2'}
                lab_auth_info = comp_lab_info['lab_auth_info']
                coursecode = 'none'
                connect_info = comp_lab_info['lab_connection_options']

            try:
                fetch_status = ec2.get_all_instance_status(
                        instance_ids=instance.id
                        )
                machine_status = fetch_status[0].system_status.details[
                        'reachability'
                        ]
            except:
                machine_status = "stopped"
            machines[instance.id] = {
                    'instance_name': instance_name,
                    'coursecode': coursecode,
                    'instance_type': instance.instance_type,
                    'lab_auth_info': lab_auth_info,
                    'instance_id': instance.id,
                    'connect_info': connect_info,
                    'instance_state': instance.state,
                    'ami_id': instance.image_id,
                    'machine_status': machine_status,
                    'public_dns': instance.public_dns_name,
                    'insert': str(instance_name)}

    return machines
    
    #shared_machine creation
def create_shared_machine(ami='ami-ddb239b4',
                          instance_type='t1.micro',
                          # key_name='aws_vcl_key',
                          key_name='instance_key',
                          key_extension='.pem',
                          key_dir='~/.ssh',
                          # key_dir='/home/infoadmin/keys',
                          group_name='default',
                          ssh_port=22,
                          cidr='0.0.0.0/0',
                          tag='LBSC_670',
                          user_data=None,
                          cmd_shell=True,
                          login_user='ubuntu',
                          ssh_passwd=None,
                          username='',
                          classcode='iSchool',
                          student_group='',
                          student_ids=[],
                          azone='us-east-1c'):

    ec2 = boto.connect_ec2()

    # Check to see if specified keypair already exists.
    # If we get an InvalidKeyPair.NotFound error back from EC2,
    # it means that it doesn't exist and we need to create it.
    try:
        key = ec2.get_all_key_pairs(keynames=[key_name])[0]
    except ec2.ResponseError, e:
        if e.code == 'InvalidKeyPair.NotFound':
            print 'Creating keypair: %s' % key_name
            # Create an SSH key to use when logging into instances.
            key = ec2.create_key_pair(key_name)

            # AWS will store the public key but the private key is
            # generated and returned and needs to be stored locally.
            # The save method will also chmod the file to protect
            # your private key.
            key.save(key_dir)
        else:
            raise

    # Check to see if specified security group already exists.
    # If we get an InvalidGroup.NotFound error back from EC2,
    # it means that it doesn't exist and we need to create it.
    try:
        group = ec2.get_all_security_groups(groupnames=[group_name])[0]
    except ec2.ResponseError, e:
        if e.code == 'InvalidGroup.NotFound':
            print 'Creating Security Group: %s' % group_name
            # Create a security group to control access to instance via SSH.
            group = ec2.create_security_group(group_name,
                                              'A group that allows SSH access')
        else:
            raise

    # Add a rule to the security group to authorize SSH traffic
    # on the specified port.
    try:
        group.authorize('tcp', ssh_port, ssh_port, cidr)
    except ec2.ResponseError, e:
        if e.code == 'InvalidPermission.Duplicate':
            print 'Security Group: %s already authorized' % group_name
        else:
            raise

    reservation = ec2.run_instances(ami,
                                    key_name=key_name,
                                    security_groups=[group_name],
                                    instance_type=instance_type,
                                    user_data=user_data,
                                    placement=azone)

    # Find the actual Instance object inside the Reservation object
    # returned by EC2.

    instance = reservation.instances[0]
    machinename = "shared--" + classcode + "--" + student_group
    # Add user tags to it

    instance.add_tag('student_ids', student_ids)
    instance.add_tag('classcode', classcode)
    instance.add_tag('Name', machinename)
    instance.add_tag('student_group', student_group)

    # The instance has been launched but it's not yet up and
    # running.  Let's wait for its state to change to 'running'.

    print 'waiting for instance'
    while instance.state != 'running':
        print '.'
        time.sleep(5)
        instance.update()

    create_status_alarm(instance.id)

    return 'Your instance has been created and is running at',
    instance.dns_name, '  Please use NX Viewer or remote desktop to connect.'


def list_shared_instances(ami='ami-',
                          instance_type='t1.micro',
                          key_name='instance_key',
                          key_extension='.pem',
                          key_dir='~/.ssh',
                          # key_dir='/home/infoadmin/keys',
                          group_name='vcl_lab',
                          ssh_port=22,
                          cidr='0.0.0.0/0',
                          tag='LBSC_670',
                          user_data=None,
                          cmd_shell=True,
                          login_user='ubuntu',
                          ssh_passwd=None,
                          username='',
                          classcode='',
                          azone='us-east-1c'):
    ec2 = boto.connect_ec2()
    reservations = ec2.get_all_instances(filters={
        'tag:student_ids': "*"+username+"*"})
    machines = {}
    for reservation in reservations:
        instance = reservation.instances[0]
        instance_tags = instance.tags
        if instance_tags[u'Name']:
            instance_name = instance_tags[u'Name']
        else:
            instance_name = "Lab machine"
        if instance.state != 'terminated':
            tmpinstance = str(instance.image_id)
            try:
                comp_lab_info = computerlab.objects.get(amazonami=tmpinstance)
                lab_auth_info = comp_lab_info.lab_auth_info
                connect_info = comp_lab_info.lab_connection_options
                coursecode = comp_lab_info.coursecode
            except Exception:
                comp_lab_info = {
                        'lab_auth_info': 'simple',
                        'lab_connection_options': 'test2'
                        }
                lab_auth_info = comp_lab_info['lab_auth_info']
                coursecode = 'none'
                connect_info = comp_lab_info['lab_connection_options']
            try:
                fetch_status = ec2.get_all_instance_status(
                        instance_ids=instance.id
                        )
                machine_status = \
                    fetch_status[0].system_status.details['reachability']
            except:
                machine_status = "stopped"
            machines[instance.id] = {
                'instance_name': instance_name,
                'coursecode': coursecode,
                'instance_type': instance.instance_type,
                'lab_auth_info': lab_auth_info,
                'instance_id': instance.id,
                'connect_info': connect_info,
                'instance_state': instance.state,
                'ami_id': instance.image_id,
                'machine_status': machine_status,
                'public_dns': instance.public_dns_name,
                'insert': str(instance_name)}

    return machines
    
    #sandbox instances
def create_sandbox_instance(ami='ami-ddb239b4',
                            instance_type='t1.micro',
                            # key_name='aws_vcl_key',
                            key_name='instance_key',
                            key_extension='.pem',
                            key_dir='~/.ssh',
                            # key_dir='/home/infoadmin/keys',
                            group_name='default',
                            ssh_port=22,
                            cidr='0.0.0.0/0',
                            tag='LBSC_670',
                            user_data=None,
                            cmd_shell=True,
                            login_user='ubuntu',
                            ssh_passwd=None,
                            username='',
                            classcode='iSchool',
                            instructor_id='',
                            credentials='',
                            monitor='yes',
                            is_instructor="no",
                            labname='',
                            azone='us-east-1c'):

    aws_conn = boto.ec2.connection.EC2Connection()
    # Create a connection to EC2 service.
    # You can pass credentials in to the connect_ec2 method explicitly
    # or you can use the default credentials in your ~/.boto config file
    # as we are doing here.
    ec2 = boto.connect_ec2()

    # Check to see if specified keypair already exists.
    # If we get an InvalidKeyPair.NotFound error back from EC2,
    # it means that it doesn't exist and we need to create it.
    try:
        key = ec2.get_all_key_pairs(keynames=[key_name])[0]
    except ec2.ResponseError, e:
        if e.code == 'InvalidKeyPair.NotFound':
            print 'Creating keypair: %s' % key_name
            # Create an SSH key to use when logging into instances.
            key = ec2.create_key_pair(key_name)

            # AWS will store the public key but the private key is
            # generated and returned and needs to be stored locally.
            # The save method will also chmod the file to protect
            # your private key.
            key.save(key_dir)
        else:
            raise

    # Check to see if specified security group already exists.
    # If we get an InvalidGroup.NotFound error back from EC2,
    # it means that it doesn't exist and we need to create it.
    try:
        group = ec2.get_all_security_groups(groupnames=[group_name])[0]
    except ec2.ResponseError, e:
        if e.code == 'InvalidGroup.NotFound':
            print 'Creating Security Group: %s' % group_name
            # Create a security group to control access to instance via SSH.
            group = ec2.create_security_group(group_name,
                                              'A group that allows SSH access')
        else:
            raise

    # Add a rule to the security group to authorize SSH traffic
    # on the specified port.
    try:
        group.authorize('tcp', ssh_port, ssh_port, cidr)
    except ec2.ResponseError, e:
        if e.code == 'InvalidPermission.Duplicate':
            print 'Security Group: %s already authorized' % group_name
        else:
            raise

        # find the volume for the user and class in question
        # volumes = ec2.get_all_volumes(filters=
        # {'tag-value': username, 'tag-value':classcode})
        # Attach the volume to the server
        # result = volumes.attach(instance, '/dev/sdf')
        # define user data to mount the volume
        # Now start up the instance.  The run_instances method
        # has many, many parameters but these are all we need
        # for now.
    reservation = ec2.run_instances(ami,
                                    key_name=key_name,
                                    security_groups=[group_name],
                                    instance_type=instance_type,
                                    user_data=user_data,
                                    placement=azone)

    # Find the actual Instance object inside the Reservation object
    # returned by EC2.

    instance = reservation.instances[0]
    machinename = "sandbox: " + labname + "--" + username
    sandbox_user = "sandbox_user:"+username
    instance.add_tag('sandbox_user', sandbox_user)
    instance.add_tag('Name', machinename)

    # The instance has been launched but it's not yet up and
    # running.  Let's wait for its state to change to 'running'.

    print 'waiting for instance'
    while instance.state != 'running':
        print '.'
        time.sleep(5)
        instance.update()

    if is_instructor == "no":
        create_status_alarm(instance.id)
    if is_instructor == "yes":
        if monitor == "yes":
            create_status_alarm(instance.id)

    return 'Your instance has been created and is running at',
    instance.dns_name,
    '  Please use NX Viewer or remote desktop to connect.'


def list_sandbox_instances(ami='ami-',
                           instance_type='t1.micro',
                           key_name='instance_key',
                           key_extension='.pem',
                           key_dir='~/.ssh',
                           # key_dir='/home/infoadmin/keys',
                           group_name='vcl_lab',
                           ssh_port=22,
                           cidr='0.0.0.0/0',
                           tag='LBSC_670',
                           user_data=None,
                           cmd_shell=True,
                           login_user='ubuntu',
                           ssh_passwd=None,
                           username='',
                           classcode='',
                           azone='us-east-1c'):
    ec2 = boto.connect_ec2()
    reservations = ec2.get_all_instances(filters={
        'tag:sandbox_user': "*"+username+"*"}
        )
    machines = {}
    for reservation in reservations:
        instance = reservation.instances[0]
        instance_tags = instance.tags
        if instance_tags[u'Name']:
            instance_name = instance_tags[u'Name']
        else:
            instance_name = "Lab machine"
        if instance.state != 'terminated':
            tmpinstance = str(instance.image_id)
            try:
                comp_lab_info = sandbox.objects.get(amazonami=tmpinstance)
                lab_auth_info = comp_lab_info.lab_auth_info
                labname = comp_lab_info.labname
            except Exception:
                comp_lab_info = {'lab_auth_info': 'simple',
                                 'lab_connection_options': 'test2'
                                 }
                lab_auth_info = comp_lab_info['lab_auth_info']
                labname = 'none'
            try:
                fetch_status = ec2.get_all_instance_status(
                        instance_ids=instance.id
                        )
                machine_status = fetch_status[0].system_status.details
                ['reachability']
            except:
                machine_status = "stopped"

            machines[instance.id] = {
                    'instance_name': instance_name,
                    'labname': labname,
                    'instance_type': instance.instance_type,
                    'lab_auth_info': lab_auth_info,
                    'instance_id': instance.id,
                    'instance_state': instance.state,
                    'ami_id': instance.image_id,
                    'machine_status': machine_status,
                    'public_dns': instance.public_dns_name,
                    'insert': str(instance_name)
                    }

    return machines
