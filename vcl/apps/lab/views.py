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
import instance_create

# Create your views here.
def home(request):
    return render_to_response("signup.html",
                              locals(),
                              context_instance=RequestContext(request))

def logout_view(request):
    logout(request)
   #return HttpResponseRedirect('registration/logout.html')
    return render_to_response('registration/logout.html',locals(),context_instance=RequestContext(request))


@login_required(login_url='/accounts/login/')
def index(request):
    myuser = request.user
    action = 'Do Nothing'
    result = ''
    if 'iid' in request.POST:
        iid = request.POST['iid']
	if 'action' in request.POST:
            action = request.POST['action']
            if action == 'Start Server':
                result = start_instance(iid)
            if action == 'Stop Server':
                result = stop_instance(iid)
            if action == 'Create Server':
        	iitype = str(request.POST['instance_type'])
		iid = request.POST['iid']
		coursecode = request.POST['coursecode']
		instructor_id = request.POST['instructor_id']
		credentials = request.POST['lab_auth_info']

#		if iitype == 't1.micro':
#                  iitype = 't2.micro'
#                if iitype == 'm1.small':
#                  iitype = 'm2.small'
#                if iitype == 'm1.medium':
#                  iitype = 'm2.medium'

		try:
		    result = create_instance(username=myuser.username, ami=iid, instance_type=iitype, classcode=coursecode,instructor_id=instructor_id,credentials=credentials)
		except:
		    iitype = 't2.micro'
    		    result = create_instance(username=myuser.username, ami=iid, instance_type=iitype, classcode=coursecode,instructor_id=instructor_id,credentials=credentials)
            if action == 'Terminate Server':
		instructor.objects.filter(instance_id=iid).delete()
                result = terminate_instance(iid)
            if action == 'Download Connection File':
		public_dns = request.POST['public_dns']
		result = create_rdp_file(public_dns)

    error_msg=''
    if result == "IntegrityError":
       error_msg = 'Only one server is allowed per course'

    list_of_machines = list_instances(username=myuser.username)
    list_of_labs = computerlab.objects.all()
    is_instructor = "no"
    check_instructor = computerlab.objects.filter(instructor_id=myuser.username)
    check_instructor = computerlab.objects.filter(Q(instructor_id=myuser.username) | Q(instructor2_id=myuser.username)| Q(instructor3_id=myuser.username))
    if check_instructor.count() > 0:
	is_instructor = "yes"
    #my_lab_info = computerlab.objects.get(amazonami=list_of_machines['ami_id'])
    return render_to_response('lab/index.html', {'list_of_machines':list_of_machines,"is_instructor":is_instructor, 'error_msg':error_msg,'myuser':myuser, 'action': action, 'list_of_labs':list_of_labs}, context_instance=RequestContext(request))
     #output =  'Your instance is ready to use!  RDP or SSH to: ',instance.dns_name
    #return HttpResponseRedirect(reverse('lab.index', args=(output,)))




###################################################


def create_rdp_file(request):
	from django.http import HttpResponse
	#import StringIO
	import csv
	public_dns=request.GET['public_dns']

	lab_auth_info = request.GET['lab_auth_info']
        try:
                find = re.compile(r"^[^,]*")
                regex1 = re.search(find, lab_auth_info).group(0)
                regex2 = regex1.split('=')
                username = regex2[1].strip()
        except:
                username=""

	import cStringIO as StringIO
	#response = HttpResponse(tmpfile, content_type="application/x-rdp")
	#response['Content-Disposition'] = 'attachment; filename=connect.rdp'
	#writer = csv.writer(response)
	#myfile = StringIO.StringIO(response)
	tmpfile = """ screen mode id:i:1
desktopwidth:i:1280
desktopheight:i:720
session bpp:i:32
auto connect:i:1
compression:i:1
keyboardhook:i:2
audiomode:i:2
redirectdrives:i:0
redirectprinters:i:0
redirectcomports:i:0
redirectsmartcards:i:0
displayconnectionbar:i:1
username:s:{0}
domain:s:
alternate shell:s:
shell working directory:s:
disable wallpaper:i:1
disable full window drag:i:1
disable menu anims:i:1
disable themes:i:1
bitmapcachepersistenable:i:1
full address:s:%s
""" % (public_dns)

	#tmpfile = tmpfile+"full address:s:"+public_dns
	#writer.writerow([tmpfile])
	tmpfile = tmpfile.format(username)
	find = re.compile(r"^[^.]*")
	filename = re.search(find, public_dns).group(0)
	filename = filename + ".rdp"
        response = HttpResponse(tmpfile, content_type="application/x-rdp")
        response['Content-Disposition'] = "attachment; filename="+ filename
	return response

def create_status_alarm(instance_id):
    ec2_conn = boto.ec2.connect_to_region("us-east-1")

    cloudwatch_conn = boto.ec2.cloudwatch.connect_to_region("us-east-1")

    reservations = ec2_conn.get_all_instances(filters = {'instance-id': instance_id})
    if reservations and reservations[0].instances:
        instance = reservations[0].instances[0]
        instance_name = instance.tags['Name']
    else:
        print "Invalid instance-id!"
        sys.exit(1)
    alarm = boto.ec2.cloudwatch.alarm.MetricAlarm(
        connection = cloudwatch_conn,
        name = instance_id + " : " + instance_name + "-CPU Utilization less than 5%",
        metric = 'CPUUtilization',
        namespace = 'AWS/EC2',
        statistic = 'Maximum',
        comparison = '<=',
        description = 'Alarm that triggers when the instance CPU goes less than 5% for 1 hour',
        threshold = 5,
        period = 3600,
        evaluation_periods = 2,
        dimensions = {'InstanceId':instance_id},
        alarm_actions = 'arn:aws:automate:us-east-1:ec2:stop',
    )
    cloudwatch_conn.put_metric_alarm(alarm)

def delete_status_alarm(instance_id):
    ec2_conn = boto.ec2.connect_to_region("us-east-1")

    cloudwatch_conn = boto.ec2.cloudwatch.connect_to_region("us-east-1")

    reservations = ec2_conn.get_all_instances(filters = {'instance-id': instance_id})
    if reservations and reservations[0].instances:
        instance = reservations[0].instances[0]
        instance_name = instance.tags['Name']
    else:
        print "Invalid instance-id!"

    alarm_name = instance_id + " : " + instance_name + "-CPU Utilization less than 10%";
    list_alarms = []
    list_alarms.append(alarm_name)
    cloudwatch_conn.delete_alarms(list_alarms)


@login_required(login_url='/accounts/login/')
def tutor(request):
    myuser = request.user
    action = 'Do Nothing'
    course = ''
    if request.method == 'GET' and 'course' in request.GET:
	course = request.GET['course']

    list_of_students = instructor.objects.filter(instructor_id=myuser.username)

    student_instance_ids = []
    course_list = []

    for student in list_of_students:
	student_instance_ids.append(student.instance_id)
	course_list.append(student.course_id)

    course_list = list(set(course_list))

    if len(course) > 0:
	list_of_students = instructor.objects.filter(instructor_id=myuser.username,course_id=course)

    final_student_instance_ids = []
    aws_conn = boto.ec2.connection.EC2Connection()
    for inst in student_instance_ids:
	try:
	    res=aws_conn.get_all_instances(instance_ids=[inst])
	    final_student_instance_ids.append(inst)
	except:
	    instructor.objects.filter(instance_id=inst).delete()

    instance_states = {}
#    aws_conn = boto.ec2.connection.EC2Connection()
    res=aws_conn.get_all_instances(instance_ids=final_student_instance_ids)
    instances = [i for r in res for i in r.instances]
    for i in instances:
        instance_states[i.id] = {'instance_state': i._state, 'public_dns': i.public_dns_name}

    student_data = []
    for student in list_of_students:
	try:
	    student_data.append({"course_id":student.course_id,"student_id":student.student_id,"credentials":student.credentials,"instance_state":str(instance_states[student.instance_id]['instance_state']),"dsn":instance_states[student.instance_id]['public_dns']})
    	except:
	    continue
    student_data = sorted(student_data, key=lambda k: k['instance_state'])

    if 'action' in request.POST:
	public_dns = request.POST['public_dns']
        result = create_rdp_file(public_dns)
    return render_to_response('lab/instructor.html', {'student_data':student_data,'course_list':course_list, 'myuser':myuser,'action': action}, context_instance=RequestContext(request))



def group1(request):
    myuser = request.user
    action = 'Do Nothing'
    course = ''
    if request.method == 'GET' and 'course' in request.GET:
        course = request.GET['course']

    list_of_students = instructor.objects.filter(instructor_id=myuser.username)

    student_instance_ids = []
    course_list = []

    for student in list_of_students:
        student_instance_ids.append(student.instance_id)
        course_list.append(student.course_id)

    course_list = list(set(course_list))

    if len(course) > 0:
        list_of_students = instructor.objects.filter(instructor_id=myuser.username,course_id=course)

    instance_states = {}
    aws_conn = boto.ec2.connection.EC2Connection()
    res=aws_conn.get_all_instances(instance_ids=student_instance_ids)
    instances = [i for r in res for i in r.instances]
    for i in instances:
        instance_states[i.id] = {'instance_state': i._state, 'public_dns': i.public_dns_name}

    student_data = []
    for student in list_of_students:
        student_data.append({"course_id":student.course_id,"student_id":student.student_id,"credentials":student.credentials,"instance_state":str(instance_states[student.instance_id]['instance_state']),"dsn":instance_states[student.instance_id]['public_dns']})
    student_data = sorted(student_data, key=lambda k: k['instance_state'])

    if 'action' in request.POST:
        public_dns = request.POST['public_dns']
        result = create_rdp_file(public_dns)
    return render_to_response('lab/groups.html', {'student_data':student_data,'course_list':course_list, 'myuser':myuser,'action': action}, context_instance=RequestContext(request))


@login_required(login_url='/accounts/login/')
def groups(request):
    myuser = request.user
    action = 'Do Nothing'
    result = ''
    coursecode = ''
    group_size = ''
    iid=''
    data=''
    if 'iid' in request.POST:
        iid = request.POST['iid']
        if 'action' in request.POST:
            action = request.POST['action']
            if action == 'Start Server':
                result = start_instance(iid)
            if action == 'Stop Server':
                result = stop_instance(iid)
            if action == 'Create Server':
                iid = request.POST['iid']
                student_group = request.POST['gname']
                group_size = int(request.POST['box-0'])
                student_ids = []
                for num in range(1,group_size+1):
                        box = "box-" + str(num);
                        student_id = request.POST[box];
                        student_ids.append(student_id);
                course_code = list(computerlab.objects.values_list('coursecode', flat=True).filter(amazonami=iid))
                instance_type = list(computerlab.objects.values_list('instance_type', flat=True).filter(amazonami=iid))

                result = create_shared_machine(student_ids=student_ids, ami=iid, instance_type=str(instance_type[0]), classcode=str(course_code[0]),student_group=student_group)

	    if action == 'Create Sandbox':
                iid = request.POST['iid']
                student_group = request.POST['gname']
                group_size = int(request.POST['box-0'])
                student_ids = []
                for num in range(1,group_size+1):
                        box = "box-" + str(num);
                        student_id = request.POST[box];
                        student_ids.append(student_id);
                course_code = list(sandbox.objects.values_list('labname', flat=True).filter(amazonami=iid))
                instance_type = list(sandbox.objects.values_list('instance_type', flat=True).filter(amazonami=iid))

                result = create_shared_machine(student_ids=student_ids, ami=iid, instance_type=str(instance_type[0]), classcode=str(course_code[0]),student_group=student_group)

            if action == 'Terminate Server':
                instructor.objects.filter(instance_id=iid).delete()
                result = terminate_instance(iid)
            if action == 'Download Connection File':
                public_dns = request.POST['public_dns']
                result = create_rdp_file(public_dns)

    error_msg=data

    list_of_machines = list_shared_instances(username=myuser.username)
    list_of_labs = computerlab.objects.all()
    list_of_sandbox = sandbox.objects.all()
    is_instructor = "no"
    check_instructor = computerlab.objects.filter(instructor_id=myuser.username)
    check_instructor = computerlab.objects.filter(Q(instructor_id=myuser.username) | Q(instructor2_id=myuser.username)| Q(instructor3_id=myuser.username))
    if check_instructor.count() > 0:
        is_instructor = "yes"
    return render_to_response('lab/groups_new.html', {'list_of_machines':list_of_machines,'list_of_sandbox':list_of_sandbox,"is_instructor":is_instructor, 'error_msg':error_msg,'myuser':myuser, 'action': action, 'list_of_labs':list_of_labs}, context_instance=RequestContext(request))

@login_required(login_url='/accounts/login/')
def sandbox_page(request):
    myuser = request.user

    is_instructor = "no"
    check_instructor = faculty.objects.filter(directory_id=myuser.username)
    if check_instructor.count() > 0:
        is_instructor = "yes"

    action = 'Do Nothing'
    result = ''
    if 'iid' in request.POST:
        iid = request.POST['iid']
        if 'action' in request.POST:
            action = request.POST['action']
            if action == 'Start Server':
                result = start_instance(iid)
            if action == 'Stop Server':
                result = stop_instance(iid)
            if action == 'Create Server':
                iitype = str(request.POST['instance_type'])
                iid = request.POST['iid']
                credentials = request.POST['lab_auth_info']
                labname = request.POST['labname']
                monitor = request.POST['monitor']
                try:
                    result = create_sandbox_instance(username=myuser.username, ami=iid, instance_type=iitype, labname=labname, is_instructor=is_instructor, credentials=credentials,monitor=monitor)
                except:
                    iitype = 't2.micro'
                    result = create_sandbox_instance(username=myuser.username, ami=iid, instance_type=iitype, labname=labname, is_instructor=is_instructor, credentials=credentials,monitor=monitor)
            if action == 'Terminate Server':
                instructor.objects.filter(instance_id=iid).delete()
                result = terminate_instance(iid)
            if action == 'Download Connection File':
                public_dns = request.POST['public_dns']
                result = create_rdp_file(public_dns)

    error_msg=''
    if result == "IntegrityError":
       error_msg = 'Only one server is allowed per course'

    list_of_machines = list_sandbox_instances(username=myuser.username)
    list_of_labs = sandbox.objects.all()

    #my_lab_info = computerlab.objects.get(amazonami=list_of_machines['ami_id'])
    return render_to_response('lab/sandbox.html', {'list_of_machines':list_of_machines,"is_instructor":is_instructor, 'error_msg':error_msg,'myuser':myuser, 'action': action, 'list_of_labs':list_of_labs}, context_instance=RequestContext(request))
     #output =  'Your instance is ready to use!  RDP or SSH to: ',instance.dns_name
    #return HttpResponseRedirect(reverse('lab.index', args=(output,)))
