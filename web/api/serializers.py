from collections import defaultdict
from dashboard.models import *
from django.contrib.humanize.templatetags.humanize import (naturalday, naturaltime)
from django.db.models import F, JSONField, Value
from recon_note.models import *
from reNgine.common_func import *
from rest_framework import serializers
from scanEngine.models import *
from startScan.models import *
from targetApp.models import *
from dashboard.models import *
import yaml


class SearchHistorySerializer(serializers.ModelSerializer):
	class Meta:
		model = SearchHistory
		fields = ['query']


class DomainSerializer(serializers.ModelSerializer):
	vuln_count = serializers.SerializerMethodField()
	organization = serializers.SerializerMethodField()
	most_recent_scan = serializers.SerializerMethodField()
	insert_date = serializers.SerializerMethodField()
	insert_date_humanized = serializers.SerializerMethodField()
	start_scan_date = serializers.SerializerMethodField()
	start_scan_date_humanized = serializers.SerializerMethodField()

	class Meta:
		model = Domain
		fields = '__all__'
		depth = 2

	def get_vuln_count(self, obj):
		try:
			return obj.vuln_count
		except:
			return None

	def get_organization(self, obj):
		if Organization.objects.filter(domains__id=obj.id).exists():
			return [org.name for org in Organization.objects.filter(domains__id=obj.id)]

	def get_most_recent_scan(self, obj):
		return obj.get_recent_scan_id()

	def get_insert_date(self, obj):
		return naturalday(obj.insert_date).title()

	def get_insert_date_humanized(self, obj):
		return naturaltime(obj.insert_date).title()

	def get_start_scan_date(self, obj):
		if obj.start_scan_date:
			return naturalday(obj.start_scan_date).title()

	def get_start_scan_date_humanized(self, obj):
		if obj.start_scan_date:
			return naturaltime(obj.start_scan_date).title()


class SubScanResultSerializer(serializers.ModelSerializer):

	task = serializers.SerializerMethodField('get_task_name')
	subdomain_name = serializers.SerializerMethodField('get_subdomain_name')
	engine = serializers.SerializerMethodField('get_engine_name')

	class Meta:
		model = SubScan
		fields = [
			'id',
			'type',
			'subdomain_name',
			'start_scan_date',
			'stop_scan_date',
			'scan_history',
			'subdomain',
			'celery_ids',
			'status',
			'subdomain_name',
			'task',
			'engine'
		]

	def get_subdomain_name(self, subscan):
		return subscan.subdomain.name

	def get_task_name(self, subscan):
		return subscan.type

	def get_engine_name(self, subscan):
		if subscan.engine:
			return subscan.engine.engine_name
		return ''


class ReconNoteSerializer(serializers.ModelSerializer):

	domain_name = serializers.SerializerMethodField('get_domain_name')
	subdomain_name = serializers.SerializerMethodField('get_subdomain_name')
	scan_started_time = serializers.SerializerMethodField('get_scan_started_time')

	class Meta:
		model = TodoNote
		fields = '__all__'

	def get_domain_name(self, note):
		if note.scan_history:
			return note.scan_history.domain.name

	def get_subdomain_name(self, note):
		if note.subdomain:
			return note.subdomain.name

	def get_scan_started_time(self, note):
		if note.scan_history:
			return note.scan_history.start_scan_date


class OnlySubdomainNameSerializer(serializers.ModelSerializer):
	class Meta:
		model = Subdomain
		fields = ['name', 'id']


class SubScanSerializer(serializers.ModelSerializer):

	subdomain_name = serializers.SerializerMethodField('get_subdomain_name')
	time_taken = serializers.SerializerMethodField('get_total_time_taken')
	elapsed_time = serializers.SerializerMethodField('get_elapsed_time')
	completed_ago = serializers.SerializerMethodField('get_completed_ago')
	engine = serializers.SerializerMethodField('get_engine_name')

	class Meta:
		model = SubScan
		fields = '__all__'

	def get_subdomain_name(self, subscan):
		return subscan.subdomain.name

	def get_total_time_taken(self, subscan):
		return subscan.get_total_time_taken()

	def get_elapsed_time(self, subscan):
		return subscan.get_elapsed_time()

	def get_completed_ago(self, subscan):
		return subscan.get_completed_ago()

	def get_engine_name(self, subscan):
		if subscan.engine:
			return subscan.engine.engine_name
		return ''


class CommandSerializer(serializers.ModelSerializer):
	class Meta:
		model = Command
		fields = '__all__'
		depth = 1


class ScanHistorySerializer(serializers.ModelSerializer):

	subdomain_count = serializers.SerializerMethodField('get_subdomain_count')
	endpoint_count = serializers.SerializerMethodField('get_endpoint_count')
	vulnerability_count = serializers.SerializerMethodField('get_vulnerability_count')
	current_progress = serializers.SerializerMethodField('get_progress')
	completed_time = serializers.SerializerMethodField('get_total_scan_time_in_sec')
	elapsed_time = serializers.SerializerMethodField('get_elapsed_time')
	completed_ago = serializers.SerializerMethodField('get_completed_ago')
	organizations = serializers.SerializerMethodField('get_organizations')

	class Meta:
		model = ScanHistory
		fields = [
			'id',
			'subdomain_count',
			'endpoint_count',
			'vulnerability_count',
			'current_progress',
			'completed_time',
			'elapsed_time',
			'completed_ago',
			'organizations',
			'start_scan_date',
			'scan_status',
			'results_dir',
			'celery_ids',
			'tasks',
			'stop_scan_date',
			'error_message',
			'domain',
			'scan_type'
		]
		depth = 1

	def get_subdomain_count(self, scan_history):
		if scan_history.get_subdomain_count:
			return scan_history.get_subdomain_count()

	def get_endpoint_count(self, scan_history):
		if scan_history.get_endpoint_count:
			return scan_history.get_endpoint_count()

	def get_vulnerability_count(self, scan_history):
		if scan_history.get_vulnerability_count:
			return scan_history.get_vulnerability_count()

	def get_progress(self, scan_history):
		return scan_history.get_progress()

	def get_total_scan_time_in_sec(self, scan_history):
		return scan_history.get_total_scan_time_in_sec()

	def get_elapsed_time(self, scan_history):
		return scan_history.get_elapsed_time()

	def get_completed_ago(self, scan_history):
		return scan_history.get_completed_ago()

	def get_organizations(self, scan_history):
		return [org.name for org in scan_history.domain.get_organization()]


class OrganizationSerializer(serializers.ModelSerializer):

	class Meta:
		model = Organization
		fields = '__all__'


class EngineSerializer(serializers.ModelSerializer):

	tasks = serializers.SerializerMethodField()

	def get_tasks(self, obj):
		try:
			yaml_config = yaml.safe_load(obj.yaml_configuration)
			if not isinstance(yaml_config, dict):
				return []
		except Exception:
			return []
		return sorted([
			task for task in yaml_config.keys()
			if task in ENGINE_NAMES
		])

	class Meta:
		model = EngineType
		fields = ['id', 'engine_name', 'tasks']


class OrganizationTargetsSerializer(serializers.ModelSerializer):

	class Meta:
		model = Domain
		fields = [
			'name'
		]


class VisualiseVulnerabilitySerializer(serializers.ModelSerializer):

	description = serializers.SerializerMethodField('get_description')

	class Meta:
		model = Vulnerability
		fields = [
			'description',
			'http_url'
		]

	def get_description(self, vulnerability):
		return vulnerability.name


class VisualiseTechnologySerializer(serializers.ModelSerializer):

	description = serializers.SerializerMethodField('get_description')

	class Meta:
		model = Technology
		fields = [
			'description'
		]

	def get_description(self, tech):
		return tech.name

class VisualisePortSerializer(serializers.ModelSerializer):
    description = serializers.SerializerMethodField()
    title = serializers.SerializerMethodField()
    is_uncommon = serializers.SerializerMethodField()

    class Meta:
        model = Port
        fields = ['description', 'title', 'is_uncommon']

    def get_description(self, port):
        return f"{port.number}/{port.service_name}/{port.service_name}"

    def get_title(self, port):
        if port.is_uncommon:
            return "Uncommon Port"
        return "Port"

    def get_is_uncommon(self, port):
        return port.is_uncommon

class VisualiseIpSerializer(serializers.ModelSerializer):
    description = serializers.SerializerMethodField('get_description')
    children = serializers.SerializerMethodField('get_children')

    class Meta:
        model = IpAddress
        fields = ['description', 'children']

    def get_description(self, ip):
        return ip.address

    def get_children(self, ip):
        ports = ip.ports.all()
        serializer = VisualisePortSerializer(ports, many=True)
        return serializer.data

class VisualiseEndpointSerializer(serializers.ModelSerializer):

	description = serializers.SerializerMethodField('get_description')

	class Meta:
		model = EndPoint
		fields = [
			'description',
			'http_url'
		]

	def get_description(self, endpoint):
		return endpoint.http_url


class VisualiseSubdomainSerializer(serializers.ModelSerializer):

	children = serializers.SerializerMethodField('get_children')
	description = serializers.SerializerMethodField('get_description')
	title = serializers.SerializerMethodField('get_title')

	class Meta:
		model = Subdomain
		fields = [
			'description',
			'children',
			'http_status',
			'title',
		]

	def get_description(self, subdomain):
		return subdomain.name

	def get_title(self, subdomain):
		if get_interesting_subdomains(subdomain.scan_history.id).filter(name=subdomain.name).exists():
			return "Interesting"

	def get_children(self, subdomain_name):
		scan_history = self.context.get('scan_history')
		subdomains = (
			Subdomain.objects
			.filter(scan_history=scan_history)
			.filter(name=subdomain_name)
		)

		ips = IpAddress.objects.filter(ip_addresses__in=subdomains)
		ip_serializer = VisualiseIpSerializer(
			ips, 
			many=True,
			context={'scan_id': scan_history.id}
		)

		# endpoint = EndPoint.objects.filter(
		#     scan_history=self.context.get('scan_history')).filter(
		#     subdomain__name=subdomain_name)
		# endpoint_serializer = VisualiseEndpointSerializer(endpoint, many=True)

		technologies = Technology.objects.filter(technologies__in=subdomains)
		tech_serializer = VisualiseTechnologySerializer(technologies, many=True)

		vulnerability = (
			Vulnerability.objects
			.filter(scan_history=scan_history)
			.filter(subdomain=subdomain_name)
		)

		return_data = []
		if ip_serializer.data:
			return_data.append({
				'description': 'IPs',
				'children': ip_serializer.data
			})
		# if endpoint_serializer.data:
		#     return_data.append({
		#         'description': 'Endpoints',
		#         'children': endpoint_serializer.data
		#     })
		if tech_serializer.data:
			return_data.append({
				'description': 'Technologies',
				'children': tech_serializer.data
			})

		if vulnerability:
			vulnerability_data = []
			critical = vulnerability.filter(severity=4)
			if critical:
				critical_serializer = VisualiseVulnerabilitySerializer(
					critical,
					many=True
				)
				vulnerability_data.append({
					'description': 'Critical',
					'children': critical_serializer.data
				})
			high = vulnerability.filter(severity=3)
			if high:
				high_serializer = VisualiseVulnerabilitySerializer(
					high,
					many=True
				)
				vulnerability_data.append({
					'description': 'High',
					'children': high_serializer.data
				})
			medium = vulnerability.filter(severity=2)
			if medium:
				medium_serializer = VisualiseVulnerabilitySerializer(
					medium,
					many=True
				)
				vulnerability_data.append({
					'description': 'Medium',
					'children': medium_serializer.data
				})
			low = vulnerability.filter(severity=1)
			if low:
				low_serializer = VisualiseVulnerabilitySerializer(
					low,
					many=True
				)
				vulnerability_data.append({
					'description': 'Low',
					'children': low_serializer.data
				})
			info = vulnerability.filter(severity=0)
			if info:
				info_serializer = VisualiseVulnerabilitySerializer(
					info,
					many=True
				)
				vulnerability_data.append({
					'description': 'Informational',
					'children': info_serializer.data
				})
			uknown = vulnerability.filter(severity=-1)
			if uknown:
				uknown_serializer = VisualiseVulnerabilitySerializer(
					uknown,
					many=True
				)
				vulnerability_data.append({
					'description': 'Unknown',
					'children': uknown_serializer.data
				})

			if vulnerability_data:
				return_data.append({
					'description': 'Vulnerabilities',
					'children': vulnerability_data
				})

		if subdomain_name.screenshot_path:
			return_data.append({
				'description': 'Screenshot',
				'screenshot_path': subdomain_name.screenshot_path
			})
		return return_data


class VisualiseEmailSerializer(serializers.ModelSerializer):
	title = serializers.SerializerMethodField('get_title')
	description = serializers.SerializerMethodField('get_description')

	class Meta:
		model = Email
		fields = [
			'description',
			'password',
			'title'
		]

	def get_description(self, email):
		if email.password:
			return email.address + " > " + email.password
		return email.address

	def get_title(self, email):
		if email.password:
			return "Exposed Creds"


class VisualiseDorkSerializer(serializers.ModelSerializer):

	title = serializers.SerializerMethodField('get_title')
	description = serializers.SerializerMethodField('get_description')
	http_url = serializers.SerializerMethodField('get_http_url')

	class Meta:
		model = Dork
		fields = [
			'title',
			'description',
			'http_url'
		]

	def get_title(self, dork):
		return dork.type

	def get_description(self, dork):
		return dork.type

	def get_http_url(self, dork):
		return dork.url


class VisualiseEmployeeSerializer(serializers.ModelSerializer):

	description = serializers.SerializerMethodField('get_description')

	class Meta:
		model = Employee
		fields = [
			'description'
		]

	def get_description(self, employee):
		if employee.designation:
			return employee.name + '--' + employee.designation
		return employee.name


class VisualiseDataSerializer(serializers.ModelSerializer):

	title = serializers.ReadOnlyField(default='Target')
	description = serializers.SerializerMethodField('get_description')
	children = serializers.SerializerMethodField('get_children')

	class Meta:
		model = ScanHistory
		fields = [
			'description',
			'title',
			'children',
		]

	def get_description(self, scan_history):
		return scan_history.domain.name

	def get_children(self, history):
		scan_history = ScanHistory.objects.filter(id=history.id)

		subdomain = Subdomain.objects.filter(scan_history=history)
		subdomain_serializer = VisualiseSubdomainSerializer(
			subdomain,
			many=True,
			context={'scan_history': history})

		processed_subdomains = self.process_subdomains(subdomain_serializer.data)

		email = Email.objects.filter(emails__in=scan_history)
		email_serializer = VisualiseEmailSerializer(email, many=True)

		dork = Dork.objects.filter(dorks__in=scan_history)
		dork_serializer = VisualiseDorkSerializer(dork, many=True)
		processed_dorks = self.process_dorks(dork_serializer.data)

		employee = Employee.objects.filter(employees__in=scan_history)
		employee_serializer = VisualiseEmployeeSerializer(employee, many=True)

		metainfo = MetaFinderDocument.objects.filter(
			scan_history__id=history.id)

		return_data = []

		if processed_subdomains:
			return_data.append({
				'description': 'Subdomains',
				'children': processed_subdomains})

		osint_data = []
		if email_serializer.data:
			osint_data.append({
				'description': 'Emails',
				'children': email_serializer.data})
		if employee_serializer.data:
			osint_data.append({
				'description': 'Employees',
				'children': employee_serializer.data})
		if processed_dorks:
			osint_data.append({
				'description': 'Dorks',
				'children': processed_dorks})

		if metainfo:
			metainfo_data = []
			usernames = (
				metainfo
				.annotate(description=F('author'))
				.values('description')
				.distinct()
				.annotate(children=Value([], output_field=JSONField()))
				.filter(author__isnull=False)
			)

			if usernames:
				metainfo_data.append({
					'description': 'Usernames',
					'children': usernames})

			software = (
				metainfo
				.annotate(description=F('producer'))
				.values('description')
				.distinct()
				.annotate(children=Value([], output_field=JSONField()))
				.filter(producer__isnull=False)
			)

			if software:
				metainfo_data.append({
					'description': 'Software',
					'children': software})

			os = (
				metainfo
				.annotate(description=F('os'))
				.values('description')
				.distinct()
				.annotate(children=Value([], output_field=JSONField()))
				.filter(os__isnull=False)
			)

			if os:
				metainfo_data.append({
					'description': 'OS',
					'children': os})

			if metainfo:
				osint_data.append({
					'description':'Metainfo',
					'children': metainfo_data})

			return_data.append({
				'description':'OSINT',
				'children': osint_data})

		if osint_data:
			return_data.append({
				'description':'OSINT',
				'children': osint_data})

		return return_data

	def process_subdomains(self, subdomains):
		for subdomain in subdomains:
			if 'children' in subdomain:
				vuln_dict = defaultdict(list)
				for child in subdomain['children']:
					if child.get('description') == 'Vulnerabilities':
						for vuln_severity in child['children']:
							severity = vuln_severity['description']
							for vuln in vuln_severity['children']:
								vuln_key = (vuln['description'], severity)
								if vuln_key not in vuln_dict:
									vuln_dict[vuln_key] = vuln

				# Reconstruct vulnerabilities structure without duplicates
				new_vuln_structure = []
				for severity in ['Critical', 'High', 'Medium', 'Low', 'Informational', 'Unknown']:
					severity_vulns = [v for k, v in vuln_dict.items() if k[1] == severity]
					if severity_vulns:
						new_vuln_structure.append({
							'description': severity,
							'children': severity_vulns
						})

				# Replace old structure with new
				subdomain['children'] = [child for child in subdomain['children'] if child.get('description') != 'Vulnerabilities']
				if new_vuln_structure:
					subdomain['children'].append({
						'description': 'Vulnerabilities',
						'children': new_vuln_structure
					})

		return subdomains
	
	def process_dorks(self, dorks):
		unique_dorks = {}
		for dork in dorks:
			dork_key = (dork['description'], dork.get('dork_type', ''))
			if dork_key not in unique_dorks:
				unique_dorks[dork_key] = dork

		return list(unique_dorks.values())

class SubdomainChangesSerializer(serializers.ModelSerializer):

	change = serializers.SerializerMethodField('get_change')
	is_interesting = serializers.SerializerMethodField('get_is_interesting')

	class Meta:
		model = Subdomain
		fields = '__all__'

	def get_change(self, Subdomain):
		return Subdomain.change

	def get_is_interesting(self, Subdomain):
		return (
			get_interesting_subdomains(Subdomain.scan_history.id)
			.filter(name=Subdomain.name)
			.exists()
		)


class EndPointChangesSerializer(serializers.ModelSerializer):

	change = serializers.SerializerMethodField('get_change')

	class Meta:
		model = EndPoint
		fields = '__all__'

	def get_change(self, EndPoint):
		return EndPoint.change


class InterestingSubdomainSerializer(serializers.ModelSerializer):

	class Meta:
		model = Subdomain
		fields = ['name']


class EmailSerializer(serializers.ModelSerializer):

	class Meta:
		model = Email
		fields = '__all__'


class DorkSerializer(serializers.ModelSerializer):

	class Meta:
		model = Dork
		fields = '__all__'


class EmployeeSerializer(serializers.ModelSerializer):
	class Meta:
		model = Employee
		fields = '__all__'


class MetafinderDocumentSerializer(serializers.ModelSerializer):

	class Meta:
		model = MetaFinderDocument
		fields = '__all__'
		depth = 1


class MetafinderUserSerializer(serializers.ModelSerializer):

	class Meta:
		model = MetaFinderDocument
		fields = ['author']


class InterestingEndPointSerializer(serializers.ModelSerializer):

	class Meta:
		model = EndPoint
		fields = ['http_url']


class TechnologyCountSerializer(serializers.Serializer):
	count = serializers.CharField()
	name = serializers.CharField()


class DorkCountSerializer(serializers.Serializer):
	count = serializers.CharField()
	type = serializers.CharField()


class TechnologySerializer(serializers.ModelSerializer):
	class Meta:
		model = Technology
		fields = '__all__'


class PortSerializer(serializers.ModelSerializer):
	class Meta:
		model = Port
		fields = '__all__'


class IpSerializer(serializers.ModelSerializer):
    ports = PortSerializer(many=True)
    subdomain_count = serializers.SerializerMethodField()
    subdomain_names = serializers.SerializerMethodField()

    class Meta:
        model = IpAddress
        fields = '__all__'

    def get_base_subdomain_query(self, obj):
        query = Subdomain.objects.filter(ip_addresses=obj)
        scan_id = self.context.get('scan_id')
        target_id = self.context.get('target_id')
        
        if scan_id:
            query = query.filter(scan_history_id=scan_id)
        elif target_id:
            query = query.filter(target_domain_id=target_id)
            
        return query.distinct('name')

    def get_subdomain_count(self, obj):
        return self.get_base_subdomain_query(obj).count()

    def get_subdomain_names(self, obj):
        return list(self.get_base_subdomain_query(obj).values_list('name', flat=True))


class DirectoryFileSerializer(serializers.ModelSerializer):

	class Meta:
		model = DirectoryFile
		fields = '__all__'


class DirectoryScanSerializer(serializers.ModelSerializer):
	scanned_date = serializers.SerializerMethodField()
	formatted_date_for_id = serializers.SerializerMethodField()
	directory_files = DirectoryFileSerializer(many=True)

	class Meta:
		model = DirectoryScan
		fields = '__all__'

	def get_scanned_date(self, DirectoryScan):
		return DirectoryScan.scanned_date.strftime("%b %d, %Y %H:%M")

	def get_formatted_date_for_id(self, DirectoryScan):
		return DirectoryScan.scanned_date.strftime("%b_%d_%Y_%H_%M")


class IpSubdomainSerializer(serializers.ModelSerializer):

	class Meta:
		model = Subdomain
		fields = ['name', 'ip_addresses']
		depth = 1

class WafSerializer(serializers.ModelSerializer):

	class Meta:
		model = Waf
		fields = '__all__'


class SubdomainSerializer(serializers.ModelSerializer):

	vuln_count = serializers.SerializerMethodField('get_vuln_count')

	is_interesting = serializers.SerializerMethodField('get_is_interesting')

	endpoint_count = serializers.SerializerMethodField('get_endpoint_count')
	info_count = serializers.SerializerMethodField('get_info_count')
	low_count = serializers.SerializerMethodField('get_low_count')
	medium_count = serializers.SerializerMethodField('get_medium_count')
	high_count = serializers.SerializerMethodField('get_high_count')
	critical_count = serializers.SerializerMethodField('get_critical_count')
	todos_count = serializers.SerializerMethodField('get_todos_count')
	directories_count = serializers.SerializerMethodField('get_directories_count')
	subscan_count = serializers.SerializerMethodField('get_subscan_count')
	ip_addresses = IpSerializer(many=True)
	waf = WafSerializer(many=True)
	technologies = TechnologySerializer(many=True)
	directories = DirectoryScanSerializer(many=True)


	class Meta:
		model = Subdomain
		fields = '__all__'

	def get_is_interesting(self, subdomain):
		scan_id = subdomain.scan_history.id if subdomain.scan_history else None
		return (
			get_interesting_subdomains(scan_id)
			.filter(name=subdomain.name)
			.exists()
		)

	def get_endpoint_count(self, subdomain):
		return subdomain.get_endpoint_count

	def get_info_count(self, subdomain):
		return subdomain.get_info_count

	def get_low_count(self, subdomain):
		return subdomain.get_low_count

	def get_medium_count(self, subdomain):
		return subdomain.get_medium_count

	def get_high_count(self, subdomain):
		return subdomain.get_high_count

	def get_critical_count(self, subdomain):
		return subdomain.get_critical_count

	def get_directories_count(self, subdomain):
		return subdomain.get_directories_count

	def get_subscan_count(self, subdomain):
		return subdomain.get_subscan_count

	def get_todos_count(self, subdomain):
		return len(subdomain.get_todos.filter(is_done=False))

	def get_vuln_count(self, obj):
		try:
			return obj.vuln_count
		except:
			return None


class EndpointSerializer(serializers.ModelSerializer):

	techs = TechnologySerializer(many=True)

	class Meta:
		model = EndPoint
		fields = '__all__'


class EndpointOnlyURLsSerializer(serializers.ModelSerializer):

	class Meta:
		model = EndPoint
		fields = ['http_url']


class VulnerabilitySerializer(serializers.ModelSerializer):

	discovered_date = serializers.SerializerMethodField()
	severity = serializers.SerializerMethodField()

	def get_discovered_date(self, Vulnerability):
		return Vulnerability.discovered_date.strftime("%b %d, %Y %H:%M")

	def get_severity(self, Vulnerability):
		if Vulnerability.severity == 0:
			return "Info"
		elif Vulnerability.severity == 1:
			return "Low"
		elif Vulnerability.severity == 2:
			return "Medium"
		elif Vulnerability.severity == 3:
			return "High"
		elif Vulnerability.severity == 4:
			return "Critical"
		elif Vulnerability.severity == -1:
			return "Unknown"
		else:
			return "Unknown"

	class Meta:
		model = Vulnerability
		fields = '__all__'
		depth = 2

class ProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project
        fields = ['id', 'name', 'slug', 'description', 'insert_date']
