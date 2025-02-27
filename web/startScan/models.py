from urllib.parse import urlparse
from django.apps import apps
from django.contrib.auth.models import User
from django.contrib.postgres.fields import ArrayField
from django.db import models
from django.db.models import Count, Q
from django.db.models.functions import TruncDay
from datetime import datetime
from django.utils import timezone
from reNgine.definitions import (CELERY_TASK_STATUSES,
								 NUCLEI_REVERSE_SEVERITY_MAP,
								 ENGINE_DISPLAY_NAMES)
from scanEngine.models import EngineType
from targetApp.models import Domain
from reNgine.utils.utils import get_time_taken


class hybrid_property:
	def __init__(self, func):
		self.func = func
		self.name = func.__name__
		self.exp = None

	def __get__(self, instance, owner):
		return self if instance is None else self.func(instance)

	def __set__(self, instance, value):
		pass

	def expression(self, exp):
		self.exp = exp
		return self


class ScanHistory(models.Model):
	id = models.AutoField(primary_key=True)
	start_scan_date = models.DateTimeField()
	scan_status = models.IntegerField(choices=CELERY_TASK_STATUSES, default=-1)
	results_dir = models.CharField(max_length=100, blank=True)
	domain = models.ForeignKey(Domain, on_delete=models.CASCADE)
	scan_type = models.ForeignKey(EngineType, on_delete=models.CASCADE)
	celery_ids = ArrayField(models.CharField(max_length=100), blank=True, default=list)
	tasks = ArrayField(models.CharField(max_length=200), null=True)
	stop_scan_date = models.DateTimeField(null=True, blank=True)
	used_gf_patterns = models.CharField(max_length=500, null=True, blank=True)
	error_message = models.CharField(max_length=300, blank=True, null=True)
	emails = models.ManyToManyField('Email', related_name='emails', blank=True)
	employees = models.ManyToManyField('Employee', related_name='employees', blank=True)
	buckets = models.ManyToManyField('S3Bucket', related_name='buckets', blank=True)
	dorks = models.ManyToManyField('Dork', related_name='dorks', blank=True)
	initiated_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='initiated_scans', blank=True, null=True)
	aborted_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='aborted_scans')


	def __str__(self):
		return self.domain.name

	def get_subdomain_count(self):
		return Subdomain.objects.filter(scan_history__id=self.id).count()

	def get_subdomain_change_count(self):
		last_scan = (
			ScanHistory.objects
			.filter(id=self.id)
			.filter(tasks__overlap=['subdomain_discovery'])
			.order_by('-start_scan_date')
		)
		scanned_host_q1 = (
			Subdomain.objects
			.filter(target_domain__id=self.domain.id)
			.exclude(scan_history__id=last_scan[0].id)
			.values('name')
		)
		scanned_host_q2 = (
			Subdomain.objects
			.filter(scan_history__id=last_scan[0].id)
			.values('name')
		)
		new_subdomains = scanned_host_q2.difference(scanned_host_q1).count()
		removed_subdomains = scanned_host_q1.difference(scanned_host_q2).count()
		return [new_subdomains, removed_subdomains]


	def get_endpoint_count(self):
		return (
			EndPoint.objects
			.filter(scan_history__id=self.id)
			.count()
		)

	def get_vulnerability_count(self):
		return (
			Vulnerability.objects
			.filter(scan_history__id=self.id)
			.count()
		)

	def get_unknown_vulnerability_count(self):
		return (
			Vulnerability.objects
			.filter(scan_history__id=self.id)
			.filter(severity=-1)
			.count()
		)

	def get_info_vulnerability_count(self):
		return (
			Vulnerability.objects
			.filter(scan_history__id=self.id)
			.filter(severity=0)
			.count()
		)

	def get_low_vulnerability_count(self):
		return (
			Vulnerability.objects
			.filter(scan_history__id=self.id)
			.filter(severity=1)
			.count()
		)

	def get_medium_vulnerability_count(self):
		return (
			Vulnerability.objects
			.filter(scan_history__id=self.id)
			.filter(severity=2)
			.count()
		)

	def get_high_vulnerability_count(self):
		return (
			Vulnerability.objects
			.filter(scan_history__id=self.id)
			.filter(severity=3)
			.count()
		)

	def get_critical_vulnerability_count(self):
		return (
			Vulnerability.objects
			.filter(scan_history__id=self.id)
			.filter(severity=4)
			.count()
		)

	def get_progress(self):
		"""Formulae to calculate count number of true things to do, for http
		crawler, it is always +1 divided by total scan activity associated - 2
		(start and stop).
		"""
		number_of_steps = len(self.tasks) if self.tasks else 0
		steps_done = len(self.scanactivity_set.all())
		if steps_done and number_of_steps:
			return round((number_of_steps / (steps_done)) * 100, 2)

	def get_completed_ago(self):
		if self.stop_scan_date:
			return self.get_time_ago(self.stop_scan_date)

	def get_total_scan_time_in_sec(self):
		if self.stop_scan_date:
			return (self.stop_scan_date - self.start_scan_date).seconds

	def get_elapsed_time(self):
		return self.get_time_ago(self.start_scan_date)

	def get_time_ago(self, time):
		duration = timezone.now() - time
		days, seconds = duration.days, duration.seconds
		hours = days * 24 + seconds // 3600
		minutes = (seconds % 3600) // 60
		seconds = seconds % 60
		if not hours and not minutes:
			return f'{seconds} seconds'
		elif not hours:
			return f'{minutes} minutes'
		elif not minutes:
			return f'{hours} hours'
		return f'{hours} hours {minutes} minutes'
	
	@classmethod
	def get_all_counts(cls, queryset):
		"""Aggregate total scans and status distribution"""
		return queryset.aggregate(
			total=Count('id'),
			pending=Count('id', filter=models.Q(scan_status=0)),
			running=Count('id', filter=models.Q(scan_status=1)),
			completed=Count('id', filter=models.Q(scan_status=2)),
			failed=Count('id', filter=models.Q(scan_status=3))
		)

	@classmethod
	def get_project_counts(cls, project):
		"""Get scan statistics for a specific project"""
		return cls.get_all_counts(
			cls.objects.filter(domain__project=project)
		)

	@staticmethod
	def get_counts_by_date(queryset, date_field, since_date):
		"""Get daily scan counts for a queryset"""
		counts = queryset.filter(
			**{f"{date_field}__gte": since_date}
		).annotate(
			date=TruncDay(date_field)
		).values("date").annotate(
			count=Count('id')
		).order_by("date")
		
		return {item['date']: item['count'] for item in counts}

	@classmethod
	def get_project_timeline(cls, project, date_range, status=None):
		"""Get scan timeline data with optional status filter"""
		queryset = cls.objects.filter(domain__project=project)
		
		if status is not None:
			queryset = queryset.filter(scan_status=status)
		
		raw_data = cls.get_counts_by_date(
			queryset,
			'start_scan_date',
			date_range[0]
		)
		
		results = []
		for date in date_range:
			aware_date = timezone.make_aware(datetime.combine(date, datetime.min.time()))
			results.append(raw_data.get(aware_date, 0))
		
		return results[::-1]

class Subdomain(models.Model):
	# TODO: Add endpoint property instead of replicating endpoint fields here
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
	target_domain = models.ForeignKey(Domain, on_delete=models.CASCADE, null=True, blank=True)
	name = models.CharField(max_length=1000)
	is_imported_subdomain = models.BooleanField(default=False)
	is_important = models.BooleanField(default=False, null=True, blank=True)
	http_url = models.CharField(max_length=10000, null=True, blank=True)
	screenshot_path = models.CharField(max_length=1000, null=True, blank=True)
	http_header_path = models.CharField(max_length=1000, null=True, blank=True)
	discovered_date = models.DateTimeField(blank=True, null=True)
	cname = models.CharField(max_length=5000, blank=True, null=True)
	is_cdn = models.BooleanField(default=False, blank=True, null=True)
	cdn_name = models.CharField(max_length=200, blank=True, null=True)
	http_status = models.IntegerField(default=0)
	content_type = models.CharField(max_length=100, null=True, blank=True)
	response_time = models.FloatField(null=True, blank=True)
	webserver = models.CharField(max_length=1000, blank=True, null=True)
	content_length = models.IntegerField(default=0, blank=True, null=True)
	page_title = models.CharField(max_length=1000, blank=True, null=True)
	technologies = models.ManyToManyField('Technology', related_name='technologies', blank=True)
	ip_addresses = models.ManyToManyField('IPAddress', related_name='ip_addresses', blank=True)
	directories = models.ManyToManyField('DirectoryScan', related_name='directories', blank=True)
	waf = models.ManyToManyField('Waf', related_name='waf', blank=True)
	attack_surface = models.TextField(null=True, blank=True)


	def __str__(self):
		return str(self.name)

	@property
	def get_endpoint_count(self):
		endpoints = EndPoint.objects.filter(subdomain__name=self.name)
		if self.scan_history:
			endpoints = endpoints.filter(scan_history=self.scan_history)
		return endpoints.count()

	@property
	def get_unknown_vulnerability_count(self):
		return (
			self.get_vulnerabilities
			.filter(severity=-1)
			.count()
		)

	@property
	def get_info_count(self):
		return (
			self.get_vulnerabilities
			.filter(severity=0)
			.count()
		)

	@property
	def get_low_count(self):
		return (
			self.get_vulnerabilities
			.filter(severity=1)
			.count()
		)

	@property
	def get_medium_count(self):
		return (
			self.get_vulnerabilities
			.filter(severity=2)
			.count()
		)

	@property
	def get_high_count(self):
		return (
			self.get_vulnerabilities
			.filter(severity=3)
			.count()
		)

	@property
	def get_critical_count(self):
		return (
			self.get_vulnerabilities
			.filter(severity=4)
			.count()
		)

	@property
	def get_total_vulnerability_count(self):
		return self.get_vulnerabilities.count()

	@property
	def get_vulnerabilities(self):
		vulns = Vulnerability.objects.filter(subdomain__name=self.name)
		if self.scan_history:
			vulns = vulns.filter(scan_history=self.scan_history)
		return vulns

	@property
	def get_vulnerabilities_without_info(self):
		vulns = Vulnerability.objects.filter(subdomain__name=self.name).exclude(severity=0)
		if self.scan_history:
			vulns = vulns.filter(scan_history=self.scan_history)
		return vulns

	@property
	def get_directories_count(self):
		subdomains = (
			Subdomain.objects
			.filter(id=self.id)
		)
		dirscan = (
			DirectoryScan.objects
			.filter(directories__in=subdomains)
		)
		return (
			DirectoryFile.objects
			.filter(directory_files__in=dirscan)
			.distinct()
			.count()
		)

	@property
	def get_todos(self):
		TodoNote = apps.get_model('recon_note', 'TodoNote')
		notes = TodoNote.objects
		if self.scan_history:
			notes = notes.filter(scan_history=self.scan_history)
		notes = notes.filter(subdomain__id=self.id)
		return notes.values()

	@property
	def get_subscan_count(self):
		return (
			SubScan.objects
			.filter(subdomain__id=self.id)
			.distinct()
			.count()
		)

	@property
	def get_ports(self):
		"""Get all ports associated with this subdomain's IP addresses"""
		ports = []
		for ip in self.ip_addresses.all():
			ports.extend(port.number for port in ip.ports.all())
		return sorted(list(set(ports)))

	@property
	def get_ports_by_ip(self):
		"""Get ports grouped by IP address with their specific service information"""
		return {
			ip.address: {
				'ports': [
					{
						'number': port.number,
						'service_name': port.service_name,
						'description': port.description,
						'is_uncommon': port.is_uncommon,
					}
					for port in ip.ports.all().order_by('number')
				],
				'is_cdn': ip.is_cdn,
			}
			for ip in self.ip_addresses.all()
		}

	@classmethod
	def get_counts(cls, queryset):
		"""Get various subdomain counts in a single query"""
		return {
			'total': queryset.count(),
			'with_ip': queryset.filter(ip_addresses__isnull=False).count(),
			'alive': queryset.exclude(http_status__exact=0).count()
		}

	@classmethod
	def get_all_counts(cls, queryset):
		"""Get all vulnerability counts in a single query"""
		# Get base counts first
		base_counts = queryset.aggregate(
			total=Count('id'),
			with_ip=Count('id', filter=Q(ip_addresses__isnull=False)),
			alive=Count('id', filter=~Q(http_status=0))
		)
		
		# Initialize vulnerability counts
		vuln_counts = {
			'vuln_info': 0,
			'vuln_low': 0,
			'vuln_medium': 0,
			'vuln_high': 0,
			'vuln_critical': 0,
			'vuln_unknown': 0
		}

		# Count vulnerabilities for each subdomain
		for subdomain in queryset.all():
			vuln_counts['vuln_info'] += subdomain.get_info_count
			vuln_counts['vuln_low'] += subdomain.get_low_count
			vuln_counts['vuln_medium'] += subdomain.get_medium_count
			vuln_counts['vuln_high'] += subdomain.get_high_count
			vuln_counts['vuln_critical'] += subdomain.get_critical_count
			vuln_counts['vuln_unknown'] += subdomain.get_unknown_vulnerability_count
		
		# Combine and calculate totals
		return {
			**base_counts,
			**vuln_counts,
			'total_vuln_count': sum(vuln_counts.values()),
			'total_vuln_ignore_info_count': sum([
				vuln_counts['vuln_low'],
				vuln_counts['vuln_medium'],
				vuln_counts['vuln_high'],
				vuln_counts['vuln_critical']
			])
		}


	@classmethod
	def get_project_counts(cls, project):
		"""Get all counts for a specific project in a single query"""
		queryset = cls.objects.filter(target_domain__project=project)
		return cls.get_all_counts(queryset)

	@staticmethod
	def get_counts_by_date(queryset, date_field, since_date):
		"""Get daily subdomain counts for a queryset"""
		counts = queryset.filter(
			**{f"{date_field}__gte": since_date}
		).annotate(
			date=TruncDay(date_field)
		).values("date").annotate(
			count=Count('id')
		).order_by("date")
		
		return {item['date']: item['count'] for item in counts}

	@classmethod
	def get_project_timeline(cls, project, date_range):
		"""Get subdomain timeline data for a specific project"""
		raw_data = cls.get_counts_by_date(
			cls.objects.filter(scan_history__domain__project=project),
			'discovered_date',
			date_range[0]
		)
		
		results = []
		for date in date_range:
			aware_date = timezone.make_aware(datetime.combine(date, datetime.min.time()))
			results.append(raw_data.get(aware_date, 0))
		
		return results[::-1]

class SubScan(models.Model):
	id = models.AutoField(primary_key=True)
	type = models.CharField(max_length=100, blank=True, null=True)
	start_scan_date = models.DateTimeField()
	status = models.IntegerField()
	celery_ids = ArrayField(models.CharField(max_length=100), blank=True, default=list)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE)
	subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE)
	stop_scan_date = models.DateTimeField(null=True, blank=True)
	error_message = models.CharField(max_length=300, blank=True, null=True)
	engine = models.ForeignKey(EngineType, on_delete=models.CASCADE, blank=True, null=True)
	subdomain_subscan_ids = models.ManyToManyField('Subdomain', related_name='subdomain_subscan_ids', blank=True)

	def get_completed_ago(self):
		if self.stop_scan_date:
			return get_time_taken(timezone.now(), self.stop_scan_date)

	def get_total_time_taken(self):
		if self.stop_scan_date:
			return get_time_taken(self.stop_scan_date, self.start_scan_date)

	def get_elapsed_time(self):
		return get_time_taken(timezone.now(), self.start_scan_date)

	def get_task_name_str(self):
		return dict(ENGINE_DISPLAY_NAMES).get(self.type, 'Unknown')

	@classmethod
	def get_all_counts(cls, queryset):
		"""Aggregate total subscans and status distribution"""
		return queryset.aggregate(
			total=Count('id'),
			pending=Count('id', filter=models.Q(status=0)),
			running=Count('id', filter=models.Q(status=1)),
			completed=Count('id', filter=models.Q(status=2)),
			failed=Count('id', filter=models.Q(status=3))
		)

	@classmethod
	def get_project_counts(cls, project):
		"""Get subscan statistics for a specific project"""
		return cls.get_all_counts(
			cls.objects.filter(
				scan_history__domain__project=project
			)
		)

	@staticmethod
	def get_counts_by_date(queryset, date_field, since_date):
		"""Get daily subscan counts for a queryset"""
		counts = queryset.filter(
			**{f"{date_field}__gte": since_date}
		).annotate(
			date=TruncDay(date_field)
		).values("date").annotate(
			count=Count('id')
		).order_by("date")
		
		return {item['date']: item['count'] for item in counts}

	@classmethod
	def get_project_timeline(cls, project, date_range, status=None):
		"""Get subscan timeline data with optional status filter"""
		queryset = cls.objects.filter(scan_history__domain__project=project)
		
		if status is not None:
			queryset = queryset.filter(status=status)
		
		raw_data = cls.get_counts_by_date(
			queryset,
			'start_scan_date',
			date_range[0]
		)
		
		results = []
		for date in date_range:
			aware_date = timezone.make_aware(datetime.combine(date, datetime.min.time()))
			results.append(raw_data.get(aware_date, 0))
		
		return results[::-1]

class EndPoint(models.Model):
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
	target_domain = models.ForeignKey(
		Domain, on_delete=models.CASCADE, null=True, blank=True)
	subdomain = models.ForeignKey(
		Subdomain,
		on_delete=models.CASCADE,
		null=True,
		blank=True)
	source = models.CharField(max_length=200, null=True, blank=True)
	http_url = models.CharField(max_length=30000)
	content_length = models.IntegerField(default=0, null=True, blank=True)
	page_title = models.CharField(max_length=30000, null=True, blank=True)
	http_status = models.IntegerField(default=0, null=True, blank=True)
	content_type = models.CharField(max_length=100, null=True, blank=True)
	discovered_date = models.DateTimeField(blank=True, null=True)
	response_time = models.FloatField(null=True, blank=True)
	webserver = models.CharField(max_length=1000, blank=True, null=True)
	is_default = models.BooleanField(null=True, blank=True, default=False)
	matched_gf_patterns = models.CharField(max_length=10000, null=True, blank=True)
	techs = models.ManyToManyField('Technology', related_name='techs', blank=True)
	# used for subscans
	endpoint_subscan_ids = models.ManyToManyField('SubScan', related_name='endpoint_subscan_ids', blank=True)

	def __str__(self):
		return self.http_url

	@hybrid_property
	def is_alive(self):
		return self.http_status

	@classmethod
	def get_counts(cls, queryset):
		"""Get endpoint counts in a single query"""
		return {
			'total': queryset.count(),
			'alive': queryset.filter(http_status__gt=0).count()
		}

	@classmethod
	def get_project_counts(cls, project):
		"""Get endpoint counts for a specific project"""
		queryset = cls.objects.filter(scan_history__domain__project=project)
		return cls.get_counts(queryset)

	@staticmethod
	def get_counts_by_date(queryset, date_field, since_date):
		"""Get daily vulnerability counts for a queryset"""
		counts = queryset.filter(
			**{f"{date_field}__gte": since_date}
		).annotate(
			date=TruncDay(date_field)
		).values("date").annotate(
			count=Count('id')
		).order_by("date")
		
		return {item['date']: item['count'] for item in counts}

	@classmethod
	def get_project_timeline(cls, project, date_range):
		"""Get vulnerability timeline data for a specific project"""
		raw_data = cls.get_counts_by_date(
			cls.objects.filter(scan_history__domain__project=project),
			'discovered_date',
			date_range[0]
		)
		
		results = []
		for date in date_range:
			aware_date = timezone.make_aware(datetime.combine(date, datetime.min.time()))
			results.append(raw_data.get(aware_date, 0))
		
		return results[::-1]

class VulnerabilityTags(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=100)

	def __str__(self):
		return self.name

	@classmethod
	def get_most_common(cls, vulnerabilities, limit=7):
		"""Get most common vulnerability tags"""
		return cls.objects.filter(
			vuln_tags__in=vulnerabilities
		).values(
			'name'
		).distinct().annotate(
			nused=Count('vuln_tags', filter=Q(vuln_tags__in=vulnerabilities))
		).order_by('-nused')[:limit]


class VulnerabilityReference(models.Model):
	id = models.AutoField(primary_key=True)
	url = models.CharField(max_length=5000)

	def __str__(self):
		return self.url


class CveId(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=100)

	def __str__(self):
		return self.name

	@classmethod
	def get_most_common(cls, vulnerabilities, limit=7):
		"""Get most common CVEs in vulnerabilities"""
		return cls.objects.filter(
			cve_ids__in=vulnerabilities
		).values(
			'name'
		).distinct().annotate(
			nused=Count('cve_ids', filter=Q(cve_ids__in=vulnerabilities))
		).order_by('-nused')[:limit]


class CweId(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=100)

	def __str__(self):
		return self.name

	@classmethod
	def get_most_common(cls, vulnerabilities, limit=7):
		"""Get most common CWEs in vulnerabilities"""
		return cls.objects.filter(
			cwe_ids__in=vulnerabilities
		).values(
			'name'
		).distinct().annotate(
			nused=Count('cwe_ids', filter=Q(cwe_ids__in=vulnerabilities))
		).order_by('-nused')[:limit]


class GPTVulnerabilityReport(models.Model):
	url_path = models.CharField(max_length=2000)
	title = models.CharField(max_length=2500)
	description = models.TextField(null=True, blank=True)
	impact = models.TextField(null=True, blank=True)
	remediation = models.TextField(null=True, blank=True)
	references = models.ManyToManyField('VulnerabilityReference', related_name='report_reference', blank=True)

	def __str__(self):
		return self.title


class Vulnerability(models.Model):
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
	source = models.CharField(max_length=200, null=True, blank=True)
	subdomain = models.ForeignKey(
		Subdomain,
		on_delete=models.CASCADE,
		null=True,
		blank=True)
	endpoint = models.ForeignKey(
		EndPoint,
		on_delete=models.CASCADE,
		blank=True,
		null=True)
	target_domain = models.ForeignKey(
		Domain, on_delete=models.CASCADE, null=True, blank=True)
	template = models.CharField(max_length=100, null=True, blank=True)
	template_url = models.CharField(max_length=2500, null=True, blank=True)
	template_id = models.CharField(max_length=200, null=True, blank=True)
	matcher_name = models.CharField(max_length=500, null=True, blank=True)
	name = models.CharField(max_length=2500)
	severity = models.IntegerField()
	description = models.TextField(null=True, blank=True)
	impact = models.TextField(null=True, blank=True)
	remediation = models.TextField(null=True, blank=True)

	extracted_results = ArrayField(
		models.CharField(max_length=5000), blank=True, null=True
	)

	tags = models.ManyToManyField('VulnerabilityTags', related_name='vuln_tags', blank=True)
	references = models.ManyToManyField('VulnerabilityReference', related_name='vuln_reference', blank=True)
	cve_ids = models.ManyToManyField('CveId', related_name='cve_ids', blank=True)
	cwe_ids = models.ManyToManyField('CweId', related_name='cwe_ids', blank=True)

	cvss_metrics = models.CharField(max_length=500, null=True, blank=True)
	cvss_score = models.FloatField(null=True, blank=True, default=None)
	curl_command = models.CharField(max_length=15000, null=True, blank=True)
	type = models.CharField(max_length=100, null=True, blank=True)
	http_url = models.CharField(max_length=10000, null=True)
	discovered_date = models.DateTimeField(null=True)
	open_status = models.BooleanField(null=True, blank=True, default=True)
	hackerone_report_id = models.CharField(max_length=50, null=True, blank=True)
	request = models.TextField(blank=True, null=True)
	response = models.TextField(blank=True, null=True)
	is_gpt_used = models.BooleanField(null=True, blank=True, default=False)
	# used for subscans
	vuln_subscan_ids = models.ManyToManyField('SubScan', related_name='vuln_subscan_ids', blank=True)

	def __str__(self):
		cve_str = ', '.join(f'`{cve.name}`' for cve in self.cve_ids.all())
		severity = NUCLEI_REVERSE_SEVERITY_MAP[self.severity]
		return f'{self.http_url} | `{severity.upper()}` | `{self.name}` | `{cve_str}`'

	def get_severity(self):
		return self.severity

	def get_cve_str(self):
		return ', '.join(f'`{cve.name}`' for cve in self.cve_ids.all())

	def get_cwe_str(self):
		return ', '.join(f'`{cwe.name}`' for cwe in self.cwe_ids.all())

	def get_tags_str(self):
		return ', '.join(f'`{tag.name}`' for tag in self.tags.all())

	def get_refs_str(self):
		return '•' + '\n• '.join(f'`{ref.url}`' for ref in self.references.all())

	def get_path(self):
		return urlparse(self.http_url).path

	@classmethod
	def get_project_data(cls, project):
		"""Get vulnerability data for a specific project"""
		queryset = cls.objects.filter(scan_history__domain__project=project)
		return {
			'feed': queryset.order_by('-discovered_date')[:50],
			'most_common_cve': CveId.get_most_common(queryset),
			'most_common_cwe': CweId.get_most_common(queryset),
			'most_common_tags': VulnerabilityTags.get_most_common(queryset)
		}

	@staticmethod
	def get_counts_by_date(queryset, date_field, since_date):
		"""Get daily vulnerability counts for a queryset"""
		counts = queryset.filter(
			**{f"{date_field}__gte": since_date}
		).annotate(
			date=TruncDay(date_field)
		).values("date").annotate(
			count=Count('id')
		).order_by("date")
		
		return {item['date']: item['count'] for item in counts}

	@classmethod
	def get_project_timeline(cls, project, date_range):
		"""Get vulnerability timeline data for a specific project"""
		raw_data = cls.get_counts_by_date(
			cls.objects.filter(scan_history__domain__project=project),
			'discovered_date',
			date_range[0]
		)
		
		results = []
		for date in date_range:
			aware_date = timezone.make_aware(datetime.combine(date, datetime.min.time()))
			results.append(raw_data.get(aware_date, 0))
		
		return results[::-1]


class ScanActivity(models.Model):
	id = models.AutoField(primary_key=True)
	scan_of = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, blank=True, null=True)
	title = models.CharField(max_length=1000)
	name = models.CharField(max_length=1000)
	time = models.DateTimeField()
	status = models.IntegerField()
	error_message = models.CharField(max_length=300, blank=True, null=True)
	traceback = models.TextField(blank=True, null=True)
	celery_id = models.CharField(max_length=100, blank=True, null=True)

	def __str__(self):
		return str(self.title)


class Command(models.Model):
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, blank=True, null=True)
	activity = models.ForeignKey(ScanActivity, on_delete=models.CASCADE, blank=True, null=True)
	command = models.TextField(blank=True, null=True)
	return_code = models.IntegerField(blank=True, null=True)
	output = models.TextField(blank=True, null=True)
	time = models.DateTimeField()

	def __str__(self):
		return str(self.command)


class Waf(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=500)
	manufacturer = models.CharField(max_length=500, blank=True, null=True)

	def __str__(self):
		return str(self.name)


class Technology(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=500, blank=True, null=True)

	def __str__(self):
		return str(self.name)

	@classmethod
	def get_project_data(cls, project):
		"""Get technology data for a specific project"""
		subdomains = Subdomain.objects.filter(
			scan_history__domain__project=project
		)
		return {
			'most_used': cls.get_most_used(subdomains)
		}

	@classmethod
	def get_most_used(cls, subdomains, limit=10):
		"""Get most used technologies"""
		return cls.objects.filter(
			technologies__in=subdomains
		).values('name').annotate(
			count=Count('name')
		).order_by('-count')[:limit]


class CountryISO(models.Model):
	id = models.AutoField(primary_key=True)
	iso = models.CharField(max_length=10, blank=True)
	name = models.CharField(max_length=100, blank=True)

	def __str__(self):
		return str(self.name)

	@classmethod
	def get_project_data(cls, project):
		"""Get country data for a specific project"""
		ip_addresses = IpAddress.objects.filter(
			ip_addresses__in=Subdomain.objects.filter(
				scan_history__domain__project=project
			)
		)
		return {
			'asset_countries': cls.get_asset_countries(ip_addresses)
		}

	@classmethod
	def get_asset_countries(cls, ip_addresses):
		"""Get countries for assets"""
		return cls.objects.filter(
			ipaddress__in=ip_addresses
		).annotate(
			count=Count('iso')
		).order_by('-count')


class IpAddress(models.Model):
	id = models.AutoField(primary_key=True)
	address = models.CharField(max_length=100, blank=True, null=True)
	is_cdn = models.BooleanField(default=False)
	geo_iso = models.ForeignKey(
		CountryISO, on_delete=models.CASCADE, null=True, blank=True)
	version = models.IntegerField(blank=True, null=True)
	is_private = models.BooleanField(default=False)
	reverse_pointer = models.CharField(max_length=100, blank=True, null=True)
	# this is used for querying which ip was discovered during subcan
	ip_subscan_ids = models.ManyToManyField('SubScan', related_name='ip_subscan_ids')

	def __str__(self):
		return str(self.address)

	@classmethod
	def get_project_data(cls, project):
		"""Get IP address data for a specific project"""
		base_query = cls.objects.filter(
			ip_addresses__in=Subdomain.objects.filter(
				scan_history__domain__project=project
			)
		)
		return {
			'total_count': base_query.count(),
			'most_used': cls.get_most_used(base_query)
		}

	@classmethod
	def get_most_used(cls, queryset, subdomains=None, limit=7):
		"""Get most common IP addresses with count annotation"""
		return queryset.annotate(
			count=Count('ip_addresses')
		).order_by('-count').exclude(
			ip_addresses__isnull=True
		)[:limit]


class Port(models.Model):
	id = models.AutoField(primary_key=True)
	number = models.IntegerField(default=0)
	is_uncommon = models.BooleanField(default=False)
	service_name = models.CharField(max_length=100, blank=True, null=True)
	description = models.CharField(max_length=1000, blank=True, null=True)
	ip_address = models.ForeignKey(
		'IpAddress', 
		on_delete=models.CASCADE, 
		related_name='ports',
		null=True,
		blank=True
	)

	class Meta:
		unique_together = ('ip_address', 'number')

	def __str__(self):
		return str(self.number)

	@classmethod
	def get_project_data(cls, project):
		"""Get port data for a specific project"""
		ip_addresses = IpAddress.objects.filter(
			ip_addresses__in=Subdomain.objects.filter(
				scan_history__domain__project=project
			)
		)
		return {
			'most_used': cls.get_most_used(ip_addresses)
		}

	@classmethod
	def get_most_used(cls, ip_addresses, limit=10):
		"""Get most used ports"""
		return cls.objects.filter(
			ip_address__in=ip_addresses
		).values(
			'number', 'service_name'
		).annotate(
			count=Count('number')
		).order_by('-count')[:limit]


class DirectoryFile(models.Model):
	id = models.AutoField(primary_key=True)
	length = models.IntegerField(default=0)
	lines = models.IntegerField(default=0)
	http_status = models.IntegerField(default=0)
	words = models.IntegerField(default=0)
	name = models.CharField(max_length=500, blank=True, null=True)
	url = models.CharField(max_length=5000, blank=True, null=True)
	content_type = models.CharField(max_length=100, blank=True, null=True)

	def __str__(self):
		return str(self.name)


class DirectoryScan(models.Model):
	id = models.AutoField(primary_key=True)
	command_line = models.CharField(max_length=5000, blank=True, null=True)
	directory_files = models.ManyToManyField('DirectoryFile', related_name='directory_files', blank=True)
	scanned_date = models.DateTimeField(null=True)
	# this is used for querying which ip was discovered during subcan
	dir_subscan_ids = models.ManyToManyField('SubScan', related_name='dir_subscan_ids', blank=True)


class MetaFinderDocument(models.Model):
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
	target_domain = models.ForeignKey(
		Domain, on_delete=models.CASCADE, null=True, blank=True)
	subdomain = models.ForeignKey(
		Subdomain,
		on_delete=models.CASCADE,
		null=True,
		blank=True)
	doc_name = models.CharField(max_length=1000, null=True, blank=True)
	url = models.CharField(max_length=10000, null=True, blank=True)
	title = models.CharField(max_length=1000, null=True, blank=True)
	author = models.CharField(max_length=1000, null=True, blank=True)
	producer = models.CharField(max_length=1000, null=True, blank=True)
	creator = models.CharField(max_length=1000, null=True, blank=True)
	os = models.CharField(max_length=1000, null=True, blank=True)
	http_status = models.IntegerField(default=0, null=True, blank=True)
	creation_date = models.CharField(max_length=1000, blank=True, null=True)
	modified_date = models.CharField(max_length=1000, blank=True, null=True)


class Email(models.Model):
	id = models.AutoField(primary_key=True)
	address = models.CharField(max_length=200, blank=True, null=True)
	password = models.CharField(max_length=200, blank=True, null=True)

class Employee(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=1000, null=True, blank=True)
	designation = models.CharField(max_length=1000, null=True, blank=True)


class Dork(models.Model):
	id = models.AutoField(primary_key=True)
	type = models.CharField(max_length=500, null=True, blank=True)
	url = models.CharField(max_length=10000, null=True, blank=True)


class S3Bucket(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=500, null=True, blank=True)
	region = models.CharField(max_length=500, null=True, blank=True)
	provider = models.CharField(max_length=100, null=True, blank=True)
	owner_id = models.CharField(max_length=250, null=True, blank=True)
	owner_display_name = models.CharField(max_length=250, null=True, blank=True)
	perm_auth_users_read = models.IntegerField(default=0)
	perm_auth_users_write = models.IntegerField(default=0)
	perm_auth_users_read_acl = models.IntegerField(default=0)
	perm_auth_users_write_acl = models.IntegerField(default=0)
	perm_auth_users_full_control = models.IntegerField(default=0)
	perm_all_users_read = models.IntegerField(default=0)
	perm_all_users_write = models.IntegerField(default=0)
	perm_all_users_read_acl = models.IntegerField(default=0)
	perm_all_users_write_acl = models.IntegerField(default=0)
	perm_all_users_full_control = models.IntegerField(default=0)
	num_objects = models.IntegerField(default=0)
	size = models.IntegerField(default=0)
