from django.apps import apps
from django.db import models
from django.db.models import Count
from dashboard.models import Project
from django.utils import timezone
from datetime import datetime
from django.db.models.functions import TruncDay


class HistoricalIP(models.Model):
	id = models.AutoField(primary_key=True)
	ip = models.CharField(max_length=150)
	location = models.CharField(max_length=500)
	owner = models.CharField(max_length=500)
	last_seen = models.CharField(max_length=500)

	def __str__(self):
		return self.name


class RelatedDomain(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=250)

	def __str__(self):
		return self.name


class Registrar(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=500, null=True, blank=True)
	phone = models.CharField(max_length=150, null=True, blank=True)
	email = models.CharField(max_length=350, null=True, blank=True)
	url = models.CharField(max_length=1000, null=True, blank=True)

	def __str__(self):
		return self.name


class DomainRegistration(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=500, null=True, blank=True)
	organization = models.CharField(max_length=500, null=True, blank=True)
	address = models.CharField(max_length=500, null=True, blank=True)
	city = models.CharField(max_length=100, null=True, blank=True)
	state = models.CharField(max_length=100, null=True, blank=True)
	zip_code = models.CharField(max_length=100, null=True, blank=True)
	country = models.CharField(max_length=100, null=True, blank=True)
	email = models.CharField(max_length=500, null=True, blank=True)
	phone = models.CharField(max_length=150, null=True, blank=True)
	fax = models.CharField(max_length=150, null=True, blank=True)
	id_str = models.CharField(max_length=500, null=True, blank=True)

	def __str__(self):
		return self.name


class WhoisStatus(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=500)

	def __str__(self):
		return self.name


class NameServer(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=500)

	def __str__(self):
		return self.name


class DNSRecord(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=500)
	type = models.CharField(max_length=50)

	def __str__(self):
		return self.name


class DomainInfo(models.Model):
	id = models.AutoField(primary_key=True)
	dnssec = models.BooleanField(default=False)
	# dates
	created = models.DateTimeField(null=True, blank=True)
	updated = models.DateTimeField(null=True, blank=True)
	expires = models.DateTimeField(null=True, blank=True)
	# geolocation
	geolocation_iso = models.CharField(max_length=10, null=True, blank=True)
	# registrar
	registrar = models.ForeignKey(Registrar, blank=True, on_delete=models.CASCADE, null=True)
	# registrant
	registrant = models.ForeignKey(
		DomainRegistration,
		blank=True,
		null=True,
		on_delete=models.CASCADE,
		related_name='registrant'
	)
	# admin
	admin = models.ForeignKey(
		DomainRegistration,
		blank=True,
		null=True,
		on_delete=models.CASCADE,
		related_name='admin'
	)
	# tech
	tech = models.ForeignKey(
		DomainRegistration,
		blank=True,
		null=True,
		on_delete=models.CASCADE,
		related_name='tech'
	)
	# status
	status = models.ManyToManyField(WhoisStatus, blank=True)
	# ns
	name_servers = models.ManyToManyField(NameServer, blank=True)
	dns_records = models.ManyToManyField(DNSRecord, blank=True)
	# whois server
	whois_server = models.CharField(max_length=150, null=True, blank=True)
	# associated/similer domains
	related_domains = models.ManyToManyField(RelatedDomain, blank=True, related_name='associated_domains')
	related_tlds = models.ManyToManyField(RelatedDomain, blank=True, related_name='related_tlds')
	similar_domains = models.ManyToManyField(RelatedDomain, blank=True, related_name='similar_domains')
	# historical ips
	historical_ips = models.ManyToManyField(HistoricalIP, blank=True, related_name='similar_domains')

	def __str__(self):
		return str(self.id)


class Organization(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=300, unique=True)
	description = models.TextField(blank=True, null=True)
	insert_date = models.DateTimeField()
	domains = models.ManyToManyField('Domain', related_name='domains')
	project = models.ForeignKey(Project, on_delete=models.CASCADE, null=True, blank=False)

	def __str__(self):
		return self.name

	def get_domains(self):
		return Domain.objects.filter(domains__in=Organization.objects.filter(id=self.id))


class Domain(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=300, unique=True)
	h1_team_handle = models.CharField(max_length=100, blank=True, null=True)
	ip_address_cidr = models.CharField(max_length=100, blank=True, null=True)
	description = models.TextField(blank=True, null=True)
	insert_date = models.DateTimeField(null=True)
	start_scan_date = models.DateTimeField(null=True)
	request_headers = models.JSONField(null=True, blank=True)
	domain_info = models.ForeignKey(DomainInfo, on_delete=models.CASCADE, null=True, blank=True)
	project = models.ForeignKey(Project, on_delete=models.CASCADE, null=True, blank=False)

	def get_organization(self):
		return Organization.objects.filter(domains__id=self.id)

	def get_recent_scan_id(self):
		ScanHistory = apps.get_model('startScan.ScanHistory')
		obj = ScanHistory.objects.filter(domain__id=self.id).order_by('-id')
		if obj:
			return obj[0].id

	def __str__(self):
		return str(self.name)

	@classmethod
	def get_all_counts(cls, queryset):
		return queryset.aggregate(
			total=Count('id'),
		)

	@classmethod
	def get_project_counts(cls, project):
		"""Get all counts for a specific project"""
		return cls.get_all_counts(cls.objects.filter(project=project))

	@classmethod
	def get_project_data(cls, project):
		"""Get domain data for a specific project"""
		queryset = cls.objects.filter(project=project)
		return {
			'total_count': queryset.count(),
			'recent_domains': queryset.order_by('-insert_date')[:10]
		}

	@staticmethod
	def get_counts_by_date(queryset, date_field, since_date):
		"""Get daily domain counts for a queryset"""
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
		"""Get domain timeline data for a specific project"""
		raw_data = cls.get_counts_by_date(
			cls.objects.filter(project=project),
			'insert_date',
			date_range[0]
		)
		
		results = []
		for date in date_range:
			aware_date = timezone.make_aware(datetime.combine(date, datetime.min.time()))
			results.append(raw_data.get(aware_date, 0))
		
		return results[::-1]  # Reverse to match chart order
