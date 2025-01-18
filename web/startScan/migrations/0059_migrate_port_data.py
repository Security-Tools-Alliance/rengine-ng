from django.db import migrations

def migrate_port_data(apps, schema_editor):
    IpAddress = apps.get_model('startScan', 'IpAddress')
    PortInfo = apps.get_model('startScan', 'PortInfo')
    
    for ip in IpAddress.objects.all():
        for port in ip.ports.all():
            PortInfo.objects.get_or_create(
                ip_address=ip,
                port=port,
                defaults={
                    'service_name': getattr(port, 'service_name', 'unknown'),
                    'description': getattr(port, 'description', '')
                }
            )

class Migration(migrations.Migration):

    dependencies = [
        ('startScan', '0058_port_info_model'),
    ]

    operations = [
        migrations.RunPython(migrate_port_data),
    ] 